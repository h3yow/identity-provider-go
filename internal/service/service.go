// Package service 组装密钥环、令牌签发/验证、会话存储与鉴权，
// 提供本地可运行的认证与令牌服务（进程内状态）。
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"time"

	idp "github.com/h3yow/identity-provider-go/internal"
	"github.com/h3yow/identity-provider-go/internal/authz"
	"github.com/h3yow/identity-provider-go/internal/keys"
	"github.com/h3yow/identity-provider-go/internal/sessions"
	"github.com/h3yow/identity-provider-go/internal/tokens"
)

// Config 是服务参数。
type Config struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// DefaultConfig 返回本地演示用默认参数。
func DefaultConfig() Config {
	return Config{AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 7 * 24 * time.Hour}
}

// Service 是进程内身份提供服务。
type Service struct {
	cfg      Config
	ring     *keys.Ring
	store    *sessions.Store
	issuer   *tokens.Issuer
	verifier *tokens.Verifier
	authz    *authz.Authorizer

	keySeq  atomic.Uint64
	sessSeq atomic.Uint64
	now     func() time.Time
}

// New 创建服务：生成初始签名密钥版本并写入空密钥环。
func New(cfg Config) *Service {
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = DefaultConfig().AccessTokenTTL
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = DefaultConfig().RefreshTokenTTL
	}
	now := time.Now
	ring := keys.NewRing()
	s := &Service{
		cfg:   cfg,
		ring:  ring,
		store: sessions.NewStore(),
		now:   now,
	}
	s.issuer = tokens.NewIssuer(ring, cfg.AccessTokenTTL, func() time.Time { return s.now() })
	s.verifier = tokens.NewVerifier(ring, func() time.Time { return s.now() })
	s.authz = authz.NewAuthorizer(s.verifier)
	if _, err := s.RotateKey(); err != nil {
		panic(err)
	}
	return s
}

// Ring 暴露密钥环用于运维观测/强制退役。
func (s *Service) Ring() *keys.Ring { return s.ring }

// Sessions 暴露会话存储用于测试观测。
func (s *Service) Sessions() *sessions.Store { return s.store }

// Authorizer 返回组合鉴权器。
func (s *Service) Authorizer() *authz.Authorizer { return s.authz }

// IssueResult 是登录/刷新成功结果。
type IssueResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    time.Duration
	KeyVersion   keys.Version
	SessionID    string
}

func randomID(prefix string, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("service: random id: " + err.Error())
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
}

// Login 为主体创建会话，签发访问令牌与首个刷新凭据。
func (s *Service) Login(subject string, grants sessions.Grants) (IssueResult, error) {
	if subject == "" {
		return IssueResult{}, errors.New("service: empty subject")
	}
	sessionID := randomID("sess", 16)
	s.sessSeq.Add(1)
	sess, cred := s.store.Create(sessionID, subject, grants, s.cfg.RefreshTokenTTL, s.now())
	return s.issuePair(sess, cred)
}

// issuePair 用当前 active 密钥签发访问令牌，组装对外结果。
// 访问令牌中的角色/作用域直接取自会话授权快照 —— 刷新不会扩大权限。
func (s *Service) issuePair(sess sessions.Session, cred sessions.Credential) (IssueResult, error) {
	access, kid, err := s.issuer.Issue(tokens.Claims{
		Subject:     sess.Subject,
		Roles:       sess.Grants.Roles,
		Scopes:      sess.Grants.Scopes,
		SessionID:   sess.ID,
		CredVersion: cred.Version,
	})
	if err != nil {
		return IssueResult{}, err
	}
	return IssueResult{
		AccessToken:  access,
		RefreshToken: cred.ID,
		TokenType:    "Bearer",
		ExpiresIn:    s.cfg.AccessTokenTTL,
		KeyVersion:   kid,
		SessionID:    sess.ID,
	}, nil
}

// Refresh 用刷新凭据换新的访问令牌与刷新凭据（一次性轮换）。
// 错误均为 *idp.Error，原因码可区分：invalid_grant / session_revoked。
func (s *Service) Refresh(ctx context.Context, refreshToken string) (IssueResult, error) {
	if refreshToken == "" {
		return IssueResult{}, idp.NewError(idp.ReasonInvalidGrant, "empty refresh token")
	}
	cred, ok := s.store.CredentialByID(refreshToken)
	if !ok {
		return IssueResult{}, idp.NewError(idp.ReasonInvalidGrant, "refresh token not recognized")
	}
	res, err := s.store.Rotate(cred, s.cfg.RefreshTokenTTL, s.now())
	if err != nil {
		return IssueResult{}, mapSessionError(err)
	}
	return s.issuePair(res.Session, res.New)
}

func mapSessionError(err error) error {
	switch {
	case errors.Is(err, sessions.ErrCredentialReplay):
		return idp.NewError(idp.ReasonSessionRevoked,
			"refresh credential replay detected; session chain terminated")
	case errors.Is(err, sessions.ErrSessionRevoked):
		return idp.NewError(idp.ReasonSessionRevoked, "session has been revoked")
	case errors.Is(err, sessions.ErrCredentialExpired):
		return idp.NewError(idp.ReasonInvalidGrant, "refresh credential expired")
	default:
		return idp.NewError(idp.ReasonInvalidGrant, err.Error())
	}
}

// Introspect 返回令牌验证结论；成功给出 Envelope，失败给出带原因码的错误。
func (s *Service) Introspect(raw string) (*tokens.Envelope, error) {
	return s.verifier.Verify(raw)
}

// RotateKey 轮换签名密钥：生成新版本成为 active，旧 active 进入验证宽限期。
func (s *Service) RotateKey() (keys.Version, error) {
	seq := s.keySeq.Add(1)
	v := keys.Version("k" + itoa(seq) + "-" + randomID("", 12))
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", errors.New("service: generate key secret: " + err.Error())
	}
	if err := s.ring.Rotate(keys.Key{Version: v, Secret: secret}); err != nil {
		return "", err
	}
	return v, nil
}

// RetireKey 在过渡期结束后立即退役指定版本；此后其令牌判定为 key_not_active。
func (s *Service) RetireKey(v keys.Version) error {
	if err := s.ring.Retire(v); err != nil {
		return err
	}
	return nil
}

func itoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	return string(buf[i:])
}
