// Package tokens 实现紧凑的签名令牌（HMAC-SHA256），携带显式密钥版本。
//
// 线路格式（全部 base64.RawURLEncoding，以 '.' 分隔）：
//
//	v1.<kid>.<payloadJSON>.<signature>
//
// 被签名内容为 "<kid>.<payloadJSON>"，签名密钥是 kid 指向版本的 Secret。
//
// 验证失败原因的判定优先级（保证结论确定、可解释）：
//  1. 格式无法解析        -> malformed_token
//  2. kid 版本从未登记    -> unknown_key
//  3. kid 存在但已退役    -> key_not_active
//  4. 签名不匹配          -> bad_signature
//  5. now > exp           -> token_expired
package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	idp "github.com/h3yow/identity-provider-go/internal"
	"github.com/h3yow/identity-provider-go/internal/keys"
)

const (
	formatPrefix = "v1"
	segments     = 4 // v1 . kid . payload . sig
)

var b64 = base64.RawURLEncoding

// Claims 是令牌中的声明集合。
type Claims struct {
	Subject     string   // 用户/主体标识
	Roles       []string // 角色
	Scopes      []string // 作用域
	SessionID   string   // 所属会话
	CredVersion int64    // 签发时对应的刷新凭据版本
}

// Envelope 是解析并验证后的令牌内容。
type Envelope struct {
	KeyVersion keys.Version
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Claims     Claims
}

// payload 是线路上的 JSON 表示。
type payload struct {
	IAT int64    `json:"iat"`
	EXP int64    `json:"exp"`
	SUB string   `json:"sub"`
	ROL []string `json:"rol,omitempty"`
	SCP []string `json:"scp,omitempty"`
	SID string   `json:"sid,omitempty"`
	CV  int64    `json:"cv,omitempty"`
}

// Clock 抽象当前时间，便于确定性测试。
type Clock func() time.Time

// Issuer 负责用密钥环当前 active 版本签发令牌。
type Issuer struct {
	ring  *keys.Ring
	ttl   time.Duration
	clock Clock
}

// NewIssuer 创建签发器；clock 为 nil 时使用 time.Now。
func NewIssuer(ring *keys.Ring, ttl time.Duration, clock Clock) *Issuer {
	if clock == nil {
		clock = time.Now
	}
	return &Issuer{ring: ring, ttl: ttl, clock: clock}
}

// Issue 用当前 active 密钥签发令牌，返回原始串与所用密钥版本。
func (i *Issuer) Issue(c Claims) (string, keys.Version, error) {
	k, ok := i.ring.SigningKey()
	if !ok {
		return "", "", errors.New("tokens: no active signing key")
	}
	now := i.clock()
	p := payload{
		IAT: now.Unix(),
		EXP: now.Add(i.ttl).Unix(),
		SUB: c.Subject,
		ROL: c.Roles,
		SCP: c.Scopes,
		SID: c.SessionID,
		CV:  c.CredVersion,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", "", fmt.Errorf("tokens: encode claims: %w", err)
	}
	return encode(k, raw), k.Version, nil
}

func encode(k keys.Key, payloadJSON []byte) string {
	kid := b64.EncodeToString([]byte(k.Version))
	body := b64.EncodeToString(payloadJSON)
	signingInput := kid + "." + body
	mac := hmac.New(sha256.New, k.Secret)
	mac.Write([]byte(signingInput))
	sig := b64.EncodeToString(mac.Sum(nil))
	return formatPrefix + "." + signingInput + "." + sig
}

// Verifier 验证令牌签名与有效期。
type Verifier struct {
	ring  *keys.Ring
	clock Clock
}

// NewVerifier 创建验证器；clock 为 nil 时使用 time.Now。
func NewVerifier(ring *keys.Ring, clock Clock) *Verifier {
	if clock == nil {
		clock = time.Now
	}
	return &Verifier{ring: ring, clock: clock}
}

// Verify 按包注释中的优先级校验令牌，并返回带稳定原因码的错误。
func (v *Verifier) Verify(raw string) (*Envelope, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != segments || parts[0] != formatPrefix {
		return nil, idp.NewError(idp.ReasonMalformedToken, "token must be 'v1.kid.payload.signature'")
	}
	kidB, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, idp.NewError(idp.ReasonMalformedToken, "kid is not base64url: "+err.Error())
	}
	kid := keys.Version(kidB)
	bodyJSON, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, idp.NewError(idp.ReasonMalformedToken, "payload is not base64url: "+err.Error())
	}
	sig, err := b64.DecodeString(parts[3])
	if err != nil {
		return nil, idp.NewError(idp.ReasonMalformedToken, "signature is not base64url: "+err.Error())
	}

	key, state, ok := v.ring.VerifyKey(kid)
	if !ok {
		switch state {
		case keys.StateRetired:
			return nil, idp.NewError(idp.ReasonKeyNotActive,
				fmt.Sprintf("key version %q is retired (verifying window ended)", kid))
		default:
			return nil, idp.NewError(idp.ReasonUnknownKey,
				fmt.Sprintf("key version %q is not registered", kid))
		}
	}

	signingInput := parts[1] + "." + parts[2]
	mac := hmac.New(sha256.New, key.Secret)
	mac.Write([]byte(signingInput))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, idp.NewError(idp.ReasonBadSignature,
			fmt.Sprintf("signature mismatch for key version %q (state=%s)", kid, state))
	}

	var p payload
	if err := json.Unmarshal(bodyJSON, &p); err != nil {
		return nil, idp.NewError(idp.ReasonMalformedToken, "payload is not valid JSON: "+err.Error())
	}

	exp := time.Unix(p.EXP, 0)
	now := v.clock()
	if now.After(exp) {
		return nil, idp.NewError(idp.ReasonTokenExpired,
			fmt.Sprintf("token expired at %s (now %s)", exp.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)))
	}

	return &Envelope{
		KeyVersion: kid,
		IssuedAt:   time.Unix(p.IAT, 0),
		ExpiresAt:  exp,
		Claims: Claims{
			Subject:     p.SUB,
			Roles:       p.ROL,
			Scopes:      p.SCP,
			SessionID:   p.SID,
			CredVersion: p.CV,
		},
	}, nil
}
