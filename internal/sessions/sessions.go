// Package sessions 管理会话与刷新凭据的一次性轮换、重放识别与并发安全。
//
// 凭据链模型（一条会话是一条只进不退的链）：
//
//	cred#1 (current) --Rotate(cred#1)--> cred#1 consumed, cred#2 (current)
//
// 规则（语义确定，且在并发下保持稳定）：
//   - 每个凭据只能成功使用一次；Rotate 成功即原子地推进 current。
//   - 同一凭据并发刷新：全部调用在同一把锁下串行判定，恰有一个成功，
//     其余看到“凭据已不是 current”，不会产生重复会话或状态分叉。
//   - 已使用（或任何非 current）的凭据再次出现即判定为重放：
//     立即吊销整条会话（Revoked=true），该会话后续所有刷新一律拒绝。
//   - 已吊销会话上的任何凭据（含当前凭据）一律拒绝。
//   - 会话保存最初授权 Grants 的排序后快照，刷新发放的权限永远以此为边界。
package sessions

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"
)

// Grants 是会话最初授权、且刷新后不得超出的权限边界。
type Grants struct {
	Roles  []string
	Scopes []string
}

func cloneSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// snapshot 返回排序去重副本，作为不可变授权边界。
func (g Grants) snapshot() Grants {
	return Grants{Roles: cloneSorted(g.Roles), Scopes: cloneSorted(g.Scopes)}
}

// Credential 是一个一次性刷新凭据（对外以不透明 ID 表示）。
type Credential struct {
	ID        string
	SessionID string
	Version   int64
	ExpiresAt time.Time
}

// Session 是一条凭据轮换链。
type Session struct {
	ID        string
	Subject   string
	Grants    Grants
	CurrentID string // 当前有效凭据 ID
	Version   int64  // 当前凭据序号（从 1 起）
	Revoked   bool
}

type credRecord struct {
	cred Credential
	used bool // 已成功用于轮换
}

// Result 是一次成功刷新的产物。
type Result struct {
	Session Session
	Old     Credential // 已作废的凭据
	New     Credential // 新生效的凭据
}

// Store 是进程内、并发安全的会话存储。
type Store struct {
	mu      sync.Mutex
	session map[string]*Session
	cred    map[string]*credRecord // ID -> 凭据记录
}

// NewStore 创建空会话存储。
func NewStore() *Store {
	return &Store{
		session: make(map[string]*Session),
		cred:    make(map[string]*credRecord),
	}
}

func newCredID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 进程内随机性不可用时没有安全的降级路径。
		panic("sessions: cannot read random bytes: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Create 新建会话并发放第一个（version=1）刷新凭据。
func (s *Store) Create(sessionID, subject string, g Grants, ttl time.Duration, now time.Time) (Session, Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Credential{
		ID:        newCredID(),
		SessionID: sessionID,
		Version:   1,
		ExpiresAt: now.Add(ttl),
	}
	sess := &Session{
		ID:        sessionID,
		Subject:   subject,
		Grants:    g.snapshot(),
		CurrentID: c.ID,
		Version:   1,
	}
	s.session[sessionID] = sess
	s.cred[c.ID] = &credRecord{cred: c}
	return *sess, c
}

// Rotate 以旧凭据换新凭据。返回的错误由上层映射为稳定原因码：
//
//	ErrUnknownCredential  凭据 ID 根本不存在
//	ErrSessionRevoked     会话已被（先前的重放）吊销
//	ErrCredentialReplay   旧凭据重放（本次调用会吊销会话）
//	ErrCredentialExpired  凭据已过期
func (s *Store) Rotate(old Credential, ttl time.Duration, now time.Time) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.cred[old.ID]
	if !ok {
		return nil, ErrUnknownCredential
	}
	sess := s.session[rec.cred.SessionID]

	// 常量时间比对 ID 之外的归属信息，避免可用信息差异；ID 本身已通过 map 命中。
	sameSession := subtle.ConstantTimeCompare([]byte(rec.cred.SessionID), []byte(old.SessionID)) == 1
	sameVersion := rec.cred.Version == old.Version
	if !sameSession || !sameVersion {
		// ID 存在但归属/版本对不上：视为伪造，按重放处理并吊销链路。
		sess.Revoked = true
		return nil, ErrCredentialReplay
	}

	if sess.Revoked {
		return nil, ErrSessionRevoked
	}

	// 非当前凭据：要么是已正常轮换掉的旧凭据（重放），要么是超前/跳跃版本。
	if rec.cred.ID != sess.CurrentID {
		// 重放旧凭据是明确攻击信号：终止整条会话链路。
		sess.Revoked = true
		if rec.used {
			return nil, ErrCredentialReplay
		}
		return nil, ErrCredentialReplay
	}

	if now.After(rec.cred.ExpiresAt) {
		// 过期不吊销会话：用户可重新登录；与重放（主动异常）区分。
		return nil, ErrCredentialExpired
	}

	// 唯一成功路径：原子推进链。
	rec.used = true
	newCred := Credential{
		ID:        newCredID(),
		SessionID: sess.ID,
		Version:   sess.Version + 1,
		ExpiresAt: now.Add(ttl),
	}
	sess.CurrentID = newCred.ID
	sess.Version = newCred.Version
	s.cred[newCred.ID] = &credRecord{cred: newCred}

	return &Result{Session: *sess, Old: rec.cred, New: newCred}, nil
}

// Get 按会话 ID 读取当前状态快照（指针内容被复制，调用方不可就地修改）。
func (s *Store) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.session[id]
	if !ok {
		return Session{}, false
	}
	return *sess, true
}

// Credential 查找使用的哨兵错误。
var (
	// ErrUnknownCredential 表示凭据 ID 从未发放。
	ErrUnknownCredential = errors.New("sessions: unknown refresh credential")
	// ErrCredentialReplay 表示旧/非当前凭据被再次提交（重放），会话已被吊销。
	ErrCredentialReplay = errors.New("sessions: refresh credential replay detected; session revoked")
	// ErrCredentialExpired 表示当前凭据已过期。
	ErrCredentialExpired = errors.New("sessions: refresh credential expired")
	// ErrSessionRevoked 表示会话链路已终止。
	ErrSessionRevoked = errors.New("sessions: session revoked")
)

// CredentialByID 仅供服务层反查登录会话用（返回副本）。
func (s *Store) CredentialByID(id string) (Credential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.cred[id]
	if !ok {
		return Credential{}, false
	}
	return rec.cred, true
}
