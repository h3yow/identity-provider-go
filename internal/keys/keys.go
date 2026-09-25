// Package keys 管理签名密钥的多版本共存与轮换（进程内状态）。
//
// 生命周期模型（每个版本不可变，轮换=引入新版本而非修改旧密钥）：
//
//	active    当前唯一用于签发的版本；旧 active 仍可验证。
//	  |  rotate(new)：新版本变 active，旧 active 变 verifying
//	  v
//	verifying 过渡期：不再签发，但该版本签发的旧令牌仍可验证。
//	  |  retire(v)：过渡期结束，显式退役
//	  v
//	retired   不再接受其签发的任何令牌（判定为 key_not_active）。
//
// 从未登记过的版本在验证时判定为 unknown_key，与“存在但已退役”严格区分。
package keys

import (
	"errors"
	"sync"
)

// Version 标识一个不可变的密钥版本。
type Version string

// Secret 是 HMAC 对称密钥原始字节。
type Secret []byte

// State 描述密钥版本所处的生命周期阶段。
type State int

const (
	StateNone      State = iota // 不存在（从未登记或已被清除）
	StateActive                 // 处于签发有效期，可签发可验证
	StateVerifying              // 已停止签发，仍可验证旧令牌（过渡期）
	StateRetired                // 已退役，不再接受
)

func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateVerifying:
		return "verifying"
	case StateRetired:
		return "retired"
	default:
		return "none"
	}
}

// Key 是某个版本的不可变密钥材料。
type Key struct {
	Version Version
	Secret  Secret
}

type entry struct {
	key   Key
	state State
}

// Ring 是进程内、并发安全的版本化密钥环。
type Ring struct {
	mu      sync.RWMutex
	order   []Version // 登记顺序，用于稳定观测
	entries map[Version]*entry
	active  Version
}

// NewRing 创建空密钥环。
func NewRing() *Ring {
	return &Ring{entries: make(map[Version]*entry)}
}

var (
	// ErrEmptyVersion 表示密钥版本为空。
	ErrEmptyVersion = errors.New("keys: empty key version")
	// ErrEmptySecret 表示密钥材料为空。
	ErrEmptySecret = errors.New("keys: empty key secret")
	// ErrDuplicateVersion 表示版本已存在（密钥不可变，禁止覆盖）。
	ErrDuplicateVersion = errors.New("keys: key version already exists")
	// ErrUnknownVersion 表示版本从未登记。
	ErrUnknownVersion = errors.New("keys: unknown key version")
	// ErrActiveCannotRetire 表示不能直接退役 active 密钥，须先轮换。
	ErrActiveCannotRetire = errors.New("keys: active key cannot be retired; rotate first")
)

// promote 登记新版本为 active，并把原 active（若有）降为 verifying。
func (r *Ring) promote(k Key) error {
	if k.Version == "" {
		return ErrEmptyVersion
	}
	if len(k.Secret) == 0 {
		return ErrEmptySecret
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[k.Version]; exists {
		return ErrDuplicateVersion
	}
	if r.active != "" {
		// 旧 active 进入验证宽限期；理论上它只会是 active。
		r.entries[r.active].state = StateVerifying
	}
	r.entries[k.Version] = &entry{key: k, state: StateActive}
	r.order = append(r.order, k.Version)
	r.active = k.Version
	return nil
}

// Add 登记一个新版本并立即置为 active（用于首次引导或追加）。
// 若此前存在 active 版本，旧版本转入 verifying 过渡期。
func (r *Ring) Add(k Key) error { return r.promote(k) }

// Rotate 执行密钥轮换：新版本成为唯一 active，旧 active 进入 verifying。
// 与 Add 使用相同的不可变版本推进规则，语义上专指“轮换”动作。
func (r *Ring) Rotate(k Key) error { return r.promote(k) }

// SigningKey 返回当前 active 密钥；无 active 时返回 false。
func (r *Ring) SigningKey() (Key, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == "" {
		return Key{}, false
	}
	return r.entries[r.active].key, true
}

// VerifyKey 按版本查找可用于验证的密钥。
//
//	版本未知：ok=false, state=StateNone    —— 上层判定 unknown_key
//	已退役：  ok=false, state=StateRetired —— 上层判定 key_not_active
//	可用：    ok=true,  state=Active/Verifying
func (r *Ring) VerifyKey(v Version) (Key, State, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[v]
	if !ok {
		return Key{}, StateNone, false
	}
	if e.state == StateActive || e.state == StateVerifying {
		return e.key, e.state, true
	}
	return e.key, e.state, false
}

// Retire 把处于 verifying 过渡期的版本立即退役；对已退役版本是幂等空操作。
func (r *Ring) Retire(v Version) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[v]
	if !ok {
		return ErrUnknownVersion
	}
	switch e.state {
	case StateRetired:
		return nil
	case StateVerifying:
		e.state = StateRetired
		return nil
	default:
		return ErrActiveCannotRetire
	}
}

// StateOf 返回版本当前状态（不存在为 StateNone）。
func (r *Ring) StateOf(v Version) State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[v]; ok {
		return e.state
	}
	return StateNone
}

// Versions 返回登记过的全部版本（按登记顺序），仅用于观测/测试。
func (r *Ring) Versions() []Version {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Version, len(r.order))
	copy(out, r.order)
	return out
}
