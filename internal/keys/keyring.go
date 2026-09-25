// Package keys manages signing-key versions and rotation.
//
// Every key version is immutable once added and goes through three states:
//
//   - Active:  now < ExpiresAt. The key may sign new tokens and verify tokens.
//   - Grace:   ExpiresAt <= now < RetireAt. The key can no longer sign, but
//     tokens it signed before expiry are still accepted ("transition window").
//   - Retired: now >= RetireAt. The key is gone; tokens signed by it are
//     rejected with a distinct key-retired cause.
//
// Rotation adds a new version and marks it active; old versions stay in the
// ring to verify previously issued tokens until their RetireAt.
package keys

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound  = errors.New("keys: version not found")
	ErrDuplicate = errors.New("keys: version already exists")
	ErrNotActive = errors.New("keys: no signable active key")
)

// Version describes one immutable signing-key version.
type Version struct {
	ID        string
	Secret    []byte
	CreatedAt time.Time
	// ExpiresAt is the signing deadline. Tokens signed at or after it are invalid.
	ExpiresAt time.Time
	// RetireAt is the verification deadline. After it the version is fully retired.
	RetireAt time.Time
}

// State is the lifecycle state of a key version.
type State int

const (
	StateUnknown State = iota
	StateActive
	StateGrace
	StateRetired
)

func (st State) String() string {
	switch st {
	case StateActive:
		return "active"
	case StateGrace:
		return "grace"
	case StateRetired:
		return "retired"
	default:
		return "unknown"
	}
}

// KeyRing holds coexisting signing-key versions in process memory.
type KeyRing struct {
	mu       sync.RWMutex
	versions map[string]*Version
	activeID string
}

func NewKeyRing() *KeyRing {
	return &KeyRing{versions: make(map[string]*Version)}
}

// Add registers an immutable version. Its time window must be sane.
func (r *KeyRing) Add(v *Version) error {
	if v == nil || v.ID == "" {
		return fmt.Errorf("keys: invalid version")
	}
	if !v.CreatedAt.Before(v.ExpiresAt) || v.RetireAt.Before(v.ExpiresAt) {
		return fmt.Errorf("keys: version %s requires CreatedAt < ExpiresAt <= RetireAt", v.ID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.versions[v.ID]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, v.ID)
	}
	cp := *v
	r.versions[v.ID] = &cp
	return nil
}

// Get returns a copy of the version, independent of ring internals.
func (r *KeyRing) Get(id string) (*Version, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.versions[id]
	if !ok {
		return nil, false
	}
	cp := *v
	return &cp, true
}

func (r *KeyRing) ActiveID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.activeID
}

// SetActive marks an existing version as the one used for signing.
func (r *KeyRing) SetActive(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.versions[id]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	r.activeID = id
	return nil
}

// State reports the lifecycle state of a version at time now.
// An unknown id yields StateUnknown and ErrNotFound.
func (r *KeyRing) State(id string, now time.Time) (State, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.versions[id]
	if !ok {
		return StateUnknown, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	switch {
	case now.Before(v.ExpiresAt):
		return StateActive, nil
	case now.Before(v.RetireAt):
		return StateGrace, nil
	default:
		return StateRetired, nil
	}
}

// Active returns the version currently used for signing. It must exist and be
// in the Active (signable) state; otherwise ErrNotActive is returned so the
// caller is forced to rotate instead of silently signing with a stale key.
func (r *KeyRing) Active(now time.Time) (*Version, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.versions[r.activeID]
	if !ok {
		return nil, fmt.Errorf("%w: active id %q missing", ErrNotActive, r.activeID)
	}
	if !now.Before(v.ExpiresAt) {
		return nil, fmt.Errorf("%w: version %s past signing expiry %s", ErrNotActive, v.ID, v.ExpiresAt.Format(time.RFC3339))
	}
	cp := *v
	return &cp, nil
}

// Rotate adds a fresh version and atomically makes it active. Previously
// active versions remain in the ring for verification until they retire.
func (r *KeyRing) Rotate(id string, secret []byte, now time.Time, signTTL, grace time.Duration) (*Version, error) {
	if signTTL <= 0 {
		return nil, fmt.Errorf("keys: signTTL must be positive")
	}
	if grace < 0 {
		return nil, fmt.Errorf("keys: grace must be non-negative")
	}
	v := &Version{
		ID:        id,
		Secret:    append([]byte(nil), secret...),
		CreatedAt: now,
		ExpiresAt: now.Add(signTTL),
		RetireAt:  now.Add(signTTL).Add(grace),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.versions[id]; ok {
		return nil, fmt.Errorf("%w: %s", ErrDuplicate, id)
	}
	r.versions[id] = v
	r.activeID = id
	cp := *v
	return &cp, nil
}

// IDs lists all known version ids in registration order (sorted for stability).
func (r *KeyRing) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.versions))
	for id := range r.versions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
