package auth

import (
	"sync"
	"time"

	"github.com/h3yow/identity-provider-go/internal/tokens"
)

// Logger is the minimal logging hook used to record key inputs and decisions.
type Logger interface {
	Printf(format string, args ...any)
}

// Options holds token lifetimes, the per-subject capacity gate and an
// optional logger.
type Options struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// MaxActiveChainsPerSubject caps how many un-terminated session chains a
	// single subject may hold at once. Zero means unlimited.
	MaxActiveChainsPerSubject int
	Logger                    Logger
}

func (o Options) withDefaults() Options {
	if o.AccessTokenTTL <= 0 {
		o.AccessTokenTTL = 15 * time.Minute
	}
	if o.RefreshTokenTTL <= 0 {
		o.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	return o
}

// Session is one node of a refresh-rotation chain.
//
// A login creates chain root. Every successful refresh consumes the parent
// refresh credential (Used=true), appends a new session with a fresh opaque
// credential, and inherits roles/scopes unchanged from the chain root.
type Session struct {
	ID           string
	ChainID      string
	Subject      string
	Roles        []string
	Scopes       []string
	RefreshToken string
	ParentID     string // session this one was rotated from ("" for chain root)
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Used         bool
	Revoked      bool
}

// IssueResult is returned by login and refresh.
type IssueResult struct {
	AccessToken  *tokens.Token
	RefreshToken string
	Session      *Session
}

// Service issues, verifies and rotates credentials in process memory.
type Service struct {
	mu        sync.Mutex
	signer    *tokens.Signer
	opts      Options
	byRefresh map[string]*Session // includes consumed credentials, for replay detection
	chains    map[string][]*Session
	inflight  map[string]struct{} // refresh credentials currently being rotated
	// terminated records why a chain ended ("replay", "logout",
	// "subject_terminated"); presence means the chain is dead.
	terminated map[string]string
	// activeChains indexes the live (un-terminated) chain IDs per subject; it
	// backs both the capacity gate and per-subject termination.
	activeChains map[string]map[string]struct{}
}

// NewService builds an in-process authentication service.
func NewService(signer *tokens.Signer, opts Options) *Service {
	return &Service{
		signer:       signer,
		opts:         opts.withDefaults(),
		byRefresh:    make(map[string]*Session),
		chains:       make(map[string][]*Session),
		inflight:     make(map[string]struct{}),
		terminated:   make(map[string]string),
		activeChains: make(map[string]map[string]struct{}),
	}
}

// short returns a non-secret prefix used to identify credentials in logs.
func short(raw string) string {
	if len(raw) > 12 {
		return raw[:12] + "..."
	}
	return "(empty)"
}

// refreshDeniedCode maps a chain-termination cause to the fixed refresh
// error code: replay detection keeps refresh_replayed, voluntary endings
// (logout, per-subject termination) yield refresh_revoked.
func refreshDeniedCode(cause string) ErrorCode {
	if cause == "replay" {
		return ErrRefreshReplayed
	}
	return ErrRefreshRevoked
}

// terminatedChainError builds the classified refresh error for a dead chain.
func terminatedChainError(cause, chainID string) *Error {
	if cause == "replay" {
		return newError(ErrRefreshReplayed, "credential belongs to chain %s terminated by a detected replay", chainID[:8])
	}
	return newError(ErrRefreshRevoked, "credential belongs to chain %s terminated by %s", chainID[:8], cause)
}

// Login creates a new session chain for subject with exactly roles/scopes.
func (s *Service) Login(subject string, roles, scopes []string, now time.Time) (*IssueResult, error) {
	refresh, err := tokens.NewOpaqueID()
	if err != nil {
		return nil, newError(ErrInvalidCredentials, "issue refresh credential: %v", err)
	}
	chainID, err := tokens.NewOpaqueID()
	if err != nil {
		return nil, newError(ErrInvalidCredentials, "issue chain id: %v", err)
	}
	roles = append([]string(nil), roles...)
	scopes = append([]string(nil), scopes...)
	sess := &Session{
		ID: chainID, ChainID: chainID, Subject: subject,
		Roles: roles, Scopes: scopes, RefreshToken: refresh,
		CreatedAt: now, ExpiresAt: now.Add(s.opts.RefreshTokenTTL),
	}
	tok, err := s.signer.Sign(tokens.Claims{
		Subject: subject, Roles: roles, Scopes: scopes, ChainID: chainID,
		IssuedAt: now, ExpiresAt: now.Add(s.opts.AccessTokenTTL),
	}, now)
	if err != nil {
		return nil, MapTokenError(err)
	}
	s.mu.Lock()
	// Capacity gate: the check and the insertion happen under the same lock,
	// so concurrent logins can never push a subject past the limit, and slots
	// freed by logout/termination are immediately reusable.
	if max := s.opts.MaxActiveChainsPerSubject; max > 0 && len(s.activeChains[subject]) >= max {
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("login: subject=%s => denied session_limit_exceeded (active=%d max=%d)",
				subject, max, max)
		}
		return nil, newError(ErrTooManySessions,
			"subject %s already holds %d active session chains (max %d)", subject, max, max)
	}
	s.byRefresh[refresh] = sess
	s.chains[chainID] = []*Session{sess}
	if s.activeChains[subject] == nil {
		s.activeChains[subject] = make(map[string]struct{})
	}
	s.activeChains[subject][chainID] = struct{}{}
	s.mu.Unlock()
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("login: subject=%s roles=%v scopes=%v chain=%s => issued refresh=%s key=%s",
			subject, roles, scopes, chainID[:8], short(refresh), tok.KeyID)
	}
	return &IssueResult{AccessToken: tok, RefreshToken: refresh, Session: sess}, nil
}

// revokeChainLocked marks every session of a chain revoked and releases the
// subject's capacity slot. It is idempotent: the first call records the
// reason and returns true, later calls are no-ops returning false. Refresh
// credentials of a terminated chain are retained in the index so later
// presentations are classified by the termination reason instead of
// "not found".
func (s *Service) revokeChainLocked(chainID, reason string) bool {
	if _, done := s.terminated[chainID]; done {
		return false
	}
	nodes := s.chains[chainID]
	for _, n := range nodes {
		n.Revoked = true
	}
	s.terminated[chainID] = reason
	if len(nodes) > 0 {
		subject := nodes[0].Subject
		delete(s.activeChains[subject], chainID)
		if len(s.activeChains[subject]) == 0 {
			delete(s.activeChains, subject)
		}
	}
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("chain-terminated: chain=%s reason=%q sessions=%d",
			chainID[:8], reason, len(nodes))
	}
	return true
}

// Refresh performs a one-time rotation.
//
// Semantics (deterministic):
//   - unknown credential ........... refresh_not_found
//   - credential of revoked chain .. refresh_replayed (chain terminated)
//   - another refresh in flight .... concurrent_refresh (no state changes)
//   - already-consumed credential .. refresh_replayed; whole chain revoked
//   - expired, unconsumed .......... refresh_expired (no rotation)
//   - otherwise .................... rotate exactly once, append one session
//
// Only one concurrent refresh of the same credential can succeed; losers make
// no state change and cannot fork the chain.
func (s *Service) Refresh(raw string, now time.Time) (*IssueResult, error) {
	if raw == "" {
		return nil, newError(ErrRefreshNotFound, "empty refresh credential")
	}
	s.mu.Lock()
	sess, ok := s.byRefresh[raw]
	switch {
	case !ok:
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s => denied refresh_not_found (credential not indexed)", short(raw))
		}
		return nil, newError(ErrRefreshNotFound, "refresh credential is not recognized")
	case sess.Revoked:
		reason := s.terminated[sess.ChainID]
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s chain=%s => denied %s (chain terminated, cause=%q)",
				short(raw), sess.ChainID[:8], refreshDeniedCode(reason), reason)
		}
		return nil, terminatedChainError(reason, sess.ChainID)
	}
	if _, busy := s.inflight[raw]; busy {
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s chain=%s => denied concurrent_refresh (another rotation in flight)",
				short(raw), sess.ChainID[:8])
		}
		return nil, newError(ErrConcurrentRefresh, "a refresh for this credential is already in progress")
	}
	if sess.Used {
		s.revokeChainLocked(sess.ChainID, "replay")
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s chain=%s => denied refresh_replayed + chain revoked (one-time-use violation)",
				short(raw), sess.ChainID[:8])
		}
		return nil, newError(ErrRefreshReplayed, "refresh credential %s was already consumed; replay detected, chain terminated", short(raw))
	}
	if !now.Before(sess.ExpiresAt) {
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s chain=%s => denied refresh_expired (expired_at=%s)",
				short(raw), sess.ChainID[:8], sess.ExpiresAt.Format(time.RFC3339))
		}
		return nil, newError(ErrRefreshExpired, "refresh credential expired at %s", sess.ExpiresAt.Format(time.RFC3339))
	}
	// Reservation: any second presentation while we prepare the rotation is a
	// concurrency loser, not a (heavier) replay event.
	s.inflight[raw] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.inflight, raw)
		s.mu.Unlock()
	}()

	// Prepare new material outside the state lock. Permissions are inherited
	// exclusively from the existing session: the caller cannot widen them.
	newRefresh, err := tokens.NewOpaqueID()
	if err != nil {
		return nil, newError(ErrInvalidCredentials, "issue refresh credential: %v", err)
	}
	tok, err := s.signer.Sign(tokens.Claims{
		Subject: sess.Subject, Roles: append([]string(nil), sess.Roles...),
		Scopes:   append([]string(nil), sess.Scopes...),
		ChainID:  sess.ChainID,
		IssuedAt: now, ExpiresAt: now.Add(s.opts.AccessTokenTTL),
	}, now)
	if err != nil {
		return nil, MapTokenError(err)
	}

	// Commit: revalidate under lock because an ancestor replay on another
	// goroutine may have terminated this chain while we were signing.
	// Locking is explicit (not deferred) so it pairs exactly with the
	// reservation cleanup below on every return path.
	s.mu.Lock()
	cur, ok := s.byRefresh[raw]
	switch {
	case !ok:
		delete(s.inflight, raw)
		s.mu.Unlock()
		return nil, newError(ErrRefreshNotFound, "refresh credential disappeared during rotation")
	case cur.Revoked:
		reason := s.terminated[cur.ChainID]
		delete(s.inflight, raw)
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s => denied %s at commit (chain terminated concurrently, cause=%q)",
				short(raw), refreshDeniedCode(reason), reason)
		}
		return nil, terminatedChainError(reason, cur.ChainID)
	case cur.Used:
		s.revokeChainLocked(cur.ChainID, "replay")
		delete(s.inflight, raw)
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s => denied refresh_replayed at commit; chain revoked", short(raw))
		}
		return nil, newError(ErrRefreshReplayed, "refresh credential consumed concurrently; chain terminated")
	case !now.Before(cur.ExpiresAt):
		delete(s.inflight, raw)
		s.mu.Unlock()
		return nil, newError(ErrRefreshExpired, "refresh credential expired at %s", cur.ExpiresAt.Format(time.RFC3339))
	}
	id, err := tokens.NewOpaqueID()
	if err != nil {
		delete(s.inflight, raw)
		s.mu.Unlock()
		return nil, newError(ErrInvalidCredentials, "issue session id: %v", err)
	}
	next := &Session{
		ID: id, ChainID: cur.ChainID, Subject: cur.Subject,
		Roles: append([]string(nil), cur.Roles...), Scopes: append([]string(nil), cur.Scopes...),
		RefreshToken: newRefresh, ParentID: cur.ID,
		CreatedAt: now, ExpiresAt: now.Add(s.opts.RefreshTokenTTL),
	}
	cur.Used = true
	s.byRefresh[newRefresh] = next
	s.chains[cur.ChainID] = append(s.chains[cur.ChainID], next)
	delete(s.inflight, raw)
	s.mu.Unlock()
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("refresh: input=%s chain=%s parent=%s => rotated once; new_refresh=%s roles=%v scopes=%v key=%s",
			short(raw), cur.ChainID[:8], cur.ID[:8], short(newRefresh), next.Roles, next.Scopes, tok.KeyID)
	}
	return &IssueResult{AccessToken: tok, RefreshToken: newRefresh, Session: next}, nil
}

// Authenticate verifies an access token and returns its claims. Empty input
// is a distinct "missing token" cause so entry points can say unauthenticated
// without blaming the signature.
func (s *Service) Authenticate(accessToken string, now time.Time) (*tokens.Claims, error) {
	if accessToken == "" {
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("authenticate: input=(empty) => missing_token")
		}
		return nil, newError(ErrMissingToken, "no access token presented")
	}
	claims, err := s.signer.Verify(accessToken, now)
	if err != nil {
		ae := MapTokenError(err)
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("authenticate: input=%s => denied %s: %s", short(accessToken), ae.Code, ae.Reason)
		}
		return nil, ae
	}
	// A cryptographically valid token is still rejected when its session chain
	// has been terminated (logout / per-subject termination / replay): ending
	// a chain invalidates its outstanding access tokens immediately. Tokens
	// without a chain binding skip this check.
	if claims.ChainID != "" {
		s.mu.Lock()
		cause, dead := s.terminated[claims.ChainID]
		s.mu.Unlock()
		if dead {
			if s.opts.Logger != nil {
				s.opts.Logger.Printf("authenticate: input=%s subject=%s chain=%s => denied session_revoked (chain terminated, cause=%q)",
					short(accessToken), claims.Subject, claims.ChainID[:8], cause)
			}
			return nil, newError(ErrSessionRevoked, "session chain %s was terminated by %s; access token no longer valid",
				claims.ChainID[:8], cause)
		}
	}
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("authenticate: input=%s => accepted subject=%s roles=%v scopes=%v",
			short(accessToken), claims.Subject, claims.Roles, claims.Scopes)
	}
	return claims, nil
}

// ChainLength reports the number of sessions currently stored for a chain.
func (s *Service) ChainLength(chainID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.chains[chainID])
}

// LogoutResult describes a terminated chain.
type LogoutResult struct {
	ChainID  string
	Sessions int
}

// Logout ends the session chain that raw belongs to. Any credential of the
// chain works: the one issued at login, the current one, or an already
// consumed one — all of them identify the same chain.
//
// Semantics (deterministic):
//   - unknown credential ....... refresh_not_found (nothing happens)
//   - chain already terminated . success, idempotent no-op (same result)
//   - otherwise ................ whole chain revoked, capacity slot released
//
// After logout, every access token minted on the chain fails authentication
// with session_revoked, and any refresh on the chain fails with
// refresh_revoked — a fixed conclusion distinct from refresh_not_found.
func (s *Service) Logout(raw string) (*LogoutResult, error) {
	if raw == "" {
		return nil, newError(ErrRefreshNotFound, "empty refresh credential")
	}
	s.mu.Lock()
	sess, ok := s.byRefresh[raw]
	if !ok {
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("logout: input=%s => denied refresh_not_found (credential not indexed)", short(raw))
		}
		return nil, newError(ErrRefreshNotFound, "refresh credential is not recognized")
	}
	chainID := sess.ChainID
	first := s.revokeChainLocked(chainID, "logout")
	res := &LogoutResult{ChainID: chainID, Sessions: len(s.chains[chainID])}
	s.mu.Unlock()
	if s.opts.Logger != nil {
		if first {
			s.opts.Logger.Printf("logout: input=%s chain=%s => terminated %d session(s); access tokens on chain now session_revoked",
				short(raw), chainID[:8], res.Sessions)
		} else {
			s.opts.Logger.Printf("logout: input=%s chain=%s => already terminated; idempotent no-op", short(raw), chainID[:8])
		}
	}
	return res, nil
}

// TerminateSubject ends every live chain of subject at once and returns how
// many chains were terminated. It races deterministically with in-flight
// refreshes: termination happens under the same state lock that refresh
// commits revalidate against, so once TerminateSubject returns no refresh of
// this subject can succeed and no in-flight rotation can still append a
// session — a commit either landed before the lock was taken (and is then
// revoked here) or observes the revocation and fails with refresh_revoked.
func (s *Service) TerminateSubject(subject string) int {
	s.mu.Lock()
	live := make([]string, 0, len(s.activeChains[subject]))
	for chainID := range s.activeChains[subject] {
		live = append(live, chainID)
	}
	for _, chainID := range live {
		s.revokeChainLocked(chainID, "subject_terminated")
	}
	s.mu.Unlock()
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("terminate-subject: subject=%s => terminated=%d live_chains", subject, len(live))
	}
	return len(live)
}

// ActiveChains reports how many un-terminated chains subject currently holds.
func (s *Service) ActiveChains(subject string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.activeChains[subject])
}
