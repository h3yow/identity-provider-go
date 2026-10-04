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

// Options holds token lifetimes, the per-subject chain capacity and an
// optional logger.
type Options struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// MaxChainsPerSubject caps the number of simultaneously live session
	// chains one subject may hold. <= 0 means unlimited.
	MaxChainsPerSubject int
	Logger              Logger
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
	// termCode records why a chain was terminated, so later refreshes on it
	// get a cause-specific code (replay vs. logout vs. subject termination).
	termCode map[string]ErrorCode
	// subjectChains indexes chain IDs by subject for per-subject termination
	// and capacity accounting.
	subjectChains map[string]map[string]struct{}
	inflight      map[string]struct{} // refresh credentials currently being rotated
}

// NewService builds an in-process authentication service.
func NewService(signer *tokens.Signer, opts Options) *Service {
	return &Service{
		signer:        signer,
		opts:          opts.withDefaults(),
		byRefresh:     make(map[string]*Session),
		chains:        make(map[string][]*Session),
		termCode:      make(map[string]ErrorCode),
		subjectChains: make(map[string]map[string]struct{}),
		inflight:      make(map[string]struct{}),
	}
}

// short returns a non-secret prefix used to identify credentials in logs.
func short(raw string) string {
	if len(raw) > 12 {
		return raw[:12] + "..."
	}
	return "(empty)"
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
		Subject: subject, Roles: roles, Scopes: scopes,
		IssuedAt: now, ExpiresAt: now.Add(s.opts.AccessTokenTTL),
		ChainID: chainID,
	}, now)
	if err != nil {
		return nil, MapTokenError(err)
	}
	s.mu.Lock()
	if s.opts.MaxChainsPerSubject > 0 {
		active := 0
		for id := range s.subjectChains[subject] {
			if !s.chainRevokedLocked(id) {
				active++
			}
		}
		if active >= s.opts.MaxChainsPerSubject {
			s.mu.Unlock()
			if s.opts.Logger != nil {
				s.opts.Logger.Printf("login: subject=%s => denied session_limit_exceeded (active=%d cap=%d)",
					subject, active, s.opts.MaxChainsPerSubject)
			}
			return nil, newError(ErrSessionLimit,
				"subject already holds %d live session chains (cap %d)", active, s.opts.MaxChainsPerSubject)
		}
	}
	s.byRefresh[refresh] = sess
	s.chains[chainID] = []*Session{sess}
	if s.subjectChains[subject] == nil {
		s.subjectChains[subject] = make(map[string]struct{})
	}
	s.subjectChains[subject][chainID] = struct{}{}
	s.mu.Unlock()
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("login: subject=%s roles=%v scopes=%v chain=%s => issued refresh=%s key=%s",
			subject, roles, scopes, chainID[:8], short(refresh), tok.KeyID)
	}
	return &IssueResult{AccessToken: tok, RefreshToken: refresh, Session: sess}, nil
}

// revokeChainLocked marks every session of a chain revoked and records the
// cause-specific code later refreshes on this chain will receive. Refresh
// credentials of a terminated chain are retained in the index so later
// presentations are classified as terminated instead of "not found".
func (s *Service) revokeChainLocked(chainID, reason string, code ErrorCode) {
	for _, n := range s.chains[chainID] {
		n.Revoked = true
	}
	s.termCode[chainID] = code
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("chain-terminated: chain=%s reason=%q code=%s sessions=%d",
			chainID[:8], reason, code, len(s.chains[chainID]))
	}
}

// chainRevokedLocked reports whether every session of the chain is revoked.
func (s *Service) chainRevokedLocked(chainID string) bool {
	nodes := s.chains[chainID]
	return len(nodes) > 0 && nodes[0].Revoked
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
		code := s.termCode[sess.ChainID]
		if code == "" {
			code = ErrRefreshReplayed
		}
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s chain=%s => denied %s (chain already terminated)",
				short(raw), sess.ChainID[:8], code)
		}
		return nil, newError(code, "credential belongs to chain %s already terminated", sess.ChainID[:8])
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
		s.revokeChainLocked(sess.ChainID, "replayed consumed credential "+short(raw), ErrRefreshReplayed)
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
		IssuedAt: now, ExpiresAt: now.Add(s.opts.AccessTokenTTL),
		ChainID: sess.ChainID,
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
	case !ok || cur.Revoked:
		code := ErrRefreshReplayed
		if ok {
			if c := s.termCode[cur.ChainID]; c != "" {
				code = c
			}
		}
		delete(s.inflight, raw)
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("refresh: input=%s => denied %s (chain terminated concurrently)", short(raw), code)
		}
		return nil, newError(code, "chain terminated concurrently during refresh")
	case cur.Used:
		s.revokeChainLocked(cur.ChainID, "concurrent double-commit of "+short(raw), ErrRefreshReplayed)
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
	// A token bound to a terminated chain is invalid immediately, even if
	// its signature and expiry are still fine.
	if claims.ChainID != "" {
		s.mu.Lock()
		revoked := s.chainRevokedLocked(claims.ChainID)
		s.mu.Unlock()
		if revoked {
			if s.opts.Logger != nil {
				s.opts.Logger.Printf("authenticate: input=%s chain=%s => denied session_revoked (chain terminated)",
					short(accessToken), claims.ChainID[:8])
			}
			return nil, newError(ErrSessionRevoked, "session chain %s has been terminated", claims.ChainID[:8])
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

// Logout terminates the chain the presented refresh credential belongs to.
//
// Semantics (deterministic):
//   - unknown/empty credential ..... refresh_not_found (nothing changes)
//   - known credential ............. its whole chain is revoked exactly once
//   - already-terminated chain ..... idempotent success, no error
//
// After logout, access tokens issued on the chain fail authentication and
// any refresh on the chain yields session_revoked (distinct from
// refresh_not_found). Other chains of the same subject are untouched.
func (s *Service) Logout(raw string, now time.Time) error {
	if raw == "" {
		return newError(ErrRefreshNotFound, "empty refresh credential")
	}
	s.mu.Lock()
	sess, ok := s.byRefresh[raw]
	if !ok {
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("logout: input=%s => denied refresh_not_found (credential not indexed)", short(raw))
		}
		return newError(ErrRefreshNotFound, "refresh credential is not recognized")
	}
	if s.chainRevokedLocked(sess.ChainID) {
		s.mu.Unlock()
		if s.opts.Logger != nil {
			s.opts.Logger.Printf("logout: input=%s chain=%s => ok (idempotent; chain already terminated)",
				short(raw), sess.ChainID[:8])
		}
		return nil
	}
	s.revokeChainLocked(sess.ChainID, "logout via credential "+short(raw), ErrSessionRevoked)
	subject := sess.Subject
	chainID := sess.ChainID
	s.mu.Unlock()
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("logout: input=%s subject=%s chain=%s => terminated at %s",
			short(raw), subject, chainID[:8], now.Format(time.RFC3339))
	}
	return nil
}

// TerminateSubject revokes every live chain of subject atomically and
// returns how many chains were terminated by this call.
//
// The whole operation runs under the state lock, and Refresh revalidates
// the chain under the same lock before committing a rotation. Therefore
// once TerminateSubject returns, no refresh for this subject can succeed
// and no in-flight refresh can append a new session: the outcome does not
// depend on goroutine scheduling.
func (s *Service) TerminateSubject(subject string, now time.Time) int {
	s.mu.Lock()
	terminated := 0
	for id := range s.subjectChains[subject] {
		if s.chainRevokedLocked(id) {
			continue
		}
		s.revokeChainLocked(id, "subject terminated", ErrSessionRevoked)
		terminated++
	}
	s.mu.Unlock()
	if s.opts.Logger != nil {
		s.opts.Logger.Printf("terminate-subject: subject=%s => terminated=%d at %s",
			subject, terminated, now.Format(time.RFC3339))
	}
	return terminated
}

// ActiveChains reports how many live (non-terminated) chains subject holds.
func (s *Service) ActiveChains(subject string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for id := range s.subjectChains[subject] {
		if !s.chainRevokedLocked(id) {
			active++
		}
	}
	return active
}
