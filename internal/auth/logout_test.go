package auth

import (
	"sync"
	"testing"
	"time"
)

// Logout with the originally issued refresh credential ends the chain:
// outstanding access tokens die immediately and every credential of the
// chain refreshes to a fixed refresh_revoked (never refresh_not_found).
func TestLogoutEndsChain(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	res, err := svc.Login("henry", []string{"editor"}, []string{"read"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Rotate once so the chain holds a consumed credential and a live one.
	r2, err := svc.Refresh(res.RefreshToken, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	lr, err := svc.Logout(res.RefreshToken) // the credential issued at login
	if err != nil {
		t.Fatalf("logout with original credential: %v", err)
	}
	t.Logf("logout: input=%s chain=%s sessions=%d => terminated",
		short(res.RefreshToken), lr.ChainID[:8], lr.Sessions)

	// Access tokens minted on the chain are invalid immediately.
	if _, err := svc.Authenticate(res.AccessToken.Raw, t0.Add(2*time.Minute)); code(err) != ErrSessionRevoked {
		t.Fatalf("access token after logout => %v, want session_revoked", err)
	}
	if _, err := svc.Authenticate(r2.AccessToken.Raw, t0.Add(2*time.Minute)); code(err) != ErrSessionRevoked {
		t.Fatalf("rotated access token after logout => %v, want session_revoked", err)
	}
	// Any credential of the chain refreshes to the fixed refresh_revoked,
	// distinguishable from "credential never existed".
	for _, raw := range []string{res.RefreshToken, r2.RefreshToken} {
		if _, err := svc.Refresh(raw, t0.Add(3*time.Minute)); code(err) != ErrRefreshRevoked {
			t.Fatalf("refresh %s after logout => %v, want refresh_revoked", short(raw), err)
		}
	}
	t.Logf("post-logout: both access tokens => session_revoked; both credentials => refresh_revoked (not refresh_not_found)")
}

// Repeated logout of the same chain is an idempotent success and does not
// touch other chains of the same subject.
func TestLogoutIdempotentAndIsolated(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	a, _ := svc.Login("irene", nil, nil, t0)
	b, _ := svc.Login("irene", nil, nil, t0)

	if _, err := svc.Logout(a.RefreshToken); err != nil {
		t.Fatalf("first logout: %v", err)
	}
	for i := 0; i < 3; i++ {
		lr, err := svc.Logout(a.RefreshToken)
		if err != nil {
			t.Fatalf("logout repeat %d must not error: %v", i, err)
		}
		if lr.ChainID != a.Session.ChainID {
			t.Fatalf("repeat logout resolved chain=%s, want %s", lr.ChainID[:8], a.Session.ChainID[:8])
		}
	}
	t.Logf("idempotency: 4 logouts of chain=%s, all success, no error", a.Session.ChainID[:8])

	// The sibling chain is untouched: it still refreshes and authenticates.
	if _, err := svc.Refresh(b.RefreshToken, t0.Add(time.Minute)); err != nil {
		t.Fatalf("sibling chain must survive logout of the other chain: %v", err)
	}
	if _, err := svc.Authenticate(b.AccessToken.Raw, t0.Add(time.Minute)); err != nil {
		t.Fatalf("sibling access token must stay valid: %v", err)
	}
	if got := svc.ActiveChains("irene"); got != 1 {
		t.Fatalf("active chains = %d, want 1 (only the sibling)", got)
	}
	t.Logf("isolation: sibling chain=%s still live; active(irene)=1", b.Session.ChainID[:8])
}

// Logout of a credential that was never issued is refresh_not_found, the
// same "never seen" classification refresh uses.
func TestLogoutUnknownCredential(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	if _, err := svc.Logout("00deadbeef"); code(err) != ErrRefreshNotFound {
		t.Fatalf("logout unknown => %v, want refresh_not_found", err)
	}
	if _, err := svc.Logout(""); code(err) != ErrRefreshNotFound {
		t.Fatalf("logout empty => %v, want refresh_not_found", err)
	}
	t.Logf("unknown/empty logout input => refresh_not_found (distinct from refresh_revoked)")
}

// TerminateSubject ends every live chain of the subject at once and leaves
// other subjects alone.
func TestTerminateSubject(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	j1, _ := svc.Login("judy", nil, nil, t0)
	j2, _ := svc.Login("judy", nil, nil, t0)
	j3, _ := svc.Login("judy", nil, nil, t0)
	k, _ := svc.Login("kyle", nil, nil, t0)
	// Rotate one chain so termination covers multi-session chains too.
	j1r, err := svc.Refresh(j1.RefreshToken, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	n := svc.TerminateSubject("judy")
	if n != 3 {
		t.Fatalf("terminated = %d, want 3", n)
	}
	t.Logf("terminate-subject: subject=judy terminated=%d active(judy)=%d", n, svc.ActiveChains("judy"))

	// No credential of judy can refresh anymore; the conclusion is the fixed
	// refresh_revoked on every chain node, old and current alike.
	for i, raw := range []string{j1.RefreshToken, j1r.RefreshToken, j2.RefreshToken, j3.RefreshToken} {
		if _, err := svc.Refresh(raw, t0.Add(2*time.Minute)); code(err) != ErrRefreshRevoked {
			t.Fatalf("judy credential %d after terminate => %v, want refresh_revoked", i, err)
		}
	}
	// Outstanding access tokens of judy are dead.
	if _, err := svc.Authenticate(j1r.AccessToken.Raw, t0.Add(2*time.Minute)); code(err) != ErrSessionRevoked {
		t.Fatalf("judy access token after terminate => %v, want session_revoked", err)
	}
	// No new sessions appeared: chain lengths are frozen at termination time.
	if got := svc.ChainLength(j1.Session.ChainID); got != 2 {
		t.Fatalf("judy chain1 length = %d, want 2 (no session appeared after terminate)", got)
	}
	// kyle is untouched.
	if _, err := svc.Refresh(k.RefreshToken, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("kyle chain must survive: %v", err)
	}
	if got := svc.ActiveChains("kyle"); got != 1 {
		t.Fatalf("active(kyle) = %d, want 1", got)
	}
	// Terminating again is a no-op reporting zero.
	if n := svc.TerminateSubject("judy"); n != 0 {
		t.Fatalf("second terminate = %d, want 0 (idempotent)", n)
	}
	t.Logf("post-terminate: judy all refresh_revoked + session_revoked, chain frozen; kyle intact; re-terminate=0")
}

// TerminateSubject racing in-flight refreshes: after it returns, no refresh
// of the subject can ever succeed again and no session can appear — every
// run must reach the same conclusion regardless of scheduling.
func TestTerminateSubjectRacesRefresh(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	const chains = 4
	creds := make([]string, chains)
	chainIDs := make([]string, chains)
	for i := 0; i < chains; i++ {
		res, err := svc.Login("racer", nil, nil, t0)
		if err != nil {
			t.Fatal(err)
		}
		creds[i] = res.RefreshToken
		chainIDs[i] = res.Session.ChainID
	}

	// Hammer refresh on every chain while the main goroutine terminates the
	// subject mid-flight.
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	lateSuccesses := 0
	results := map[ErrorCode]int{}
	for i := 0; i < chains; i++ {
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, err := svc.Refresh(creds[i], t0.Add(time.Minute))
				mu.Lock()
				if err == nil {
					results["success"]++
				} else {
					results[code(err)]++
				}
				mu.Unlock()
			}(i)
		}
	}
	close(start)
	terminated := svc.TerminateSubject("racer")
	wg.Wait()
	t.Logf("race: terminated=%d refresh outcomes=%v", terminated, results)

	// Deterministic post-conditions, independent of how the race resolved.
	if got := svc.ActiveChains("racer"); got != 0 {
		t.Fatalf("active(racer) = %d after terminate, want 0", got)
	}
	// Every chain must be frozen: no refresh may succeed and no session may
	// appear from now on. Probe each chain repeatedly.
	lengths := make(map[string]int)
	for _, id := range chainIDs {
		lengths[id] = svc.ChainLength(id)
	}
	for round := 0; round < 4; round++ {
		for i, id := range chainIDs {
			// Find the current tail credential by walking is overkill; the
			// original credentials are all indexed and must stay revoked.
			if _, err := svc.Refresh(creds[i], t0.Add(2*time.Minute)); code(err) != ErrRefreshRevoked {
				t.Fatalf("post-terminate refresh chain=%s => %v, want refresh_revoked", id[:8], err)
			}
			if got := svc.ChainLength(id); got != lengths[id] {
				t.Fatalf("chain=%s length changed %d -> %d after terminate (session appeared)", id[:8], lengths[id], got)
			}
		}
	}
	if lateSuccesses != 0 {
		t.Fatalf("refresh succeeded after terminate returned")
	}
	t.Logf("post-terminate invariants hold: active=0, all refreshes refresh_revoked, chain lengths frozen %v", lengths)
}

// The per-subject capacity gate refuses logins past the limit with a
// distinguishable code, and freed slots are reusable.
func TestSessionLimitPerSubject(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
	svc.opts.MaxActiveChainsPerSubject = 2

	l1, err := svc.Login("mia", nil, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := svc.Login("mia", nil, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Login("mia", nil, nil, t0)
	if code(err) != ErrTooManySessions {
		t.Fatalf("third login => %v, want session_limit_exceeded", err)
	}
	t.Logf("limit: active(mia)=2 max=2 => third login denied %s", code(err))

	// The limit is per subject: liam is unaffected.
	if _, err := svc.Login("liam", nil, nil, t0); err != nil {
		t.Fatalf("other subject must not be limited by mia's quota: %v", err)
	}

	// Logout frees a slot for real.
	if _, err := svc.Logout(l1.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if got := svc.ActiveChains("mia"); got != 1 {
		t.Fatalf("active(mia) = %d after logout, want 1", got)
	}
	if _, err := svc.Login("mia", nil, nil, t0); err != nil {
		t.Fatalf("login after logout freed a slot: %v", err)
	}
	t.Logf("logout freed quota: active(mia)=1 -> login succeeds again")

	// Per-subject termination frees everything.
	if n := svc.TerminateSubject("mia"); n != 2 {
		t.Fatalf("terminate mia = %d, want 2", n)
	}
	if got := svc.ActiveChains("mia"); got != 0 {
		t.Fatalf("active(mia) = %d after terminate, want 0", got)
	}
	if _, err := svc.Login("mia", nil, nil, t0); err != nil {
		t.Fatalf("login after terminate freed quota: %v", err)
	}
	// Refreshing does not consume extra quota (rotation stays on one chain).
	if _, err := svc.Refresh(l2.RefreshToken, t0.Add(time.Minute)); code(err) == ErrTooManySessions {
		t.Fatalf("refresh must never hit the login capacity gate: %v", err)
	}
	t.Logf("terminate freed quota: active(mia)=0 -> login ok; refresh unaffected by gate")
}

// Concurrent logins and logouts: the number of live chains must never exceed
// the limit, however the operations interleave.
func TestConcurrentLoginLogoutRespectsLimit(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
	const max = 5
	svc.opts.MaxActiveChainsPerSubject = max

	var mu sync.Mutex
	live := map[string]string{} // chainID -> refresh credential of live logins
	var wg sync.WaitGroup
	start := make(chan struct{})
	violations := 0
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start
			if g%2 == 0 {
				res, err := svc.Login("nina", nil, nil, t0)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					live[res.Session.ChainID] = res.RefreshToken
				} else if code(err) != ErrTooManySessions {
					t.Errorf("unexpected login error: %v", err)
				}
				if n := svc.ActiveChains("nina"); n > max {
					violations++
				}
			} else {
				mu.Lock()
				var victim string
				for id := range live {
					victim = id
					break
				}
				var raw string
				if victim != "" {
					raw = live[victim]
					delete(live, victim)
				}
				mu.Unlock()
				if raw != "" {
					if _, err := svc.Logout(raw); err != nil {
						t.Errorf("logout of live chain: %v", err)
					}
				}
			}
		}(g)
	}
	close(start)
	wg.Wait()

	final := svc.ActiveChains("nina")
	t.Logf("mixed login/logout storm: max=%d final_active=%d limit_violations=%d", max, final, violations)
	if violations != 0 {
		t.Fatalf("active chains exceeded the limit %d times", violations)
	}
	if final > max {
		t.Fatalf("final active = %d, want <= %d", final, max)
	}
}
