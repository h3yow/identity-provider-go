package auth

import (
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/identity-provider-go/internal/keys"
	"github.com/h3yow/identity-provider-go/internal/tokens"
)

// testServiceCap builds a service with a per-subject chain cap (0 = unlimited).
func testServiceCap(t *testing.T, t0 time.Time, accessTTL, refreshTTL time.Duration, cap int) *Service {
	t.Helper()
	r := keys.NewKeyRing()
	if _, err := r.Rotate("k1", []byte("test-secret"), t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	return NewService(tokens.NewSigner(r), Options{
		AccessTokenTTL: accessTTL, RefreshTokenTTL: refreshTTL,
		MaxChainsPerSubject: cap,
		Logger:              log.New(os.Stdout, "  [termtest] ", log.LstdFlags|log.Lmicroseconds),
	})
}

// Logout with the original refresh credential ends the chain: the issued
// access token dies at once, every credential of the chain refreshes to
// session_revoked (distinct from refresh_not_found), and repeats are
// idempotent without touching other chains.
func TestLogoutTerminatesChain(t *testing.T) {
	t0 := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	svc := testServiceCap(t, t0, 30*time.Minute, time.Hour, 0)

	victim, _ := svc.Login("alice", []string{"editor"}, []string{"read"}, t0)
	bystander, _ := svc.Login("alice", []string{"editor"}, []string{"read"}, t0)

	// Rotate once so the chain holds two credentials; logout with the
	// ORIGINAL credential issued at login.
	rot, err := svc.Refresh(victim.RefreshToken, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Logout(victim.RefreshToken, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("logout with original credential: %v", err)
	}
	t.Logf("logout input=%s chain=%s => terminated", short(victim.RefreshToken), victim.Session.ChainID[:8])

	// The already-issued access token is invalid immediately.
	if _, err := svc.Authenticate(rot.AccessToken.Raw, t0.Add(2*time.Minute)); code(err) != ErrSessionRevoked {
		t.Fatalf("access token after logout => %v, want session_revoked", err)
	}
	t.Logf("post-logout authenticate => code=%s (token would otherwise be valid until %s)",
		ErrSessionRevoked, rot.AccessToken.Claims.ExpiresAt.Format(time.RFC3339))

	// Any credential of the chain refreshes to session_revoked, which must
	// differ from the never-seen conclusion.
	for _, cred := range []string{victim.RefreshToken, rot.RefreshToken} {
		if _, err := svc.Refresh(cred, t0.Add(3*time.Minute)); code(err) != ErrSessionRevoked {
			t.Fatalf("refresh %s after logout => %v, want session_revoked", short(cred), err)
		}
	}
	if _, err := svc.Refresh("never-issued", t0.Add(3*time.Minute)); code(err) != ErrRefreshNotFound {
		t.Fatalf("unknown credential => %v, want refresh_not_found (must differ from session_revoked)", err)
	}
	t.Logf("post-logout refresh on chain => %s; unknown credential => %s (distinct conclusions)",
		ErrSessionRevoked, ErrRefreshNotFound)

	// Idempotent: repeated logout succeeds and changes nothing.
	if err := svc.Logout(victim.RefreshToken, t0.Add(4*time.Minute)); err != nil {
		t.Fatalf("repeated logout must be idempotent: %v", err)
	}
	if err := svc.Logout(rot.RefreshToken, t0.Add(4*time.Minute)); err != nil {
		t.Fatalf("logout via sibling credential of dead chain must be idempotent: %v", err)
	}
	t.Logf("repeated logout on terminated chain => ok (idempotent)")

	// Unknown credential cannot log anything out.
	if err := svc.Logout("never-issued", t0); code(err) != ErrRefreshNotFound {
		t.Fatalf("logout with unknown credential => %v, want refresh_not_found", err)
	}

	// The sibling chain of the same subject is untouched.
	if _, err := svc.Refresh(bystander.RefreshToken, t0.Add(5*time.Minute)); err != nil {
		t.Fatalf("sibling chain must survive logout of another chain: %v", err)
	}
	if _, err := svc.Authenticate(bystander.AccessToken.Raw, t0.Add(5*time.Minute)); err != nil {
		t.Fatalf("sibling access token must stay valid: %v", err)
	}
	t.Logf("bystander chain=%s still live after logout of chain=%s",
		bystander.Session.ChainID[:8], victim.Session.ChainID[:8])
}

// TerminateSubject ends every live chain of the subject at once and leaves
// other subjects alone.
func TestTerminateSubject(t *testing.T) {
	t0 := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	svc := testServiceCap(t, t0, 30*time.Minute, time.Hour, 0)

	a1, _ := svc.Login("henry", nil, []string{"read"}, t0)
	a2, _ := svc.Login("henry", nil, []string{"read"}, t0)
	other, _ := svc.Login("iris", nil, []string{"read"}, t0)

	if n := svc.TerminateSubject("henry", t0.Add(time.Minute)); n != 2 {
		t.Fatalf("terminated = %d, want 2", n)
	}
	t.Logf("terminate-subject henry => terminated=2 chains (%s, %s)",
		a1.Session.ChainID[:8], a2.Session.ChainID[:8])

	// No refresh for henry can succeed anymore; tokens already issued die.
	for _, res := range []*IssueResult{a1, a2} {
		if _, err := svc.Refresh(res.RefreshToken, t0.Add(2*time.Minute)); code(err) != ErrSessionRevoked {
			t.Fatalf("refresh after terminate => %v, want session_revoked", err)
		}
		if _, err := svc.Authenticate(res.AccessToken.Raw, t0.Add(2*time.Minute)); code(err) != ErrSessionRevoked {
			t.Fatalf("authenticate after terminate => %v, want session_revoked", err)
		}
	}
	t.Logf("post-terminate: all henry refreshes => %s, all his tokens => %s", ErrSessionRevoked, ErrSessionRevoked)

	// Idempotent at subject level: terminating again terminates nothing new.
	if n := svc.TerminateSubject("henry", t0.Add(3*time.Minute)); n != 0 {
		t.Fatalf("second terminate = %d, want 0 (already terminated)", n)
	}

	// Other subjects are unaffected.
	if _, err := svc.Refresh(other.RefreshToken, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("other subject must be unaffected: %v", err)
	}
	t.Logf("bystander subject=iris chain=%s still refreshable", other.Session.ChainID[:8])
}

// The per-subject cap rejects logins with a distinct, explainable cause and
// frees quota again on logout / subject termination.
func TestChainCapacityLimit(t *testing.T) {
	t0 := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	svc := testServiceCap(t, t0, 30*time.Minute, time.Hour, 2)

	r1, err := svc.Login("judy", nil, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.Login("judy", nil, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Login("judy", nil, nil, t0)
	if code(err) != ErrSessionLimit {
		t.Fatalf("third login at cap=2 => %v, want session_limit_exceeded", err)
	}
	t.Logf("cap=2: third login => code=%s (distinct from %s / %s)",
		code(err), ErrRefreshNotFound, ErrInvalidCredentials)

	// The cap is per subject: someone else can still log in.
	if _, err := svc.Login("kate", nil, nil, t0); err != nil {
		t.Fatalf("cap must be per subject, kate login: %v", err)
	}

	// Logout frees the quota for real.
	if err := svc.Logout(r1.RefreshToken, t0); err != nil {
		t.Fatal(err)
	}
	if got := svc.ActiveChains("judy"); got != 1 {
		t.Fatalf("active chains after logout = %d, want 1", got)
	}
	if _, err := svc.Login("judy", nil, nil, t0); err != nil {
		t.Fatalf("login after logout freed a slot: %v", err)
	}
	t.Logf("logout freed quota: active=1, new login accepted")

	// Subject termination frees everything.
	if n := svc.TerminateSubject("judy", t0); n != 2 {
		t.Fatalf("terminate = %d, want 2 live chains", n)
	}
	if got := svc.ActiveChains("judy"); got != 0 {
		t.Fatalf("active chains after terminate = %d, want 0", got)
	}
	if _, err := svc.Login("judy", nil, nil, t0); err != nil {
		t.Fatalf("login after termination freed all slots: %v", err)
	}
	t.Logf("terminate freed quota: active=0, new login accepted")

	// A terminated chain must not resurrect: the old credential stays dead.
	if _, err := svc.Refresh(r2.RefreshToken, t0); code(err) != ErrSessionRevoked {
		t.Fatalf("refresh on terminated chain => %v, want session_revoked", err)
	}
}

// Concurrent logins beyond the cap: exactly cap chains survive, losers get
// session_limit_exceeded; mixed login+logout never exceeds the cap and the
// final count matches the conserved quota arithmetic exactly.
func TestConcurrentLoginLogoutRespectsCap(t *testing.T) {
	t0 := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	const cap = 4
	svc := testServiceCap(t, t0, 30*time.Minute, time.Hour, cap)

	// Phase 1: 16 goroutines race to log in; exactly cap may win.
	const contenders = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	logins := 0
	start := make(chan struct{})
	wg.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.Login("leo", nil, nil, t0)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				logins++
			case code(err) != ErrSessionLimit:
				t.Errorf("login rejection => %v, want session_limit_exceeded", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	t.Logf("phase1: goroutines=%d cap=%d => accepted=%d rejected=%d active=%d",
		contenders, cap, logins, contenders-logins, svc.ActiveChains("leo"))
	if logins != cap {
		t.Fatalf("accepted logins = %d, want exactly cap=%d", logins, cap)
	}
	if got := svc.ActiveChains("leo"); got != cap {
		t.Fatalf("active chains = %d, want %d", got, cap)
	}

	// Phase 2: seed cap live chains with known credentials, then run
	// cap logouts concurrently with 8 fresh logins.
	seeds := make([]string, 0, cap)
	for i := 0; i < cap; i++ {
		res, err := svc.Login("mia", nil, nil, t0)
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, res.RefreshToken)
	}
	var mu2 sync.Mutex
	newLogins := 0
	start2 := make(chan struct{})
	wg.Add(cap + 8)
	for _, cred := range seeds {
		go func(c string) {
			defer wg.Done()
			<-start2
			if err := svc.Logout(c, t0); err != nil {
				t.Errorf("logout of live chain: %v", err)
			}
		}(cred)
	}
	for i := 0; i < 8; i++ {
		go func() {
			defer wg.Done()
			<-start2
			if _, err := svc.Login("mia", nil, nil, t0); err == nil {
				mu2.Lock()
				newLogins++
				mu2.Unlock()
			} else if code(err) != ErrSessionLimit {
				t.Errorf("login rejection => %v, want session_limit_exceeded", err)
			}
		}()
	}
	close(start2)
	wg.Wait()

	final := svc.ActiveChains("mia")
	t.Logf("phase2: logouts=%d concurrent logins accepted=%d => final active=%d (cap=%d)",
		cap, newLogins, final, cap)
	// Conservation: every seeded chain was logged out exactly once, so the
	// final live count must equal the number of new logins that got in,
	// and it can never exceed the cap.
	if final != newLogins {
		t.Fatalf("final active = %d, want %d (accepted logins; quota leaked or lost)", final, newLogins)
	}
	if final > cap {
		t.Fatalf("final active = %d exceeds cap=%d", final, cap)
	}
}

// Terminate vs. in-flight refreshes: once TerminateSubject returns, no
// refresh of that subject can succeed and no session can be appended; the
// chain lengths frozen at that moment must not move afterwards.
func TestTerminateRacesWithRefresh(t *testing.T) {
	t0 := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	svc := testServiceCap(t, t0, 30*time.Minute, time.Hour, 0)

	const chains = 8
	type handle struct {
		chainID string
		current string
	}
	handles := make([]handle, 0, chains)
	for i := 0; i < chains; i++ {
		res, err := svc.Login("racer", nil, []string{"read"}, t0)
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, handle{res.Session.ChainID, res.RefreshToken})
	}

	// Each chain gets a goroutine hammering refresh with its latest
	// credential until told to stop.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var mu sync.Mutex
	refreshOK := 0
	for i := range handles {
		wg.Add(1)
		go func(h *handle) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				res, err := svc.Refresh(h.current, t0.Add(time.Minute))
				if err != nil {
					return // chain terminated: this goroutine is done
				}
				mu.Lock()
				refreshOK++
				h.current = res.RefreshToken
				mu.Unlock()
			}
		}(&handles[i])
	}

	// Let the refreshers run, then terminate the subject mid-flight.
	time.Sleep(20 * time.Millisecond)
	n := svc.TerminateSubject("racer", t0.Add(time.Minute))
	// Snapshot chain lengths at the moment termination is complete. Only
	// the pre-collected chain IDs are read here; the goroutines may still
	// be writing handles[i].current until stop is closed.
	chainIDs := make([]string, 0, chains)
	for i := range handles {
		chainIDs = append(chainIDs, handles[i].chainID)
	}
	frozen := make(map[string]int, chains)
	for _, id := range chainIDs {
		frozen[id] = svc.ChainLength(id)
	}
	close(stop)
	wg.Wait()

	mu.Lock()
	ok := refreshOK
	mu.Unlock()
	t.Logf("race: chains=%d refreshes succeeded before terminate=%d; terminated=%d chains",
		chains, ok, n)
	if n != chains {
		t.Fatalf("terminated = %d, want %d live chains", n, chains)
	}

	// After termination returned, no session may have been appended.
	total := 0
	for _, h := range handles {
		got := svc.ChainLength(h.chainID)
		total += got
		if got != frozen[h.chainID] {
			t.Fatalf("chain %s grew after terminate: %d -> %d", h.chainID[:8], frozen[h.chainID], got)
		}
	}
	t.Logf("post-terminate: %d chains frozen at %d total sessions; no session appended, none lost", chains, total)

	// And no refresh can succeed anymore, with a fixed conclusion.
	mu.Lock()
	for _, h := range handles {
		if _, err := svc.Refresh(h.current, t0.Add(2*time.Minute)); code(err) != ErrSessionRevoked {
			t.Fatalf("post-terminate refresh => %v, want session_revoked", err)
		}
	}
	mu.Unlock()
	t.Logf("post-terminate: all %d latest credentials => %s (deterministic)", chains, ErrSessionRevoked)
}
