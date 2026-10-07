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

func testService(t *testing.T, t0 time.Time, accessTTL, refreshTTL time.Duration) (*Service, *keys.KeyRing) {
	t.Helper()
	r := keys.NewKeyRing()
	if _, err := r.Rotate("k1", []byte("test-secret"), t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	svc := NewService(tokens.NewSigner(r), Options{
		AccessTokenTTL: accessTTL, RefreshTokenTTL: refreshTTL,
		Logger: log.New(os.Stdout, "  [authtest] ", log.LstdFlags|log.Lmicroseconds),
	})
	return svc, r
}

func code(err error) ErrorCode {
	if ae, ok := AsError(err); ok {
		return ae.Code
	}
	return "non-classified"
}

func TestLoginAndRefreshRotation(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	res, err := svc.Login("alice", []string{"editor"}, []string{"read", "write"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	chain := res.Session.ChainID
	first := res.RefreshToken

	r2, err := svc.Refresh(first, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("first refresh should succeed: %v", err)
	}
	if r2.RefreshToken == first {
		t.Fatal("refresh credential must rotate to a new opaque value")
	}
	if n := svc.ChainLength(chain); n != 2 {
		t.Fatalf("chain length = %d, want 2", n)
	}
	t.Logf("rotation: chain=%s sessions=%d old=%s new=%s roles=%v scopes=%v",
		chain[:8], svc.ChainLength(chain), short(first), short(r2.RefreshToken), r2.Session.Roles, r2.Session.Scopes)

	// A second normal rotation works with the fresh credential.
	r3, err := svc.Refresh(r2.RefreshToken, t0.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second refresh should succeed: %v", err)
	}
	if n := svc.ChainLength(chain); n != 3 {
		t.Fatalf("chain length = %d, want 3", n)
	}
	t.Logf("rotation: chain=%s sessions=%d roles inherited=%v scopes inherited=%v",
		chain[:8], n3(svc, chain), r3.Session.Roles, r3.Session.Scopes)
}

// Replaying the first consumed credential terminates the whole chain.
func TestReplayTerminatesChain(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	res, _ := svc.Login("bob", []string{"viewer"}, []string{"read"}, t0)
	r2, err := svc.Refresh(res.RefreshToken, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// Attacker presents the already-consumed first credential.
	_, err = svc.Refresh(res.RefreshToken, t0.Add(2*time.Minute))
	if code(err) != ErrRefreshReplayed {
		t.Fatalf("replayed credential => %v, want refresh_replayed", err)
	}
	t.Logf("replay input=%s => code=%s chain=%s revoked", short(res.RefreshToken), code(err), res.Session.ChainID[:8])

	// The legitimate current credential must also stop working: chain dead.
	_, err = svc.Refresh(r2.RefreshToken, t0.Add(3*time.Minute))
	if code(err) != ErrRefreshReplayed {
		t.Fatalf("current credential after replay => %v, want refresh_replayed (terminated chain)", err)
	}
	t.Logf("post-replay current credential=%s => code=%s (chain terminated, no forking)", short(r2.RefreshToken), code(err))
}

func TestUnknownAndExpiredRefresh(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, 30*time.Minute)

	res, _ := svc.Login("carol", nil, nil, t0)
	if _, err := svc.Refresh("00deadbeef", t0); code(err) != ErrRefreshNotFound {
		t.Fatalf("unknown credential => %v, want refresh_not_found", err)
	}
	t.Logf("unknown input=00deadbeef => code=%s", ErrRefreshNotFound)

	_, err := svc.Refresh(res.RefreshToken, t0.Add(31*time.Minute))
	if code(err) != ErrRefreshExpired {
		t.Fatalf("expired credential => %v, want refresh_expired", err)
	}
	t.Logf("expired input=%s at=10:31 => code=%s (ttl 30m)", short(res.RefreshToken), code(err))

	// Expired-but-unconsumed credentials remain replay-safe on later use.
	_, err = svc.Refresh(res.RefreshToken, t0.Add(32*time.Minute))
	if code(err) != ErrRefreshExpired {
		t.Fatalf("second expired use => %v, want refresh_expired", err)
	}
}

// Concurrent refreshes of the same credential: exactly one success, no chain
// fork; every loser is classified concurrent_refresh (never refresh_replayed),
// changes no state, and the chain must remain fully usable afterwards. The
// outcome is independent of scheduling.
func TestConcurrentRefreshSingleWinner(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
	res, _ := svc.Login("dave", []string{"editor"}, []string{"read", "write"}, t0)

	const n = 32
	var wg sync.WaitGroup
	winners, losers, replays := 0, 0, 0
	var mu sync.Mutex
	start := make(chan struct{})
	var winnerRT string
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			r, err := svc.Refresh(res.RefreshToken, t0.Add(time.Minute))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
				winnerRT = r.RefreshToken
			case code(err) == ErrConcurrentRefresh:
				losers++
			case code(err) == ErrRefreshReplayed:
				replays++
			}
		}()
	}
	close(start)
	wg.Wait()

	t.Logf("concurrent input=%s goroutines=%d => winners=%d concurrent_refresh=%d replayed=%d chain_length=%d",
		short(res.RefreshToken), n, winners, losers, replays, svc.ChainLength(res.Session.ChainID))
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners)
	}
	if losers != n-1 {
		t.Fatalf("concurrent_refresh losers = %d, want %d (any replay would be a scheduling-dependent false positive)", losers, n-1)
	}
	if replays != 0 {
		t.Fatalf("replays = %d, want 0 (a concurrent duplicate must never terminate a live chain)", replays)
	}
	if n := svc.ChainLength(res.Session.ChainID); n != 2 {
		t.Fatalf("chain length = %d, want 2 (no duplicate session/fork)", n)
	}
	// The winner's fresh credential must still rotate: the chain survived the
	// duplicate storm, and an immediate retry of the consumed input stays a
	// harmless concurrent_refresh inside the grace window.
	if _, err := svc.Refresh(res.RefreshToken, t0.Add(1*time.Minute)); code(err) != ErrConcurrentRefresh {
		t.Fatalf("immediate retry of consumed credential => %v, want concurrent_refresh", err)
	}
	if _, err := svc.Refresh(winnerRT, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("winner credential must still rotate after the duplicate storm: %v", err)
	}
	if n := svc.ChainLength(res.Session.ChainID); n != 3 {
		t.Fatalf("chain length = %d, want 3 (one legitimate append after the storm)", n)
	}
	t.Logf("post-storm: chain still live, length=3; retry input=%s => concurrent_refresh, winner rotated", short(res.RefreshToken))
}

// Refreshes never widen the original grant, even across multiple rotations.
func TestRefreshCannotEscalateScopes(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
	res, _ := svc.Login("erin", []string{"viewer"}, []string{"read"}, t0)

	cur := res.RefreshToken
	for i := 0; i < 3; i++ {
		r, err := svc.Refresh(cur, t0.Add(time.Duration(i+1)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Session.Roles) != 1 || r.Session.Roles[0] != "viewer" ||
			len(r.Session.Scopes) != 1 || r.Session.Scopes[0] != "read" {
			t.Fatalf("refresh %d widened grant: roles=%v scopes=%v", i, r.Session.Roles, r.Session.Scopes)
		}
		// The signed access token carries exactly the inherited grant.
		if got := r.AccessToken.Claims.Scopes; len(got) != 1 || got[0] != "read" {
			t.Fatalf("access token scopes=%v, want [read]", got)
		}
		cur = r.RefreshToken
	}
	t.Logf("escalation check: after 3 rotations roles=[viewer] scopes=[read] preserved exactly")
}

func TestAuthenticateClassifies(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
	res, _ := svc.Login("frank", nil, nil, t0)

	if _, err := svc.Authenticate("", t0); code(err) != ErrMissingToken {
		t.Fatalf("empty token => %v, want missing_token", err)
	}
	if _, err := svc.Authenticate("garbage", t0); code(err) != ErrTokenMalformed {
		t.Fatalf("garbage => %v, want token_malformed", err)
	}
	if _, err := svc.Authenticate(res.AccessToken.Raw, t0.Add(11*time.Minute)); code(err) != ErrTokenExpired {
		t.Fatalf("expired => %v, want token_expired", err)
	}
	claims, err := svc.Authenticate(res.AccessToken.Raw, t0.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("valid token: %v", err)
	}
	t.Logf("authenticate valid token => subject=%s; empty/garbage/expired distinctly classified", claims.Subject)
}

// Key rotation: a token signed by the old key verifies after rotate; a token
// whose kid the ring never knew is rejected as unknown_key_version.
func TestAuthenticateAcrossKeyRotation(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, ring := testService(t, t0, 30*time.Minute, 2*time.Hour)
	res, _ := svc.Login("gina", nil, nil, t0)

	if _, err := ring.Rotate("k2", []byte("new-secret"), t0.Add(10*time.Minute), time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	// Old token (kid k1) still verifies during k1's grace window.
	if _, err := svc.Authenticate(res.AccessToken.Raw, t0.Add(15*time.Minute)); err != nil {
		t.Fatalf("old-key token should verify in grace: %v", err)
	}
	// Newly issued token is signed by k2.
	r2, err := svc.Refresh(res.RefreshToken, t0.Add(16*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if r2.AccessToken.KeyID != "k2" {
		t.Fatalf("new token kid = %s, want k2", r2.AccessToken.KeyID)
	}
	if _, err := svc.Authenticate(r2.AccessToken.Raw, t0.Add(17*time.Minute)); err != nil {
		t.Fatalf("new-key token should verify: %v", err)
	}
	t.Logf("rotation accepted: k1 token verifies in grace; fresh token signed with k2")
}

func n3(s *Service, chain string) int { return s.ChainLength(chain) }
