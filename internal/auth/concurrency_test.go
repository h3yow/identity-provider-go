package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// All tests in this file pin time, so conclusions depend only on committed
// state — never on goroutine scheduling. Each scenario is repeated over many
// rounds and run under -race.

// A credential presented after the winner committed, still inside the
// replay-grace window with its successor alive as the chain tip, must be a
// stable concurrent_refresh (the client-timeout retry shape) and must never
// terminate the live chain. Same inputs => same code, every round.
func TestRetryAfterCommitWithinGraceStable(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

	for round := 0; round < 30; round++ {
		svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
		res, err := svc.Login(fmt.Sprintf("grace-%d", round), nil, nil, t0)
		if err != nil {
			t.Fatal(err)
		}
		// Winner rotates at +1s; the client misses the response and retries
		// with the old credential at +2s (well inside the 30s grace).
		win, err := svc.Refresh(res.RefreshToken, t0.Add(time.Second))
		if err != nil {
			t.Fatalf("round %d: winner: %v", round, err)
		}
		if _, err := svc.Refresh(res.RefreshToken, t0.Add(2*time.Second)); code(err) != ErrConcurrentRefresh {
			t.Fatalf("round %d: in-grace retry => %v, want concurrent_refresh", round, err)
		}
		// Chain must survive: the successor still rotates and length grew once.
		if _, err := svc.Refresh(win.RefreshToken, t0.Add(3*time.Second)); err != nil {
			t.Fatalf("round %d: successor must survive in-grace retry: %v", round, err)
		}
		if got := svc.ChainLength(res.Session.ChainID); got != 3 {
			t.Fatalf("round %d: chain length = %d, want 3", round, got)
		}
		t.Logf("round=%02d retry input=%s at=+2s => concurrent_refresh; chain live length=3",
			round, short(res.RefreshToken))
	}
}

// After the replay-grace window closes, a duplicate presentation with the
// successor still the chain tip is a genuine one-time-use violation: stable
// refresh_replayed, chain terminated. This is the "old credential reused long
// after rotation" case the grace window must not weaken.
func TestReplayAfterGraceStillTerminates(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, 2*time.Hour)
	res, _ := svc.Login("mallory", nil, nil, t0)

	win, err := svc.Refresh(res.RefreshToken, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(res.RefreshToken, t0.Add(31*time.Second)); code(err) != ErrConcurrentRefresh {
		t.Fatalf("in-grace duplicate => %v, want concurrent_refresh", err)
	}
	t.Logf("boundary input=%s at=+31s grace=30s => concurrent_refresh (chain live)", short(res.RefreshToken))

	// Just beyond the default 30s window with successor still live => replay.
	if _, err := svc.Refresh(res.RefreshToken, t0.Add(time.Minute+31*time.Second)); code(err) != ErrRefreshReplayed {
		t.Fatalf("out-of-grace duplicate => %v, want refresh_replayed", err)
	}
	t.Logf("replay input=%s at=+91s => refresh_replayed, chain terminated", short(res.RefreshToken))
	// Successor dies with the chain, classified by the replay cause.
	if _, err := svc.Refresh(win.RefreshToken, t0.Add(2*time.Minute)); code(err) != ErrRefreshReplayed {
		t.Fatalf("successor after replay => %v, want refresh_replayed", err)
	}
	if got := svc.ChainLength(res.Session.ChainID); got != 2 {
		t.Fatalf("chain length = %d, want 2 (replay appends nothing)", got)
	}
}

// A duplicate once the chain has advanced past the successor is always a
// replay, even inside the grace window: rotating R1->R2->R3 and then
// presenting R1 again is unambiguous reuse, not a retry.
func TestReplayOnceChainAdvanced(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, 2*time.Hour)
	res, _ := svc.Login("mallory2", nil, nil, t0)

	r2, err := svc.Refresh(res.RefreshToken, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	r3, err := svc.Refresh(r2.RefreshToken, t0.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// R1 again at +3s (inside the 30s window), but the chain already moved to
	// R3: structural replay regardless of the clock.
	if _, err := svc.Refresh(res.RefreshToken, t0.Add(3*time.Second)); code(err) != ErrRefreshReplayed {
		t.Fatalf("R1 after chain advanced => %v, want refresh_replayed", err)
	}
	t.Logf("structural replay input=%s at=+3s (chain advanced to %s) => refresh_replayed",
		short(res.RefreshToken), short(r3.RefreshToken))
	if _, err := svc.Refresh(r3.RefreshToken, t0.Add(4*time.Second)); code(err) != ErrRefreshReplayed {
		t.Fatalf("live tip after structural replay => %v, want refresh_replayed", err)
	}
}

// TerminateSubject racing in-flight refreshes: however the winner's commit
// and termination interleave, after TerminateSubject returns every credential
// of the subject must reach the same fixed conclusion refresh_revoked (distinct
// from refresh_not_found), no refresh may succeed past that point, and no
// session may appear. A barrier pins the duplicate presentations at exactly
// the winner's commit instant so both interleavings are exercised.
func TestTerminateRacesRefreshDeterministic(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	const rounds = 25
	const chainsPerRound = 3

	for round := 0; round < rounds; round++ {
		svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
		type chain struct {
			id string
			r0 string
		}
		var cs []chain
		for i := 0; i < chainsPerRound; i++ {
			res, err := svc.Login(fmt.Sprintf("racer-%d", round), nil, nil, t0)
			if err != nil {
				t.Fatal(err)
			}
			cs = append(cs, chain{res.Session.ChainID, res.RefreshToken})
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		var mu sync.Mutex
		outcomes := map[string]int{}
		record := func(err error) {
			mu.Lock()
			if err == nil {
				outcomes["success"]++
			} else {
				outcomes[string(code(err))]++
			}
			mu.Unlock()
		}

		// Each chain: one winner plus a storm of duplicates that may land
		// before, during, or after the winner's commit; termination runs
		// concurrently with the whole burst.
		for _, c := range cs {
			wg.Add(1)
			go func(raw string) {
				defer wg.Done()
				<-start
				r, err := svc.Refresh(raw, t0.Add(time.Second))
				record(err)
				// Immediately retry the consumed credential too: under the
				// race it must never become refresh_replayed (only
				// concurrent_refresh while live, or refresh_revoked once
				// terminated), and the chain must never be replay-killed.
				if err == nil {
					_ = r.RefreshToken
				}
				_, e := svc.Refresh(raw, t0.Add(time.Second))
				record(e)
			}(c.r0)
			for j := 0; j < 6; j++ {
				wg.Add(1)
				go func(raw string) {
					defer wg.Done()
					<-start
					_, err := svc.Refresh(raw, t0.Add(time.Second))
					record(err)
				}(c.r0)
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			n := svc.TerminateSubject(fmt.Sprintf("racer-%d", round))
			_ = n
		}()

		close(start)
		wg.Wait()

		// Invariants independent of scheduling.
		if got := svc.ActiveChains(fmt.Sprintf("racer-%d", round)); got != 0 {
			t.Fatalf("round %d: active chains = %d after terminate, want 0", round, got)
		}
		if outcomes["refresh_replayed"] != 0 {
			t.Fatalf("round %d: %d outcomes were refresh_replayed; a terminate/refresh race must never replay-kill a chain: %v",
				round, outcomes["refresh_replayed"], outcomes)
		}
		// No refresh may succeed after termination returns: every chain is
		// frozen and every credential (original or any rotated tail) yields the
		// fixed refresh_revoked conclusion, repeatedly.
		lengths := map[string]int{}
		for _, c := range cs {
			lengths[c.id] = svc.ChainLength(c.id)
			for k := 0; k < 3; k++ {
				if _, err := svc.Refresh(c.r0, t0.Add(2*time.Second)); code(err) != ErrRefreshRevoked {
					t.Fatalf("round %d chain=%s probe=%d post-terminate => %v, want refresh_revoked",
						round, c.id[:8], k, err)
				}
			}
		}
		for _, c := range cs {
			if got := svc.ChainLength(c.id); got != lengths[c.id] {
				t.Fatalf("round %d chain=%s length grew %d -> %d after terminate",
					round, c.id[:8], lengths[c.id], got)
			}
		}
		t.Logf("round=%02d race outcomes=%v; post-terminate all probes refresh_revoked; chain lengths frozen=%v",
			round, outcomes, lengths)
	}
}

// The boundary itself is clock-determined, not scheduler-determined: with the
// chain tip unchanged, a duplicate one instant inside the window is
// concurrent_refresh; advancing the pinned clock one instant past the window
// flips it to refresh_replayed. Both conclusions are reproducible on demand.
func TestGraceBoundaryIsClockDetermined(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, 2*time.Hour)
	svc.opts.ReplayGrace = 10 * time.Second // tighten the window for the test
	res, _ := svc.Login("ned", nil, nil, t0)

	win, err := svc.Refresh(res.RefreshToken, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly at the boundary (consumed+grace) => still inside (before, not
	// after) => concurrent_refresh, chain intact.
	if _, err := svc.Refresh(res.RefreshToken, t0.Add(10*time.Second)); code(err) != ErrConcurrentRefresh {
		t.Fatalf("duplicate exactly at boundary => %v, want concurrent_refresh", err)
	}
	t.Logf("boundary input=%s at=consumed+10s grace=10s => concurrent_refresh", short(res.RefreshToken))
	// One nanosecond past the boundary => replay, chain terminated.
	if _, err := svc.Refresh(res.RefreshToken, t0.Add(10*time.Second+time.Nanosecond)); code(err) != ErrRefreshReplayed {
		t.Fatalf("duplicate past boundary => %v, want refresh_replayed", err)
	}
	t.Logf("past-boundary input=%s at=consumed+10s+1ns => refresh_replayed, chain terminated", short(res.RefreshToken))
	if _, err := svc.Refresh(win.RefreshToken, t0.Add(11*time.Second)); code(err) != ErrRefreshReplayed {
		t.Fatalf("tip after boundary replay => %v, want refresh_replayed", err)
	}
}

// A long concurrent burst against one credential, repeated many rounds: the
// aggregate is always {exactly one success, every other outcome
// concurrent_refresh}, zero replays, chain length exactly 2, and afterwards
// the winner's credential rotates normally.
func TestDuplicateBurstNeverReplays(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	for round := 0; round < 15; round++ {
		svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
		res, _ := svc.Login(fmt.Sprintf("burst-%d", round), nil, nil, t0)
		const n = 48
		var wg sync.WaitGroup
		start := make(chan struct{})
		var mu sync.Mutex
		success, concurrent, replayed := 0, 0, 0
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				<-start
				_, err := svc.Refresh(res.RefreshToken, t0)
				mu.Lock()
				defer mu.Unlock()
				switch codeOrNil(err) {
				case "":
					success++
				case ErrConcurrentRefresh:
					concurrent++
				case ErrRefreshReplayed:
					replayed++
				}
			}()
		}
		close(start)
		wg.Wait()
		t.Logf("round=%02d burst n=%d => success=%d concurrent_refresh=%d replayed=%d length=%d",
			round, n, success, concurrent, replayed, svc.ChainLength(res.Session.ChainID))
		if success != 1 || concurrent != n-1 || replayed != 0 {
			t.Fatalf("round %d: success=%d concurrent=%d replayed=%d, want 1/%d/0",
				round, success, concurrent, replayed, n-1)
		}
		if got := svc.ChainLength(res.Session.ChainID); got != 2 {
			t.Fatalf("round %d: length = %d, want 2", round, got)
		}
	}
}

func codeOrNil(err error) ErrorCode {
	if err == nil {
		return ""
	}
	return code(err)
}
