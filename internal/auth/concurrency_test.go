package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Terminate-vs-refresh race, repeated over many independent rounds: whatever
// the scheduler does, once TerminateSubject returns the conclusion for every
// credential of the subject is fixed at refresh_revoked — distinguishable
// from refresh_not_found ("never seen") and from refresh_replayed — and no
// session may appear afterwards.
func TestTerminateVsInFlightRefreshDeterministic(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	const rounds = 40
	const chainsPerRound = 3
	const refreshersPerChain = 6

	for round := 0; round < rounds; round++ {
		subject := fmt.Sprintf("term-racer-%d", round)
		creds := make([]string, chainsPerRound)
		chainIDs := make([]string, chainsPerRound)
		for i := 0; i < chainsPerRound; i++ {
			res, err := svc.Login(subject, nil, nil, t0)
			if err != nil {
				t.Fatal(err)
			}
			creds[i] = res.RefreshToken
			chainIDs[i] = res.Session.ChainID
		}

		// Hammer every chain with concurrent refreshes while the main
		// goroutine terminates the subject mid-flight.
		var wg sync.WaitGroup
		start := make(chan struct{})
		var mu sync.Mutex
		outcomes := map[ErrorCode]int{}
		successPerChain := make([]int, chainsPerRound)
		wg.Add(chainsPerRound * refreshersPerChain)
		for i := 0; i < chainsPerRound; i++ {
			for j := 0; j < refreshersPerChain; j++ {
				go func(i int) {
					defer wg.Done()
					<-start
					_, err := svc.Refresh(creds[i], t0.Add(time.Minute))
					mu.Lock()
					if err == nil {
						outcomes["success"]++
						successPerChain[i]++
					} else {
						outcomes[code(err)]++
					}
					mu.Unlock()
				}(i)
			}
		}
		close(start)
		terminated := svc.TerminateSubject(subject)
		wg.Wait()

		// An in-flight refresh has exactly two fates: committed before the
		// termination (and revoked by it), or failed after. Hence per chain at
		// most one success, and the chain length accounts for it exactly.
		for i, id := range chainIDs {
			if successPerChain[i] > 1 {
				t.Fatalf("round %d chain=%s: %d successful refreshes, want <= 1", round, id[:8], successPerChain[i])
			}
			if got, want := svc.ChainLength(id), 1+successPerChain[i]; got != want {
				t.Fatalf("round %d chain=%s: length=%d, want %d (root + committed rotations only)",
					round, id[:8], got, want)
			}
		}
		if got := svc.ActiveChains(subject); got != 0 {
			t.Fatalf("round %d: active(%s)=%d after terminate, want 0", round, subject, got)
		}

		// The fixed post-termination conclusion: every credential of every
		// chain of the subject yields refresh_revoked on every probe, never
		// refresh_not_found, never refresh_replayed, never a success; and no
		// session appears anymore.
		lengths := make(map[string]int, chainsPerRound)
		for _, id := range chainIDs {
			lengths[id] = svc.ChainLength(id)
		}
		for probe := 0; probe < 3; probe++ {
			for i, id := range chainIDs {
				_, err := svc.Refresh(creds[i], t0.Add(2*time.Minute))
				if code(err) != ErrRefreshRevoked {
					t.Fatalf("round %d probe %d chain=%s input=%s => %v, want the fixed refresh_revoked",
						round, probe, id[:8], short(creds[i]), err)
				}
				if got := svc.ChainLength(id); got != lengths[id] {
					t.Fatalf("round %d chain=%s: session appeared after terminate (%d -> %d)",
						round, id[:8], lengths[id], got)
				}
			}
		}
		if round%10 == 0 || round == rounds-1 {
			t.Logf("round %d: subject=%s terminated=%d outcomes=%v => post-terminate verdict fixed at refresh_revoked, lengths frozen %v",
				round, subject, terminated, outcomes, lengths)
		}
	}
	t.Logf("terminate-vs-refresh: %d rounds, every round reached the identical post-termination conclusion (refresh_revoked, no new sessions)", rounds)
}

// The same credential submitted concurrently, then retried shortly after a
// client-side timeout: the loser's verdict must be stable — always
// concurrent_refresh, never replay — and the live chain must survive.
func TestSameCredentialConcurrentAndRetryStable(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	const rounds = 30
	const submitters = 16

	for round := 0; round < rounds; round++ {
		subject := fmt.Sprintf("retry-racer-%d", round)
		res, err := svc.Login(subject, nil, nil, t0)
		if err != nil {
			t.Fatal(err)
		}
		raw := res.RefreshToken
		chain := res.Session.ChainID
		rotatedAt := t0.Add(time.Minute)

		// Phase 1: many goroutines submit the same credential at once.
		var wg sync.WaitGroup
		start := make(chan struct{})
		var mu sync.Mutex
		var winner *IssueResult
		winners, concurrent, replays, others := 0, 0, 0, 0
		wg.Add(submitters)
		for i := 0; i < submitters; i++ {
			go func() {
				defer wg.Done()
				<-start
				r, err := svc.Refresh(raw, rotatedAt)
				mu.Lock()
				switch {
				case err == nil:
					winners++
					winner = r
				case code(err) == ErrConcurrentRefresh:
					concurrent++
				case code(err) == ErrRefreshReplayed:
					replays++
				default:
					others++
				}
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()

		if winners != 1 {
			t.Fatalf("round %d: winners=%d, want exactly 1", round, winners)
		}
		if concurrent != submitters-1 || replays != 0 || others != 0 {
			t.Fatalf("round %d: losers split concurrent=%d replayed=%d other=%d; every loser must be concurrent_refresh",
				round, concurrent, replays, others)
		}

		// Phase 2: the client "timed out" and retries the same credential
		// shortly after, still inside the grace window. Every retry gets the
		// identical verdict and the chain is not harmed.
		for k := 0; k < 3; k++ {
			retryAt := rotatedAt.Add(time.Duration(k+1) * time.Second)
			if _, err := svc.Refresh(raw, retryAt); code(err) != ErrConcurrentRefresh {
				t.Fatalf("round %d retry %d at +%ds => %v, want the stable concurrent_refresh",
					round, k, k+1, err)
			}
		}
		if got := svc.ChainLength(chain); got != 2 {
			t.Fatalf("round %d: chain length=%d after retries, want 2 (retries changed no state)", round, got)
		}

		// The chain is still alive: the rotated credential refreshes fine.
		if _, err := svc.Refresh(winner.RefreshToken, rotatedAt.Add(2*time.Second)); err != nil {
			t.Fatalf("round %d: live chain must survive duplicate submissions: %v", round, err)
		}
		if round%10 == 0 || round == rounds-1 {
			t.Logf("round %d: input=%s submitters=%d => winners=1 concurrent_refresh=%d replayed=%d; retries=>concurrent_refresh; chain=%s alive (length=%d)",
				round, short(raw), submitters, concurrent, replays, chain[:8], svc.ChainLength(chain))
		}
	}
	t.Logf("same-credential concurrent+retry: %d rounds, loser verdict never drifted to replay, no live chain was killed", rounds)
}

// Genuine replay detection is not weakened by the grace window: presenting a
// rotated-out credential after the window still terminates the whole chain,
// while inside the window the very same action is a harmless duplicate.
func TestGenuineReplayStillTerminatesChain(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)
	grace := svc.opts.RotationGrace

	res, _ := svc.Login("replay-victim", nil, nil, t0)
	old := res.RefreshToken
	chain := res.Session.ChainID
	rotatedAt := t0.Add(time.Minute)
	r2, err := svc.Refresh(old, rotatedAt)
	if err != nil {
		t.Fatal(err)
	}

	// Boundary: one second before the grace expires the old credential is
	// still a duplicate — stable concurrent_refresh, chain untouched.
	if _, err := svc.Refresh(old, rotatedAt.Add(grace-time.Second)); code(err) != ErrConcurrentRefresh {
		t.Fatalf("grace-epsilon => %v, want concurrent_refresh", err)
	}
	if svc.ActiveChains("replay-victim") != 1 {
		t.Fatal("in-grace duplicate must not terminate the chain")
	}
	t.Logf("boundary: input=%s at rotation+%s => concurrent_refresh (chain alive)", short(old), grace-time.Second)

	// Past the grace window the same credential is a genuine replay: the
	// whole chain is terminated and every credential of it reports
	// refresh_replayed from then on.
	if _, err := svc.Refresh(old, rotatedAt.Add(grace+time.Second)); code(err) != ErrRefreshReplayed {
		t.Fatalf("grace+epsilon => %v, want refresh_replayed", err)
	}
	if _, err := svc.Refresh(r2.RefreshToken, rotatedAt.Add(grace+2*time.Second)); code(err) != ErrRefreshReplayed {
		t.Fatalf("current credential after replay => %v, want refresh_replayed (chain terminated)", err)
	}
	if got := svc.ActiveChains("replay-victim"); got != 0 {
		t.Fatalf("active(replay-victim)=%d after replay, want 0", got)
	}
	if got := svc.ChainLength(chain); got != 2 {
		t.Fatalf("chain length=%d after replay, want 2 (no fork)", got)
	}
	t.Logf("boundary: input=%s at rotation+%s => refresh_replayed, chain=%s terminated (replay detection intact)",
		short(old), grace+time.Second, chain[:8])
}

// Termination while a duplicate retry is also in flight: the termination
// cause stays subject_terminated and the post-termination verdict is the
// fixed refresh_revoked — a retry racing the terminate must not flip the
// chain into replay state.
func TestTerminateRacingRetryKeepsFixedVerdict(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	svc, _ := testService(t, t0, 10*time.Minute, time.Hour)

	const rounds = 40
	for round := 0; round < rounds; round++ {
		subject := fmt.Sprintf("term-retry-%d", round)
		res, err := svc.Login(subject, nil, nil, t0)
		if err != nil {
			t.Fatal(err)
		}
		raw := res.RefreshToken
		chain := res.Session.ChainID

		// One rotation in flight, retried concurrently many times, while the
		// subject is terminated mid-flight.
		var wg sync.WaitGroup
		start := make(chan struct{})
		var mu sync.Mutex
		outcomes := map[ErrorCode]int{}
		wg.Add(8)
		for i := 0; i < 8; i++ {
			go func() {
				defer wg.Done()
				<-start
				_, err := svc.Refresh(raw, t0.Add(time.Minute))
				mu.Lock()
				if err == nil {
					outcomes["success"]++
				} else {
					outcomes[code(err)]++
				}
				mu.Unlock()
			}()
		}
		close(start)
		svc.TerminateSubject(subject)
		wg.Wait()

		// No replay may ever be recorded for this race: retries are duplicates,
		// and the termination is the only thing allowed to end the chain.
		if outcomes[ErrRefreshReplayed] != 0 {
			t.Fatalf("round %d: replay appeared in terminate/retry race: %v", round, outcomes)
		}
		// The fixed conclusion holds for the credential on every probe.
		for probe := 0; probe < 3; probe++ {
			if _, err := svc.Refresh(raw, t0.Add(2*time.Minute)); code(err) != ErrRefreshRevoked {
				t.Fatalf("round %d probe %d => %v, want the fixed refresh_revoked", round, probe, err)
			}
		}
		if got, want := svc.ChainLength(chain), 1+outcomes["success"]; got != want {
			t.Fatalf("round %d: chain length=%d, want %d", round, got, want)
		}
		if round%10 == 0 || round == rounds-1 {
			t.Logf("round %d: subject=%s outcomes=%v => verdict fixed at refresh_revoked, no replay misclassification",
				round, subject, outcomes)
		}
	}
	t.Logf("terminate racing retry: %d rounds, termination cause never hijacked by a duplicate, verdict stable", rounds)
}
