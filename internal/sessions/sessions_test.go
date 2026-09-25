package sessions

import (
	"errors"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func newTestSession(t *testing.T, s *Store) (Session, Credential) {
	t.Helper()
	sess, cred := s.Create("sess-1", "alice", Grants{Roles: []string{"admin"}, Scopes: []string{"read", "write"}}, time.Hour, t0)
	t.Logf("[sessions] input=create session=%s subject=%s roles=%v scopes=%v => cred#%d issued",
		sess.ID, sess.Subject, sess.Grants.Roles, sess.Grants.Scopes, cred.Version)
	return sess, cred
}

func TestRotateOneTimeUseAndChainAdvance(t *testing.T) {
	s := NewStore()
	_, c1 := newTestSession(t, s)

	r1, err := s.Rotate(c1, time.Hour, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	t.Logf("[sessions] input=Rotate(cred#%d) => ok; basis=old consumed, new cred#%d current, session=%s",
		c1.Version, r1.New.Version, r1.Session.ID)
	if r1.New.Version != 2 || !r1.OldEqual(c1) {
		t.Fatalf("unexpected rotation result: %+v", r1)
	}
	if got, _ := s.Get("sess-1"); got.CurrentID != r1.New.ID || got.Version != 2 {
		t.Fatalf("chain did not advance atomically: %+v", got)
	}
	if r1.Session.Grants.Roles[0] != "admin" {
		t.Fatalf("grants snapshot lost: %+v", r1.Session.Grants)
	}
}

func TestReplayRevokesChain(t *testing.T) {
	s := NewStore()
	_, c1 := newTestSession(t, s)
	r1, err := s.Rotate(c1, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	// 攻击者重放旧凭据 c1。
	_, err = s.Rotate(c1, time.Hour, t0.Add(time.Second))
	if !errors.Is(err, ErrCredentialReplay) {
		t.Fatalf("replay err = %v, want ErrCredentialReplay", err)
	}
	t.Logf("[sessions] input=Rotate(USED cred#%d) => replay detected; basis=cred is not current, chain revoked",
		c1.Version)

	sess, _ := s.Get("sess-1")
	if !sess.Revoked {
		t.Fatal("session must be revoked after replay")
	}
	// 即使持有当前的新凭据，链路也已终止：不得分叉出新会话。
	_, err = s.Rotate(r1.New, time.Hour, t0.Add(2*time.Second))
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("post-replay rotate err = %v, want ErrSessionRevoked", err)
	}
	t.Logf("[sessions] input=Rotate(current cred#%d after replay) => session_revoked; basis=Revoked=true short-circuits chain",
		r1.New.Version)

	// 再次重放仍给出确定结论。
	_, err = s.Rotate(c1, time.Hour, t0.Add(3*time.Second))
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("second replay err = %v, want ErrSessionRevoked", err)
	}
}

func TestUnknownAndExpired(t *testing.T) {
	s := NewStore()
	_, c1 := newTestSession(t, s)
	_, err := s.Rotate(Credential{ID: "never-issued", SessionID: "sess-1", Version: 1}, time.Hour, t0)
	if !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("unknown err = %v", err)
	}
	t.Logf("[sessions] input=Rotate(id=never-issued) => unknown credential; basis=no index entry")

	_, err = s.Rotate(c1, time.Hour, t0.Add(2*time.Hour))
	if !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("expired err = %v", err)
	}
	t.Logf("[sessions] input=Rotate(cred#1 at now+2h, exp+1h) => expired; basis=current but past ExpiresAt, session NOT revoked")
	if sess, _ := s.Get("sess-1"); sess.Revoked {
		t.Fatal("expiry must not revoke session (distinct from replay)")
	}
}

func TestConcurrentSameCredentialExactlyOneSucceeds(t *testing.T) {
	s := NewStore()
	_, c1 := newTestSession(t, s)

	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes, replays, revoked, others int
	newIDs := map[string]struct{}{}
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := s.Rotate(c1, time.Hour, t0.Add(time.Minute))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
				newIDs[r.New.ID] = struct{}{}
			case errors.Is(err, ErrCredentialReplay):
				replays++
			case errors.Is(err, ErrSessionRevoked):
				revoked++
			default:
				others++
			}
		}()
	}
	close(start)
	wg.Wait()

	t.Logf("[sessions] input=%d concurrent Rotate(same cred#1) => success=%d replay=%d revoked=%d other=%d distinct_new_creds=%d",
		n, successes, replays, revoked, others, len(newIDs))
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}
	if len(newIDs) != 1 {
		t.Fatalf("distinct new credentials = %d, want 1 (no state fork)", len(newIDs))
	}
	sess, _ := s.Get("sess-1")
	if !sess.Revoked {
		t.Fatal("losing concurrent attempts are replays; chain must end revoked")
	}
	if others != 0 {
		t.Fatalf("unexpected error category count=%d", others)
	}
}

func TestConcurrentDifferentCredentialsChainLinear(t *testing.T) {
	// 串行推进链后拿到的多个凭据里，只有最后一个是 current；
	// 并发提交它们时，任何旧凭据获胜都会立即吊销链路，结果确定不重复。
	s := NewStore()
	_, c1 := newTestSession(t, s)
	r2, _ := s.Rotate(c1, time.Hour, t0)
	// 此时 c1 已 used，r2.New 为 current。并发提交 c1 与 current。
	creds := []Credential{c1, r2.New}
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	var success int
	for _, c := range creds {
		wg.Add(1)
		go func(c Credential) {
			defer wg.Done()
			<-start
			if r, err := s.Rotate(c, time.Hour, t0.Add(time.Minute)); err == nil {
				mu.Lock()
				success++
				_ = r
				mu.Unlock()
			}
		}(c)
	}
	close(start)
	wg.Wait()
	sess, _ := s.Get("sess-1")
	t.Logf("[sessions] input=concurrent Rotate(used cred + current cred) => success=%d revoked=%v",
		success, sess.Revoked)
	// 若 current 先赢：success=1，旧凭据随后重放 -> revoked。
	// 若旧凭据先到：直接 replay -> revoked，current 失败。两种交错下 success<=1 且无分叉。
	if success > 1 {
		t.Fatalf("success=%d, must be at most 1", success)
	}
	if !sess.Revoked {
		t.Fatal("used credential participating concurrently is replay; chain must revoke")
	}
}

// r 扩展断言辅助。
func (r *Result) OldEqual(c Credential) bool { return r.Old.ID == c.ID && r.Old.Version == c.Version }
