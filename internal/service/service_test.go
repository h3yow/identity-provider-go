package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	idp "github.com/h3yow/identity-provider-go/internal"
	"github.com/h3yow/identity-provider-go/internal/authz"
	"github.com/h3yow/identity-provider-go/internal/keys"
	"github.com/h3yow/identity-provider-go/internal/sessions"
)

func testService(t *testing.T) (*Service, *clockMock) {
	t.Helper()
	c := &clockMock{t: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
	svc := New(Config{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour})
	svc.now = c.now
	// 重新绑定 issuer/verifier 的时钟（New 时闭包已指向 svc.now，因此直接生效）。
	return svc, c
}

type clockMock struct{ t time.Time }

func (c *clockMock) now() time.Time { return c.t }
func (c *clockMock) advance(d time.Duration) time.Time {
	c.t = c.t.Add(d)
	return c.t
}

func reasonIs(t *testing.T, err error, want idp.Reason) {
	t.Helper()
	var ie *idp.Error
	if !errors.As(err, &ie) {
		t.Fatalf("err %v is not *idp.Error", err)
	}
	if ie.Reason != want {
		t.Fatalf("reason = %s (%q), want %s", ie.Reason, ie.Message, want)
	}
}

func TestEndToEndKeyRotationAcrossSessions(t *testing.T) {
	svc, clk := testService(t)
	res1, err := svc.Login("alice", sessions.Grants{Roles: []string{"admin"}, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	kid1 := res1.KeyVersion
	t.Logf("[svc] input=login alice kid=%s => access/refresh issued", kid1)

	// 轮换签名密钥：新登录走新 kid，旧访问令牌在过渡期内仍被接受。
	kid2, err := svc.RotateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[svc] input=rotate key => new active=%s, %s moved to verifying", kid2, kid1)
	res2, err := svc.Login("bob", sessions.Grants{Roles: []string{"viewer"}, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if res2.KeyVersion != kid2 {
		t.Fatalf("new login kid=%s want %s", res2.KeyVersion, kid2)
	}
	if _, err := svc.Introspect(res1.AccessToken); err != nil {
		t.Fatalf("old token must verify during transition: %v", err)
	}
	if _, err := svc.Introspect(res2.AccessToken); err != nil {
		t.Fatalf("new token must verify: %v", err)
	}
	t.Logf("[svc] basis=both coexisting keys verify: %s(verifying) + %s(active)", kid1, kid2)

	// 过渡期结束后退役旧版本：旧令牌被拒且原因是 key_not_active（非 unknown_key）。
	if err := svc.RetireKey(kid1); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Introspect(res1.AccessToken)
	reasonIs(t, err, idp.ReasonKeyNotActive)
	t.Logf("[svc] input=old token after retire => reason=key_not_active; basis=kid known but state=retired")

	// 未知 kid 与退役 kid 的结论必须可区分。
	ghost := mutateKid(res1.AccessToken, "ghost")
	_, err = svc.Introspect(ghost)
	reasonIs(t, err, idp.ReasonUnknownKey)
	t.Logf("[svc] input=token with kid=ghost => reason=unknown_key; basis=kid never registered")

	// 新密钥令牌继续有效；推进时钟使其过期得到 token_expired。
	if _, err := svc.Introspect(res2.AccessToken); err != nil {
		t.Fatalf("kid2 token after kid1 retire: %v", err)
	}
	clk.advance(2 * time.Minute)
	_, err = svc.Introspect(res2.AccessToken)
	reasonIs(t, err, idp.ReasonTokenExpired)
	t.Logf("[svc] input=kid2 token at now+2m (ttl=1m) => reason=token_expired")
}

func TestEndToEndRefreshReplayAndContainment(t *testing.T) {
	svc, clk := testService(t)
	login, err := svc.Login("carol", sessions.Grants{Roles: []string{"viewer"}, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	oldRefresh := login.RefreshToken

	// 刷新成功：新访问令牌嵌入相同授权边界，kid 为当前 active。
	r1, err := svc.Refresh(context.Background(), oldRefresh)
	if err != nil {
		t.Fatal(err)
	}
	env, err := svc.Introspect(r1.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[svc] input=refresh#1 => roles=%v scopes=%v kid=%s session=%s cred_ver=%d",
		env.Claims.Roles, env.Claims.Scopes, env.KeyVersion, env.Claims.SessionID, env.Claims.CredVersion)
	if env.Claims.SessionID != login.SessionID {
		t.Fatal("refresh must preserve same session (no fork)")
	}
	if env.Claims.CredVersion != 2 {
		t.Fatalf("cred version after first refresh = %d want 2", env.Claims.CredVersion)
	}
	// 权限不得超出最初授权：write 永远拿不到。
	out := svc.Authorizer().Authorize(context.Background(), r1.AccessToken,
		authz.Policy{NeedScopes: []string{"write"}})
	if out.Decision != authz.DecisionDenyForbidden {
		t.Fatalf("refreshed token escalated scopes: %s", out.Detail)
	}
	t.Logf("[svc] basis=refreshed token scopes=[read] vs need write => forbidden (no privilege escalation)")

	// 旧凭据重放：会话链路终止。
	_, err = svc.Refresh(context.Background(), oldRefresh)
	reasonIs(t, err, idp.ReasonSessionRevoked)
	t.Logf("[svc] input=replay old credential => reason=session_revoked; basis=one-time rotation violated")

	// 当前凭据也无法再用。
	clk.advance(time.Second)
	_, err = svc.Refresh(context.Background(), r1.RefreshToken)
	reasonIs(t, err, idp.ReasonSessionRevoked)
	sess, _ := svc.Sessions().Get(login.SessionID)
	t.Logf("[svc] input=refresh with current credential post-replay => session_revoked (store revoked=%v)", sess.Revoked)

	// 无法识别的凭据 -> invalid_grant（与重放区分）。
	_, err = svc.Refresh(context.Background(), "not-a-real-credential")
	reasonIs(t, err, idp.ReasonInvalidGrant)
}

func TestEndToEndConcurrentRefreshExactlyOne(t *testing.T) {
	svc, _ := testService(t)
	login, err := svc.Login("dave", sessions.Grants{Roles: []string{"user"}, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	const n = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	var success int
	sessionsSeen := map[string]struct{}{}
	reasons := map[idp.Reason]int{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := svc.Refresh(context.Background(), login.RefreshToken)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				success++
				sessionsSeen[res.SessionID] = struct{}{}
				return
			}
			var ie *idp.Error
			if errors.As(err, &ie) {
				reasons[ie.Reason]++
			}
		}()
	}
	close(start)
	wg.Wait()
	t.Logf("[svc] input=%d concurrent refresh(same credential) => success=%d reasons=%v distinct_sessions=%d",
		n, success, reasons, len(sessionsSeen))
	if success != 1 {
		t.Fatalf("success = %d want 1", success)
	}
	if len(sessionsSeen) != 1 {
		t.Fatalf("session fork: %d distinct sessions", len(sessionsSeen))
	}
	if reasons[idp.ReasonSessionRevoked] != n-1 {
		t.Fatalf("losing refreshes reason distribution = %v want all session_revoked", reasons)
	}
	// 链路已终止，任何后续刷新都拒绝。
	if _, err := svc.Refresh(context.Background(), login.RefreshToken); err == nil {
		t.Fatal("post-contention refresh must fail")
	}
}

func TestKeyRotationStatesObservable(t *testing.T) {
	svc, _ := testService(t)
	k1 := svc.Ring().Versions()[0]
	k2, _ := svc.RotateKey()
	if got := svc.Ring().StateOf(k1); got != keys.StateVerifying {
		t.Fatalf("old active state=%s want verifying", got)
	}
	if got := svc.Ring().StateOf(k2); got != keys.StateActive {
		t.Fatalf("new key state=%s want active", got)
	}
	t.Logf("[svc] basis=rotation states: %s=verifying, %s=active (multiple simultaneously-valid keys)", k1, k2)
}

// mutateKid 把令牌头部 kid 替换为给定版本（签名保持原样），用于触发 unknown_key。
func mutateKid(raw, kid string) string {
	return mutateKidHelper(raw, kid)
}
