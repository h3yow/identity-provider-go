package authz

import (
	"context"
	"sync"
	"testing"
	"time"

	idp "github.com/h3yow/identity-provider-go/internal"
	"github.com/h3yow/identity-provider-go/internal/keys"
	"github.com/h3yow/identity-provider-go/internal/tokens"
)

var base = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func newAuthz(t *testing.T) (*Authorizer, *tokens.Issuer, *keys.Ring) {
	t.Helper()
	ring := keys.NewRing()
	if err := ring.Add(keys.Key{Version: "k1", Secret: []byte("01234567890123456789012345678901")}); err != nil {
		t.Fatal(err)
	}
	iss := tokens.NewIssuer(ring, time.Minute, func() time.Time { return base })
	az := NewAuthorizer(tokens.NewVerifier(ring, func() time.Time { return base.Add(30 * time.Second) }))
	return az, iss, ring
}

func issue(t *testing.T, iss *tokens.Issuer, c tokens.Claims) string {
	t.Helper()
	raw, _, err := iss.Issue(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAllowForbiddenUnauthenticatedDistinction(t *testing.T) {
	az, iss, _ := newAuthz(t)
	adminToken := issue(t, iss, tokens.Claims{Subject: "alice", Roles: []string{"admin"}, Scopes: []string{"read", "write"}})
	viewerToken := issue(t, iss, tokens.Claims{Subject: "bob", Roles: []string{"viewer"}, Scopes: []string{"read"}})
	pol := Policy{NeedAnyRole: []string{"admin"}, NeedScopes: []string{"write"}}

	// allow
	out := az.Authorize(context.Background(), adminToken, pol)
	t.Logf("[authz] input=subject=alice roles=[admin] scopes=[read write] policy{role admin,scope write} => %s basis=%q",
		out.Decision, out.Detail)
	if out.Decision != DecisionAllow {
		t.Fatalf("alice: %s %s", out.Decision, out.Detail)
	}

	// forbidden：身份有效，但权限不足，并能看到具体缺口。
	out = az.Authorize(context.Background(), viewerToken, pol)
	t.Logf("[authz] input=subject=bob roles=[viewer] scopes=[read] => decision=%s reason=%s missing_roles=%v missing_scopes=%v basis=%q",
		out.Decision, out.Reason, out.MissingRoles, out.MissingScopes, out.Detail)
	if out.Decision != DecisionDenyForbidden || out.Reason != string(idp.ReasonForbidden) {
		t.Fatalf("bob decision=%s reason=%s", out.Decision, out.Reason)
	}
	if len(out.MissingRoles) != 1 || out.MissingRoles[0] != "admin" {
		t.Fatalf("missing roles = %v", out.MissingRoles)
	}
	if len(out.MissingScopes) != 1 || out.MissingScopes[0] != "write" {
		t.Fatalf("missing scopes = %v", out.MissingScopes)
	}

	// unauthenticated：无令牌。
	out = az.Authorize(context.Background(), "", pol)
	t.Logf("[authz] input=empty token => decision=%s reason=%s basis=%q", out.Decision, out.Reason, out.Detail)
	if out.Decision != DecisionDenyUnauthenticated || out.Reason != string(idp.ReasonUnauthenticated) {
		t.Fatalf("empty: %s/%s", out.Decision, out.Reason)
	}
}

func TestUnauthenticatedReasonsStayDistinguishable(t *testing.T) {
	ring := keys.NewRing()
	if err := ring.Add(keys.Key{Version: "k1", Secret: []byte("0123456789012345678901234678901")}); err != nil {
		t.Fatal(err)
	}
	// 用独立环构造各类令牌，再交给主鉴权器验证，覆盖 unauthenticated 的细分原因。
	mainRing := keys.NewRing()
	_ = mainRing.Add(keys.Key{Version: "k1", Secret: []byte("01234567890123456789012345678901")})
	_ = ring
	iss := tokens.NewIssuer(mainRing, time.Minute, func() time.Time { return base })
	good := issue(t, iss, tokens.Claims{Subject: "x"})

	// 过期
	azExp := NewAuthorizer(tokens.NewVerifier(mainRing, func() time.Time { return base.Add(2 * time.Hour) }))
	out := azExp.Authorize(context.Background(), good, Policy{})
	t.Logf("[authz] input=expired valid-signature token => decision=%s reason=%s basis=%q", out.Decision, out.Reason, out.Detail)
	if out.Decision != DecisionDenyUnauthenticated || out.Reason != string(idp.ReasonTokenExpired) {
		t.Fatalf("expired: %s/%s", out.Decision, out.Reason)
	}

	// 坏签名
	azNow := NewAuthorizer(tokens.NewVerifier(mainRing, func() time.Time { return base.Add(30 * time.Second) }))
	out = azNow.Authorize(context.Background(), good[:len(good)-1]+"A", Policy{})
	t.Logf("[authz] input=tampered token => decision=%s reason=%s", out.Decision, out.Reason)
	if out.Decision != DecisionDenyUnauthenticated || out.Reason != string(idp.ReasonBadSignature) {
		t.Fatalf("tampered: %s/%s", out.Decision, out.Reason)
	}

	// 未知密钥版本：轮换到 k2 并退役清理 k1 不容易，直接构造一个只含 k2 的环验证 k1 令牌。
	other := keys.NewRing()
	_ = other.Add(keys.Key{Version: "k2", Secret: []byte("01234567890123456789012345678901")})
	azOther := NewAuthorizer(tokens.NewVerifier(other, func() time.Time { return base.Add(30 * time.Second) }))
	out = azOther.Authorize(context.Background(), good, Policy{})
	t.Logf("[authz] input=token kid=k1 verified against ring{k2} => decision=%s reason=%s", out.Decision, out.Reason)
	if out.Decision != DecisionDenyUnauthenticated || out.Reason != string(idp.ReasonUnknownKey) {
		t.Fatalf("unknown kid: %s/%s", out.Decision, out.Reason)
	}
}

func TestScopeAndRolePolicySemantics(t *testing.T) {
	az, iss, _ := newAuthz(t)
	tok := issue(t, iss, tokens.Claims{Subject: "c", Roles: []string{"viewer"}, Scopes: []string{"read", "audit"}})

	// 角色为 OR：viewer 命中即放行。
	out := az.Authorize(context.Background(), tok, Policy{NeedAnyRole: []string{"admin", "viewer"}})
	if out.Decision != DecisionAllow {
		t.Fatalf("role OR semantics: %s %s", out.Decision, out.Detail)
	}
	// 作用域为 AND：缺 delete 即拒绝。
	out = az.Authorize(context.Background(), tok, Policy{NeedScopes: []string{"read", "delete"}})
	t.Logf("[authz] basis=scopes AND: have=[read audit] need=[read delete] => %s missing=%v",
		out.Decision, out.MissingScopes)
	if out.Decision != DecisionDenyForbidden || len(out.MissingScopes) != 1 || out.MissingScopes[0] != "delete" {
		t.Fatalf("scope AND semantics: %+v", out)
	}
	// 无角色要求时，任何已认证身份仅按作用域判定。
	out = az.Authorize(context.Background(), tok, Policy{NeedScopes: []string{"read"}})
	if out.Decision != DecisionAllow {
		t.Fatalf("no-role-required policy: %s", out.Detail)
	}
}

func TestConcurrentStableDecisions(t *testing.T) {
	az, iss, _ := newAuthz(t)
	tok := issue(t, iss, tokens.Claims{Subject: "alice", Roles: []string{"admin"}, Scopes: []string{"read"}})
	polAllow := Policy{NeedAnyRole: []string{"admin"}}
	polDeny := Policy{NeedScopes: []string{"write"}}

	const n = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	allowOK, forbiddenOK, unauthOK := make(chan bool, n), make(chan bool, n), make(chan bool, n)
	submit := func(token string, p Policy, ch chan bool) {
		defer wg.Done()
		<-start
		o := az.Authorize(context.Background(), token, p)
		switch ch {
		case allowOK:
			ch <- o.Decision == DecisionAllow
		case forbiddenOK:
			ch <- o.Decision == DecisionDenyForbidden
		default:
			ch <- o.Decision == DecisionDenyUnauthenticated
		}
	}
	for i := 0; i < n; i++ {
		wg.Add(3)
		go submit(tok, polAllow, allowOK)
		go submit(tok, polDeny, forbiddenOK)
		go submit("", polAllow, unauthOK)
	}
	close(start)
	wg.Wait()
	close(allowOK)
	close(forbiddenOK)
	close(unauthOK)
	for b := range allowOK {
		if !b {
			t.Fatal("allow decision unstable under concurrency")
		}
	}
	for b := range forbiddenOK {
		if !b {
			t.Fatal("forbidden decision unstable under concurrency")
		}
	}
	for b := range unauthOK {
		if !b {
			t.Fatal("unauthenticated decision unstable under concurrency")
		}
	}
	t.Logf("[authz] basis=%d concurrent requests x 3 inputs each => allow/forbidden/unauthenticated all stable", n)
}
