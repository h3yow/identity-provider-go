package authz

import (
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/identity-provider-go/internal/auth"
	"github.com/h3yow/identity-provider-go/internal/keys"
	"github.com/h3yow/identity-provider-go/internal/tokens"
)

func build(t *testing.T) (*auth.Service, *Authorizer, time.Time, func(string, []string, []string, time.Time) string) {
	t.Helper()
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	r := keys.NewKeyRing()
	if _, err := r.Rotate("k1", []byte("z"), t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	signer := tokens.NewSigner(r)
	logger := log.New(os.Stdout, "  [authztest] ", log.LstdFlags|log.Lmicroseconds)
	authn := auth.NewService(signer, auth.Options{
		AccessTokenTTL: time.Hour, RefreshTokenTTL: 2 * time.Hour, Logger: logger,
	})
	pol := NewPolicy()
	pol.Grant("viewer", "read")
	pol.Grant("editor", "read", "write")
	pol.Grant("admin", "read", "write", "admin")
	az := NewAuthorizer(authn, pol, logger)

	mint := func(sub string, roles, scopes []string, now time.Time) string {
		res, err := authn.Login(sub, roles, scopes, now)
		if err != nil {
			t.Fatal(err)
		}
		return res.AccessToken.Raw
	}
	return authn, az, t0, mint
}

func TestFourWayDecision(t *testing.T) {
	_, az, t0, mint := build(t)
	viewer := mint("alice", []string{"viewer"}, nil, t0)
	editor := mint("bob", []string{"editor"}, nil, t0)

	cases := []struct {
		name string
		req  Request
		want Decision
	}{
		{"no credentials", Request{Now: t0}, DecisionDenyNoCredentials},
		{"malformed token", Request{AccessToken: "junk", Now: t0}, DecisionDenyUnauthenticated},
		{"expired token", Request{AccessToken: mint("old", []string{"admin"}, nil, t0), Now: t0.Add(2 * time.Hour)}, DecisionDenyUnauthenticated},
		{"viewer needs editor role", Request{AccessToken: viewer, RequiredRoles: []string{"editor"}, Now: t0.Add(time.Minute)}, DecisionDenyForbidden},
		{"viewer lacks write scope", Request{AccessToken: viewer, RequiredScopes: []string{"write"}, Now: t0.Add(time.Minute)}, DecisionDenyForbidden},
		{"viewer allowed read", Request{AccessToken: viewer, RequiredScopes: []string{"read"}, Now: t0.Add(time.Minute)}, DecisionAllow},
		{"editor allowed write", Request{AccessToken: editor, RequiredRoles: []string{"editor"}, RequiredScopes: []string{"write"}, Now: t0.Add(time.Minute)}, DecisionAllow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := az.Authorize(c.req)
			t.Logf("input token=%q required_roles=%v required_scopes=%v => decision=%s reason=%q authCode=%s",
				shortTok(c.req.AccessToken), c.req.RequiredRoles, c.req.RequiredScopes, got.Decision, got.Reason, got.AuthCode)
			if got.Decision != c.want {
				t.Fatalf("decision = %s, want %s", got.Decision, c.want)
			}
		})
	}
}

// Refreshed grants cannot exceed the first authorization. Login grants only
// read; after refresh the token still fails an admin check and passes read.
func TestRefreshedGrantStaysWithinOriginal(t *testing.T) {
	authn, az, t0, _ := build(t)
	res, err := authn.Login("carol", nil, []string{"read"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := authn.Refresh(res.RefreshToken, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	refreshed := rotated.AccessToken.Raw

	allow := az.Authorize(Request{AccessToken: refreshed, RequiredScopes: []string{"read"}, Now: t0.Add(2 * time.Minute)})
	if allow.Decision != DecisionAllow {
		t.Fatalf("refreshed read grant: %s %s", allow.Decision, allow.Reason)
	}
	deny := az.Authorize(Request{AccessToken: refreshed, RequiredScopes: []string{"admin"}, Now: t0.Add(2 * time.Minute)})
	if deny.Decision != DecisionDenyForbidden {
		t.Fatalf("refreshed token must not gain admin scope, got %s: %s", deny.Decision, deny.Reason)
	}
	t.Logf("refreshed claims roles=%v scopes=%v => read allowed, admin forbidden (no escalation)",
		deny.Claims.Roles, deny.Claims.Scopes)
}

// The same request evaluated by many goroutines must always yield the same
// decision: no torn reads, no timing-dependent allow/forbidden flips.
func TestConcurrentDecisionsStable(t *testing.T) {
	_, az, t0, mint := build(t)
	tok := mint("dave", []string{"viewer"}, nil, t0)
	req := Request{AccessToken: tok, RequiredScopes: []string{"write"}, Now: t0.Add(time.Minute)}
	base := az.Authorize(req).Decision

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			if got := az.Authorize(req).Decision; got != base {
				t.Errorf("unstable decision: got %s, want %s", got, base)
			}
		}()
	}
	close(start)
	wg.Wait()
	t.Logf("concurrent authorization x%d stable decision=%s", n, base)
}

func shortTok(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}
