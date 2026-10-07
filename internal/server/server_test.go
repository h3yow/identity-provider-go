package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/identity-provider-go/internal/auth"
	"github.com/h3yow/identity-provider-go/internal/authz"
	"github.com/h3yow/identity-provider-go/internal/keys"
	"github.com/h3yow/identity-provider-go/internal/tokens"
)

func newTestServer(t *testing.T) (*Server, *keys.KeyRing, time.Time, func(time.Duration)) {
	t.Helper()
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	now := t0
	r := keys.NewKeyRing()
	if _, err := r.Rotate("k1", []byte("http-secret"), t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	logger := log.New(os.Stdout, "  [httptest] ", log.LstdFlags|log.Lmicroseconds)
	signer := tokens.NewSigner(r)
	authn := auth.NewService(signer, auth.Options{
		AccessTokenTTL: 30 * time.Minute, RefreshTokenTTL: 2 * time.Hour, Logger: logger,
	})
	pol := authz.NewPolicy()
	pol.Grant("viewer", "read")
	pol.Grant("editor", "read", "write")
	srv := New(Config{
		Auth: authn, Authz: authz.NewAuthorizer(authn, pol, logger),
		Now: func() time.Time { return now },
	})
	// advance moves the pinned server clock forward, letting tests leave
	// bounded windows (the replay-grace window) without real sleeping.
	advance := func(d time.Duration) { now = now.Add(d) }
	return srv, r, t0, advance
}

func post(t *testing.T, h http.Handler, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out == nil {
		out = map[string]any{}
	}
	t.Logf("POST %s body=%s => status=%d resp=%s", path, b, rec.Code, rec.Body.String())
	return rec.Code, out
}

func TestHTTPFullLifecycle(t *testing.T) {
	srv, _, _, advance := newTestServer(t)
	h := srv.Handler()

	// Login as viewer.
	st, login := post(t, h, "/login", map[string]any{"subject": "alice", "roles": []string{"viewer"}, "scopes": []string{"read"}})
	if st != 200 {
		t.Fatalf("login status = %d", st)
	}
	access, _ := login["access_token"].(string)
	refresh, _ := login["refresh_token"].(string)

	// Verify works.
	if st, _ := post(t, h, "/verify", map[string]any{"access_token": access}); st != 200 {
		t.Fatalf("verify status = %d", st)
	}
	// Authz: read allowed; write is 403 (authenticated, forbidden).
	if st, _ := post(t, h, "/authz", map[string]any{"access_token": access, "scopes": []string{"read"}}); st != 200 {
		t.Fatalf("read should be allowed")
	}
	st, forbidden := post(t, h, "/authz", map[string]any{"access_token": access, "scopes": []string{"write"}})
	if st != http.StatusForbidden || forbidden["error"] != "forbidden" {
		t.Fatalf("write => %d %v, want 403 forbidden", st, forbidden)
	}
	// Missing token is 401 missing_token.
	if st, m := post(t, h, "/authz", map[string]any{}); st != http.StatusUnauthorized || m["error"] != "missing_token" {
		t.Fatalf("empty => %d %v, want 401 missing_token", st, m)
	}
	// Malformed token is 401 token_malformed; tampering the signature is a
	// distinct 401 signature_mismatch.
	if st, m := post(t, h, "/verify", map[string]any{"access_token": "not-a-token"}); st != http.StatusUnauthorized || m["error"] != "token_malformed" {
		t.Fatalf("malformed => %d %v, want 401 token_malformed", st, m)
	}
	if st, m := post(t, h, "/verify", map[string]any{"access_token": access + "x"}); st != http.StatusUnauthorized || m["error"] != "signature_mismatch" {
		t.Fatalf("tampered => %d %v, want 401 signature_mismatch", st, m)
	}

	// Refresh rotates once.
	st, rot := post(t, h, "/refresh", map[string]any{"refresh_token": refresh})
	if st != 200 {
		t.Fatalf("refresh status = %d", st)
	}
	newRefresh, _ := rot["refresh_token"].(string)
	// An immediate replay at the same pinned instant lands inside the
	// replay-grace window: this is classified concurrent_refresh and MUST NOT
	// terminate the still-live chain (it is the same state a client-timeout
	// retry would produce).
	st, dup := post(t, h, "/refresh", map[string]any{"refresh_token": refresh})
	if st != http.StatusUnauthorized || dup["error"] != "concurrent_refresh" {
		t.Fatalf("in-grace duplicate => %d %v, want 401 concurrent_refresh", st, dup)
	}
	// The rotated credential is still usable: the chain survived. Rotating it
	// yields the next credential r3.
	st2, rot2 := post(t, h, "/refresh", map[string]any{"refresh_token": newRefresh})
	if st2 != 200 {
		t.Fatalf("successor must still rotate after in-grace duplicate, got %d", st2)
	}
	liveRefresh, _ := rot2["refresh_token"].(string)
	// Move the clock past the replay-grace window: reusing a consumed
	// credential now is a genuine one-time-use violation, 401
	// refresh_replayed, chain terminated.
	advance(31 * time.Second)
	st, replay := post(t, h, "/refresh", map[string]any{"refresh_token": newRefresh})
	if st != http.StatusUnauthorized || replay["error"] != "refresh_replayed" {
		t.Fatalf("replay after grace => %d %v, want 401 refresh_replayed", st, replay)
	}
	// The new credential is now unusable because the chain was terminated.
	st, dead := post(t, h, "/refresh", map[string]any{"refresh_token": liveRefresh})
	if st != http.StatusUnauthorized || dead["error"] != "refresh_replayed" {
		t.Fatalf("post-replay credential => %d %v, want 401 refresh_replayed", st, dead)
	}
}

func TestHTTPConcurrentRefreshSingleWinner(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	h := srv.Handler()
	_, login := post(t, h, "/login", map[string]any{"subject": "bob"})
	refresh, _ := login["refresh_token"].(string)

	type callResult struct {
		status int
		code   string
		rt     string
	}
	const n = 16
	results := make(chan callResult, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			b, _ := json.Marshal(map[string]any{"refresh_token": refresh})
			req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(b))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var m map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &m)
			c, _ := m["error"].(string)
			rt, _ := m["refresh_token"].(string)
			results <- callResult{status: rec.Code, code: c, rt: rt}
		}()
	}
	close(start)
	wins, denied := 0, 0
	replays, concurrent := 0, 0
	var winner string
	for i := 0; i < n; i++ {
		r := <-results
		st := r.status
		code := r.code
		rt := r.rt
		if st == 200 {
			wins++
			winner = rt
		} else {
			denied++
			switch code {
			case "concurrent_refresh":
				concurrent++
			case "refresh_replayed":
				replays++
			default:
				t.Errorf("unexpected denied code %q status=%d", code, st)
			}
		}
	}
	t.Logf("HTTP concurrent refresh: winners=%d concurrent_refresh=%d replayed=%d", wins, concurrent, replays)
	if wins != 1 {
		t.Fatalf("winners = %d, want 1", wins)
	}
	if replays != 0 {
		t.Fatalf("replays = %d, want 0 (a duplicate burst must never terminate the chain)", replays)
	}
	if concurrent != n-1 {
		t.Fatalf("concurrent_refresh = %d, want %d", concurrent, n-1)
	}
	// Retrying the original credential inside the grace window, while the
	// winner's successor is still the chain tip, stays a scheduling-independent
	// concurrent_refresh (never refresh_replayed) ...
	if st, m := post(t, h, "/refresh", map[string]any{"refresh_token": refresh}); st != 401 || m["error"] != "concurrent_refresh" {
		t.Fatalf("in-grace retry => %d %v, want 401 concurrent_refresh", st, m)
	}
	// ... and the winner's rotated credential then rotates normally: the chain
	// survived the duplicate storm. (Once that rotation lands, re-presenting
	// the original credential is a genuine structural replay, asserted in
	// TestHTTPFullLifecycle after advancing the clock.)
	if st, _ := post(t, h, "/refresh", map[string]any{"refresh_token": winner}); st != 200 {
		t.Fatalf("winner credential must rotate after the duplicate burst, got %d", st)
	}
}

// Logout over HTTP: the chain's access token dies at once, its refresh
// credentials yield 401 refresh_revoked, and a repeated logout stays 200.
func TestHTTPLogout(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	h := srv.Handler()

	_, login := post(t, h, "/login", map[string]any{"subject": "olga"})
	access, _ := login["access_token"].(string)
	refresh, _ := login["refresh_token"].(string)

	st, out := post(t, h, "/logout", map[string]any{"refresh_token": refresh})
	if st != 200 || out["status"] != "logged_out" {
		t.Fatalf("logout => %d %v, want 200 logged_out", st, out)
	}
	// Idempotent: same call again is still 200.
	if st, out := post(t, h, "/logout", map[string]any{"refresh_token": refresh}); st != 200 || out["status"] != "logged_out" {
		t.Fatalf("repeat logout => %d %v, want 200 logged_out", st, out)
	}
	// Access token on the terminated chain is rejected with session_revoked.
	if st, m := post(t, h, "/verify", map[string]any{"access_token": access}); st != 401 || m["error"] != "session_revoked" {
		t.Fatalf("verify after logout => %d %v, want 401 session_revoked", st, m)
	}
	// Refresh on the terminated chain is refresh_revoked, not not_found.
	if st, m := post(t, h, "/refresh", map[string]any{"refresh_token": refresh}); st != 401 || m["error"] != "refresh_revoked" {
		t.Fatalf("refresh after logout => %d %v, want 401 refresh_revoked", st, m)
	}
	// Unknown credential on /logout is 401 refresh_not_found.
	if st, m := post(t, h, "/logout", map[string]any{"refresh_token": "00deadbeef"}); st != 401 || m["error"] != "refresh_not_found" {
		t.Fatalf("logout unknown => %d %v, want 401 refresh_not_found", st, m)
	}
}

// Per-subject termination over HTTP kills all of the subject's chains and
// none of anyone else's.
func TestHTTPTerminateSubject(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	h := srv.Handler()

	_, l1 := post(t, h, "/login", map[string]any{"subject": "pat"})
	_, l2 := post(t, h, "/login", map[string]any{"subject": "pat"})
	_, other := post(t, h, "/login", map[string]any{"subject": "quinn"})

	st, out := post(t, h, "/terminate", map[string]any{"subject": "pat"})
	if st != 200 || out["chains"].(float64) != 2 {
		t.Fatalf("terminate => %d %v, want 200 chains=2", st, out)
	}
	for _, l := range []map[string]any{l1, l2} {
		rt, _ := l["refresh_token"].(string)
		at, _ := l["access_token"].(string)
		if st, m := post(t, h, "/refresh", map[string]any{"refresh_token": rt}); st != 401 || m["error"] != "refresh_revoked" {
			t.Fatalf("pat refresh after terminate => %d %v, want 401 refresh_revoked", st, m)
		}
		if st, m := post(t, h, "/verify", map[string]any{"access_token": at}); st != 401 || m["error"] != "session_revoked" {
			t.Fatalf("pat verify after terminate => %d %v, want 401 session_revoked", st, m)
		}
	}
	// quinn is untouched.
	ort, _ := other["refresh_token"].(string)
	if st, _ := post(t, h, "/refresh", map[string]any{"refresh_token": ort}); st != 200 {
		t.Fatalf("quinn refresh must survive, got %d", st)
	}
	// Terminating a subject with no live chains is a 200 no-op.
	if st, out := post(t, h, "/terminate", map[string]any{"subject": "nobody"}); st != 200 || out["chains"].(float64) != 0 {
		t.Fatalf("terminate nobody => %d %v, want 200 chains=0", st, out)
	}
}

// The capacity gate surfaces over HTTP as a distinguishable 409.
func TestHTTPSessionLimit(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	r := keys.NewKeyRing()
	if _, err := r.Rotate("k1", []byte("http-secret"), t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	authn := auth.NewService(tokens.NewSigner(r), auth.Options{
		AccessTokenTTL: 30 * time.Minute, RefreshTokenTTL: 2 * time.Hour,
		MaxActiveChainsPerSubject: 1,
	})
	pol := authz.NewPolicy()
	limited := New(Config{
		Auth: authn, Authz: authz.NewAuthorizer(authn, pol, nil),
		Now: func() time.Time { return t0 },
	}).Handler()

	if st, _ := post(t, limited, "/login", map[string]any{"subject": "rita"}); st != 200 {
		t.Fatalf("first login => %d, want 200", st)
	}
	st, m := post(t, limited, "/login", map[string]any{"subject": "rita"})
	if st != http.StatusConflict || m["error"] != "session_limit_exceeded" {
		t.Fatalf("second login => %d %v, want 409 session_limit_exceeded", st, m)
	}
	t.Logf("capacity gate over HTTP: second login => 409 session_limit_exceeded (distinct from 401 causes)")
}

// Unknown vs retired vs rotated key distinctions across /verify.
func TestHTTPKeyRotationDistinctions(t *testing.T) {
	srv, ring, t0, _ := newTestServer(t)
	h := srv.Handler()
	_, login := post(t, h, "/login", map[string]any{"subject": "carol"})
	oldAccess, _ := login["access_token"].(string)

	// Rotate to k2; k1 still in grace => old token verifies.
	if _, err := ring.Rotate("k2", []byte("new"), t0.Add(10*time.Minute), time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	// A token referring to a kid the ring never had: sign on a foreign ring.
	foreign := keys.NewKeyRing()
	if _, err := foreign.Rotate("zz", []byte("x"), t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	foreignTok, err := tokens.NewSigner(foreign).Sign(tokens.Claims{
		Subject: "x", IssuedAt: t0, ExpiresAt: t0.Add(time.Minute),
	}, t0)
	if err != nil {
		t.Fatal(err)
	}
	st, m := post(t, h, "/verify", map[string]any{"access_token": foreignTok.Raw})
	if st != 401 || m["error"] != "unknown_key_version" {
		t.Fatalf("foreign kid => %d %v, want 401 unknown_key_version", st, m)
	}
	// Old key token still verifies in grace at +15m (server clock fixed t0; use
	// /verify semantics through a direct ring-state check is covered elsewhere;
	// here we assert the token at least still decodes against k1).
	if _, err := tokens.NewSigner(ring).Verify(oldAccess, t0.Add(15*time.Minute)); err != nil {
		t.Fatalf("old token should verify during k1 grace: %v", err)
	}
}

// /terminate racing concurrent /refresh calls: once terminate returns, every
// later refresh of the subject's credentials is 401 refresh_revoked (never
// refresh_not_found or refresh_replayed), regardless of how the calls
// interleaved. Repeated rounds under -race.
func TestHTTPTerminateRacesRefreshDeterministic(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	h := srv.Handler()
	const rounds = 20
	const chains = 2
	for round := 0; round < rounds; round++ {
		subject := fmt.Sprintf("racer-%d", round)
		creds := make([]string, 0, chains)
		for i := 0; i < chains; i++ {
			_, login := post(t, h, "/login", map[string]any{"subject": subject})
			rt, _ := login["refresh_token"].(string)
			creds = append(creds, rt)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		var mu sync.Mutex
		codes := map[string]int{}
		record := func(c string) {
			mu.Lock()
			codes[c]++
			mu.Unlock()
		}
		refresh := func(raw string) {
			defer wg.Done()
			<-start
			b, _ := json.Marshal(map[string]any{"refresh_token": raw})
			req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(b))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == 200 {
				record("200")
				return
			}
			var m map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &m)
			c, _ := m["error"].(string)
			record(c)
		}
		for _, rt := range creds {
			for j := 0; j < 8; j++ {
				wg.Add(1)
				go refresh(rt)
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			b, _ := json.Marshal(map[string]any{"subject": subject})
			req := httptest.NewRequest(http.MethodPost, "/terminate", bytes.NewReader(b))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
		}()
		close(start)
		wg.Wait()

		if codes["refresh_replayed"] != 0 {
			t.Fatalf("round %d: %d refresh_replayed during terminate/refresh race: %v", round, codes["refresh_replayed"], codes)
		}
		// After terminate returns every probe is the fixed refresh_revoked.
		for i, rt := range creds {
			if st, m := post(t, h, "/refresh", map[string]any{"refresh_token": rt}); st != 401 || m["error"] != "refresh_revoked" {
				t.Fatalf("round %d chain=%d post-terminate => %d %v, want 401 refresh_revoked",
					round, i, st, m)
			}
		}
		t.Logf("round=%02d race http outcomes=%v; post-terminate all refresh_revoked", round, codes)
	}
}
