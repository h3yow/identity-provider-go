package tokens

import (
	"strings"
	"testing"
	"time"

	"github.com/h3yow/identity-provider-go/internal/keys"
)

type env struct {
	ring   *keys.KeyRing
	signer *Signer
	t0     time.Time
}

func setup(t *testing.T) *env {
	t.Helper()
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	r := keys.NewKeyRing()
	// v1: signs for one hour, verifies for three (2h grace).
	if _, err := r.Rotate("v1", []byte("secret-1"), t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	return &env{ring: r, signer: NewSigner(r), t0: t0}
}

func claims(e *env, ttl time.Duration) Claims {
	return Claims{
		Subject: "alice", Roles: []string{"editor"}, Scopes: []string{"read", "write"},
		IssuedAt: e.t0, ExpiresAt: e.t0.Add(ttl),
	}
}

func codeOf(err error) ErrorCode {
	if te, ok := AsError(err); ok {
		return te.Code
	}
	return "non-classified"
}

// Multiple valid keys coexist: after rotating to v2, tokens signed by v1 and
// v2 both verify within their windows.
func TestVerifyCoexistingVersions(t *testing.T) {
	e := setup(t)
	tok1, err := e.signer.Sign(claims(e, 30*time.Minute), e.t0)
	if err != nil {
		t.Fatalf("sign v1: %v", err)
	}
	if _, err := e.ring.Rotate("v2", []byte("secret-2"), e.t0.Add(20*time.Minute), time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	tok2, err := e.signer.Sign(Claims{
		Subject: "alice", Roles: []string{"editor"}, Scopes: []string{"read", "write"},
		IssuedAt: e.t0.Add(20 * time.Minute), ExpiresAt: e.t0.Add(50 * time.Minute),
	}, e.t0.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("sign v2: %v", err)
	}
	at := e.t0.Add(25 * time.Minute)
	for _, tok := range []*Token{tok1, tok2} {
		got, err := e.signer.Verify(tok.Raw, at)
		t.Logf("input kid=%s at=%s => err=%v subject=%s", tok.KeyID, at.Format(time.RFC3339), err, gotSub(got))
		if err != nil {
			t.Fatalf("token from %s must verify while both keys valid: %v", tok.KeyID, err)
		}
	}
}

// Old key in grace: v1 can no longer sign but a token it signed before the
// signing deadline (and which itself has not expired) still verifies.
func TestGraceWindowAcceptsOldKeyToken(t *testing.T) {
	e := setup(t)
	signAt := e.t0.Add(55 * time.Minute) // v1 still signable until 11:00
	tok, err := e.signer.Sign(Claims{
		Subject: "alice", IssuedAt: signAt, ExpiresAt: signAt.Add(3 * time.Hour),
	}, signAt)
	if err != nil {
		t.Fatal(err)
	}
	at := e.t0.Add(90 * time.Minute) // v1 grace (signing expired 11:00, retires 13:00)
	if _, err := e.signer.Verify(tok.Raw, at); err != nil {
		t.Fatalf("grace-period token rejected: %v", err)
	}
	t.Logf("input kid=v1 signed_at=10:55 at=%s => accepted during grace (signing expired, verification open until 13:00)",
		at.Format(time.RFC3339))

	// Once the key retires, the same still-unexpired token is rejected as
	// key_retired — a cause distinct from token_expired.
	_, err = e.signer.Verify(tok.Raw, e.t0.Add(181*time.Minute))
	if codeOf(err) != ErrKeyRetired {
		t.Fatalf("after retire want key_retired, got %v", err)
	}
	t.Logf("input same token at=13:01 => code=%s (token exp=13:55, but key verification window closed)", codeOf(err))
}

func TestFailureCausesAreDistinct(t *testing.T) {
	e := setup(t)
	tok, err := e.signer.Sign(claims(e, 30*time.Minute), e.t0)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		raw   string
		at    time.Time
		want  ErrorCode
		basis string
	}{
		{"malformed segments", "a.b", e.t0, ErrMalformed, "segment count != 3"},
		{"malformed base64", "###.###.###", e.t0, ErrMalformed, "base64url decode"},
		{"bad signature on known key", swapSig(t, tok.Raw, strings.Repeat("A", 43)), e.t0, ErrSignatureBad, "kid v1 known, HMAC comparison fails"},
		{"expired token", tok.Raw, e.t0.Add(31 * time.Minute), ErrTokenExpired, "now >= exp 10:30"},
	}
	// Unknown-kid case: retarget header kid by signing with a ring then verify on a fresh ring.
	other := keys.NewKeyRing()
	if _, err := other.Rotate("v9", []byte("other"), e.t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	unknownTok, err := NewSigner(other).Sign(claims(e, 30*time.Minute), e.t0)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, struct {
		name  string
		raw   string
		at    time.Time
		want  ErrorCode
		basis string
	}{"unknown key version", unknownTok.Raw, e.t0, ErrUnknownKeyVer, "kid v9 absent from ring"})

	// Retired key: v1 retires at 13:00; use a token with long ttl but signed at t0.
	longTok, err := e.signer.Sign(Claims{
		Subject: "alice", Roles: nil, Scopes: nil, IssuedAt: e.t0, ExpiresAt: e.t0.Add(4 * time.Hour),
	}, e.t0)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, struct {
		name  string
		raw   string
		at    time.Time
		want  ErrorCode
		basis string
	}{"retired key rejected before expiry", longTok.Raw, e.t0.Add(181 * time.Minute), ErrKeyRetired, "kid v1 RetireAt 13:00 < now"})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.signer.Verify(c.raw, c.at)
			got := codeOf(err)
			t.Logf("input=%s at=%s basis=%q => code=%s reason=%v",
				shortRaw(c.raw), c.at.Format(time.RFC3339), c.basis, got, err)
			if got != c.want {
				t.Fatalf("code = %s, want %s", got, c.want)
			}
		})
	}
}

// Tampering with the signature yields signature_mismatch, distinctly from expiry.
func TestSignatureTamper(t *testing.T) {
	e := setup(t)
	tok, err := e.signer.Sign(claims(e, 30*time.Minute), e.t0)
	if err != nil {
		t.Fatal(err)
	}
	tampered := mutateMiddle(t, tok.Raw)
	_, err = e.signer.Verify(tampered, e.t0.Add(5*time.Minute))
	t.Logf("input=kid(v1),signature-tampered at=10:05 => code=%s reason=%v", codeOf(err), err)
	if codeOf(err) != ErrSignatureBad {
		t.Fatalf("want signature_mismatch, got %v", err)
	}
}

func last(s string) byte { return s[len(s)-1] }
func flip(b byte) string {
	if b == 'A' {
		return "B"
	}
	return "A"
}

// mutateMiddle flips a character in the claims segment so the HMAC must fail
// while all segments remain valid base64url and the kid stays recognized.
func mutateMiddle(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	b := []byte(parts[1])
	for i := range b {
		switch b[i] {
		case 'A':
			b[i] = 'B'
		default:
			b[i] = 'A'
		}
		break
	}
	return parts[0] + "." + string(b) + "." + parts[2]
}
func gotSub(c *Claims) string {
	if c == nil {
		return ""
	}
	return c.Subject
}
func shortRaw(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}
func swapSig(t *testing.T, raw, sig string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	return parts[0] + "." + parts[1] + "." + sig
}
