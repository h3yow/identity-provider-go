package tokens

import (
	"strings"
	"testing"
	"time"

	idp "github.com/h3yow/identity-provider-go/internal"
	"github.com/h3yow/identity-provider-go/internal/keys"
)

func fixedClock(t time.Time) Clock { return func() time.Time { return t } }

func TestIssueVerifyRoundTrip(t *testing.T) {
	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	ring := keys.NewRing()
	if err := ring.Add(keys.Key{Version: "k1", Secret: []byte("01234567890123456789012345678901")}); err != nil {
		t.Fatal(err)
	}
	iss := NewIssuer(ring, time.Minute, fixedClock(base))
	ver := NewVerifier(ring, fixedClock(base.Add(30*time.Second)))

	raw, kid, err := iss.Issue(Claims{Subject: "alice", Roles: []string{"admin"}, Scopes: []string{"read", "write"}, SessionID: "s1", CredVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if kid != "k1" {
		t.Fatalf("kid = %s", kid)
	}
	env, err := ver.Verify(raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("[tokens] input=valid token kid=k1 at now+30s => allow; basis=subject=%s roles=%v scopes=%v exp=%s",
		env.Claims.Subject, env.Claims.Roles, env.Claims.Scopes, env.ExpiresAt.Format(time.RFC3339))
	if env.Claims.Subject != "alice" || env.KeyVersion != "k1" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}

func TestVerifyFailureClassification(t *testing.T) {
	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	ring := keys.NewRing()
	if err := ring.Add(keys.Key{Version: "k1", Secret: []byte("01234567890123456789012345678901")}); err != nil {
		t.Fatal(err)
	}
	iss := NewIssuer(ring, time.Minute, fixedClock(base))
	raw, _, err := iss.Issue(Claims{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}

	type tc struct {
		name string
		now  time.Time
		// mutate 在验证前对环做动作，并可篡改 raw；返回输入令牌。
		token  string
		reason idp.Reason
		basis  string
	}
	cases := []tc{
		{"expired", base.Add(2 * time.Minute), raw, idp.ReasonTokenExpired,
			"now(+2m) > exp(+1m) => token_expired（在签名有效之后才判过期）"},
		{"malformed", base, "garbage.token", idp.ReasonMalformedToken,
			"段数/前缀不符 => malformed_token"},
		{"unknown_key", base, reSignKid(t, raw, "ghost", []byte("01234567890123456789012345678901")), idp.ReasonUnknownKey,
			"kid=ghost 从未登记 => unknown_key"},
		{"bad_signature", base, raw[:len(raw)-2] + flip(raw[len(raw)-2:]), idp.ReasonBadSignature,
			"密钥版本有效但 HMAC 不一致 => bad_signature"},
		{"wrong_secret_same_kid", base, reSignKid(t, raw, "k1", []byte("99999999999999999999999999999999")), idp.ReasonBadSignature,
			"用错误密钥重签同 kid => bad_signature"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ver := NewVerifier(ring, fixedClock(c.now))
			_, err := ver.Verify(c.token)
			if err == nil {
				t.Fatalf("%s: expected error", c.name)
			}
			ie := asIDP(t, err)
			t.Logf("[tokens] input=%s => reason=%s detail=%q | basis=%s", c.name, ie.Reason, ie.Message, c.basis)
			if ie.Reason != c.reason {
				t.Fatalf("%s reason = %s, want %s", c.name, ie.Reason, c.reason)
			}
		})
	}
}

func TestKeyRotationAcceptsBothVersions(t *testing.T) {
	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	ring := keys.NewRing()
	if err := ring.Add(keys.Key{Version: "k-old", Secret: []byte("old-secret-000000000000000000000")}); err != nil {
		t.Fatal(err)
	}
	issOld := NewIssuer(ring, time.Minute, fixedClock(base))
	oldToken, _, err := issOld.Issue(Claims{Subject: "bob", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	// 轮换：旧密钥进入 verifying，新令牌由新密钥签发。
	if err := ring.Rotate(keys.Key{Version: "k-new", Secret: []byte("new-secret-000000000000000000000")}); err != nil {
		t.Fatal(err)
	}
	issNew := NewIssuer(ring, time.Minute, fixedClock(base))
	newToken, newKid, err := issNew.Issue(Claims{Subject: "bob", Scopes: []string{"read"}})
	if err != nil || newKid != "k-new" {
		t.Fatalf("new issue: %v kid=%s", err, newKid)
	}
	ver := NewVerifier(ring, fixedClock(base.Add(10*time.Second)))
	for name, tok := range map[string]string{"old": oldToken, "new": newToken} {
		env, err := ver.Verify(tok)
		if err != nil {
			t.Fatalf("%s token after rotation: %v", name, err)
		}
		t.Logf("[tokens] input=%s token after rotation => accept; basis=kid=%s in {active,verifying}", name, env.KeyVersion)
	}

	// 过渡期结束、旧密钥退役：旧令牌被拒为 key_not_active，新令牌继续有效。
	if err := ring.Retire("k-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(oldToken); err == nil || asIDP(t, err).Reason != idp.ReasonKeyNotActive {
		t.Fatalf("retired old token err=%v want key_not_active", err)
	}
	t.Logf("[tokens] input=old token after retire => reason=key_not_active basis=kid=k-old state=retired（区别于 unknown_key）")
	if _, err := ver.Verify(newToken); err != nil {
		t.Fatalf("new token must still verify: %v", err)
	}
}

func reSignKid(t *testing.T, raw, newKid string, secret []byte) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		t.Fatalf("bad raw token")
	}
	parts[1] = b64.EncodeToString([]byte(newKid))
	signingInput := parts[1] + "." + parts[2]
	return signRaw(signingInput, secret, parts)
}

func flip(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
	}
	return string(b)
}

func asIDP(t *testing.T, err error) *idp.Error {
	t.Helper()
	ie, ok := err.(*idp.Error)
	if !ok {
		t.Fatalf("error %T is not *idp.Error: %v", err, err)
	}
	return ie
}
