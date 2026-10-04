// Package tokens implements compact signed access tokens and opaque refresh
// credentials.
//
// Wire format of an access token:
//
//	base64url(headerJSON).base64url(claimsJSON).base64url(HMAC-SHA256)
//
// Verification failures are classified into distinct codes so callers can
// tell malformed input, unknown key versions, retired keys, bad signatures
// and expiry apart.
package tokens

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/h3yow/identity-provider-go/internal/keys"
)

// ErrorCode classifies a token operation failure.
type ErrorCode string

const (
	ErrMalformed     ErrorCode = "token_malformed"
	ErrUnknownKeyVer ErrorCode = "unknown_key_version"
	ErrKeyRetired    ErrorCode = "key_retired"
	ErrSignatureBad  ErrorCode = "signature_mismatch"
	ErrTokenExpired  ErrorCode = "token_expired"
	ErrNoSigningKey  ErrorCode = "no_signing_key"
)

// Error is a classified token error.
type Error struct {
	Code   ErrorCode
	Reason string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Reason) }

func tokenError(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// Claims are the verifiable contents of an access token.
type Claims struct {
	Subject   string
	Roles     []string
	Scopes    []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// ChainID binds the token to the session chain that issued it, so the
	// caller can invalidate already-issued tokens when the chain ends.
	// Empty means the token is not bound to any chain.
	ChainID string
}

// Token is a signed token plus the key version that signed it.
type Token struct {
	Raw    string
	KeyID  string
	Claims Claims
}

// KeySource is the subset of the key ring the signer needs.
type KeySource interface {
	Active(now time.Time) (*keys.Version, error)
	Get(id string) (*keys.Version, bool)
	State(id string, now time.Time) (keys.State, error)
}

// Signer signs and verifies tokens against a KeySource.
type Signer struct {
	ks KeySource
}

func NewSigner(ks KeySource) *Signer {
	return &Signer{ks: ks}
}

type wireHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type wireClaims struct {
	Sub   string   `json:"sub"`
	Roles []string `json:"roles"`
	Scp   []string `json:"scp"`
	Iat   int64    `json:"iat"`
	Exp   int64    `json:"exp"`
	Cid   string   `json:"cid,omitempty"`
}

var b64 = base64.RawURLEncoding

// Sign produces a token signed with the ring's currently active key version.
func (s *Signer) Sign(c Claims, now time.Time) (*Token, error) {
	if !c.ExpiresAt.After(now) {
		return nil, tokenError(ErrTokenExpired, "refusing to sign token already expired at %s", c.ExpiresAt.Format(time.RFC3339))
	}
	v, err := s.ks.Active(now)
	if err != nil {
		return nil, tokenError(ErrNoSigningKey, "%v", err)
	}
	hdr := wireHeader{Alg: "HS256", Kid: v.ID}
	body := wireClaims{
		Sub: c.Subject, Roles: append([]string(nil), c.Roles...),
		Scp: append([]string(nil), c.Scopes...),
		Iat: c.IssuedAt.Unix(), Exp: c.ExpiresAt.Unix(),
		Cid: c.ChainID,
	}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return nil, tokenError(ErrMalformed, "marshal header: %v", err)
	}
	cb, err := json.Marshal(body)
	if err != nil {
		return nil, tokenError(ErrMalformed, "marshal claims: %v", err)
	}
	signingInput := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	mac := hmac.New(sha256.New, v.Secret)
	mac.Write([]byte(signingInput))
	sig := b64.EncodeToString(mac.Sum(nil))
	raw := signingInput + "." + sig
	return &Token{Raw: raw, KeyID: v.ID, Claims: c}, nil
}

// Verify validates raw at time now.
//
// Failure precedence is fixed and documented:
//  1. malformed wire format / encoding / contents
//  2. key version unknown to the ring
//  3. key version retired (verification window closed)
//  4. signature mismatch
//  5. token expiry
//
// Keys in the grace window still verify: an old key's tokens are accepted
// until either the key retires or the token itself expires.
func (s *Signer) Verify(raw string, now time.Time) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, tokenError(ErrMalformed, "expected 3 segments, got %d", len(parts))
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, tokenError(ErrMalformed, "header not base64url: %v", err)
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, tokenError(ErrMalformed, "claims not base64url: %v", err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, tokenError(ErrMalformed, "signature not base64url: %v", err)
	}
	var hdr wireHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, tokenError(ErrMalformed, "header not json: %v", err)
	}
	if hdr.Alg != "HS256" {
		return nil, tokenError(ErrMalformed, "unsupported alg %q", hdr.Alg)
	}
	if hdr.Kid == "" {
		return nil, tokenError(ErrMalformed, "missing kid")
	}
	v, ok := s.ks.Get(hdr.Kid)
	if !ok {
		return nil, tokenError(ErrUnknownKeyVer, "key version %q is not present in the ring", hdr.Kid)
	}
	st, err := s.ks.State(hdr.Kid, now)
	if err != nil {
		return nil, tokenError(ErrUnknownKeyVer, "%v", err)
	}
	if st == keys.StateRetired {
		return nil, tokenError(ErrKeyRetired, "key version %q retired at %s; token verification window closed",
			hdr.Kid, v.RetireAt.Format(time.RFC3339))
	}
	mac := hmac.New(sha256.New, v.Secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, tokenError(ErrSignatureBad, "HMAC mismatch for key version %q", hdr.Kid)
	}
	var body wireClaims
	if err := json.Unmarshal(cb, &body); err != nil {
		return nil, tokenError(ErrMalformed, "claims not json: %v", err)
	}
	claims := &Claims{
		Subject: body.Sub, Roles: body.Roles, Scopes: body.Scp,
		IssuedAt:  time.Unix(body.Iat, 0).UTC(),
		ExpiresAt: time.Unix(body.Exp, 0).UTC(),
		ChainID:   body.Cid,
	}
	if !now.Before(claims.ExpiresAt) {
		return nil, tokenError(ErrTokenExpired, "token for %q expired at %s",
			claims.Subject, claims.ExpiresAt.Format(time.RFC3339))
	}
	return claims, nil
}

// NewOpaqueID returns 256 bits of cryptographically random data, hex encoded.
// It is used for refresh credentials, which carry no meaning and only exist
// to be looked up server side.
func NewOpaqueID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("tokens: generate random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// AsError unwraps a classified token error, if err is one.
func AsError(err error) (*Error, bool) {
	var te *Error
	if errors.As(err, &te) {
		return te, true
	}
	return nil, false
}
