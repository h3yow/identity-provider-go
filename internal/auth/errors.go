// Package auth implements login, one-time-use refresh chains and
// authentication entry points.
package auth

import (
	"errors"
	"fmt"

	"github.com/h3yow/identity-provider-go/internal/tokens"
)

// ErrorCode classifies authentication failures so callers can explain them
// and map them to stable HTTP semantics.
type ErrorCode string

const (
	ErrInvalidCredentials ErrorCode = "invalid_credentials"
	ErrMissingToken       ErrorCode = "missing_token"
	ErrTokenMalformed     ErrorCode = "token_malformed"
	ErrTokenExpired       ErrorCode = "token_expired"
	ErrSignatureMismatch  ErrorCode = "signature_mismatch"
	ErrUnknownKeyVersion  ErrorCode = "unknown_key_version"
	ErrKeyRetired         ErrorCode = "key_retired"
	ErrRefreshNotFound    ErrorCode = "refresh_not_found"
	ErrRefreshReplayed    ErrorCode = "refresh_replayed"
	ErrRefreshExpired     ErrorCode = "refresh_expired"
	ErrConcurrentRefresh  ErrorCode = "concurrent_refresh"
	// ErrRefreshRevoked: the credential is known, but its chain was ended
	// voluntarily (logout / per-subject termination). Distinct from both
	// "never seen" (refresh_not_found) and "replay detected" (refresh_replayed).
	ErrRefreshRevoked ErrorCode = "refresh_revoked"
	// ErrSessionRevoked: an access token verified cryptographically, but its
	// session chain has already been terminated.
	ErrSessionRevoked ErrorCode = "session_revoked"
	// ErrTooManySessions: login refused because the subject already holds the
	// configured maximum of active chains.
	ErrTooManySessions ErrorCode = "session_limit_exceeded"
)

// Error is a classified authentication error.
type Error struct {
	Code   ErrorCode
	Reason string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Reason) }

func newError(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// AsError extracts *Error from err when present.
func AsError(err error) (*Error, bool) {
	var ae *Error
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// MapTokenError translates a token-layer failure into the equivalent
// authentication ErrorCode. The mapping is 1:1 so that the distinct causes
// (expiry vs. bad signature vs. unknown vs. retired key) survive every
// entry point.
func MapTokenError(err error) *Error {
	te, ok := tokens.AsError(err)
	if !ok {
		return newError(ErrTokenMalformed, "unclassified token error: %v", err)
	}
	switch te.Code {
	case tokens.ErrMalformed:
		return newError(ErrTokenMalformed, "%s", te.Reason)
	case tokens.ErrUnknownKeyVer:
		return newError(ErrUnknownKeyVersion, "%s", te.Reason)
	case tokens.ErrKeyRetired:
		return newError(ErrKeyRetired, "%s", te.Reason)
	case tokens.ErrSignatureBad:
		return newError(ErrSignatureMismatch, "%s", te.Reason)
	case tokens.ErrTokenExpired:
		return newError(ErrTokenExpired, "%s", te.Reason)
	case tokens.ErrNoSigningKey:
		return newError(ErrSignatureMismatch, "%s", te.Reason)
	default:
		return newError(ErrTokenMalformed, "%s", te.Reason)
	}
}
