// Package authz implements role- and scope-based authorization on top of the
// authentication service.
//
// Authorization answers are deliberately four-valued so callers never confuse
// "we don't know who you are" with "we know you, and you may not":
//
//   - Allow
//   - DenyNoCredentials:    no token was presented at all
//   - DenyUnauthenticated: a token was presented but could not be verified
//     (malformed, expired, bad/unknown/retired key)
//   - DenyForbidden:       identity is verified but lacks a required role or
//     scope
//
// Scope containment: refreshed tokens repeat exactly the roles/scopes of the
// original grant (the auth layer enforces inheritance), so a later request can
// never gain scope beyond the first authorization.
package authz

import (
	"strings"
	"time"

	"github.com/h3yow/identity-provider-go/internal/auth"
	"github.com/h3yow/identity-provider-go/internal/tokens"
)

// Decision is the explainable authorization outcome.
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionDenyNoCredentials
	DecisionDenyUnauthenticated
	DecisionDenyForbidden
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionDenyNoCredentials:
		return "deny_no_credentials"
	case DecisionDenyUnauthenticated:
		return "deny_unauthenticated"
	case DecisionDenyForbidden:
		return "deny_forbidden"
	default:
		return "unknown"
	}
}

// Authenticator verifies access tokens. *auth.Service satisfies it.
type Authenticator interface {
	Authenticate(accessToken string, now time.Time) (*tokens.Claims, error)
}

// Policy maps roles to the scopes they grant and may list per-role scope caps.
// A request is authorized when its token contains every required role and the
// union of granted scopes (plus the token's own scopes) covers every required
// scope.
type Policy struct {
	roleScopes map[string]map[string]bool
}

func NewPolicy() *Policy {
	return &Policy{roleScopes: make(map[string]map[string]bool)}
}

// Grant records that role grants the given scopes.
func (p *Policy) Grant(role string, scopes ...string) {
	set, ok := p.roleScopes[role]
	if !ok {
		set = make(map[string]bool)
		p.roleScopes[role] = set
	}
	for _, sc := range scopes {
		set[sc] = true
	}
}

func (p *Policy) grantedScopes(roles []string) map[string]bool {
	out := make(map[string]bool)
	for _, r := range roles {
		for sc := range p.roleScopes[r] {
			out[sc] = true
		}
	}
	return out
}

// Authorizer authenticates requests and applies a policy.
type Authorizer struct {
	authn Authenticator
	pol   *Policy
	log   auth.Logger
}

func NewAuthorizer(authn Authenticator, pol *Policy, log auth.Logger) *Authorizer {
	if pol == nil {
		pol = NewPolicy()
	}
	return &Authorizer{authn: authn, pol: pol, log: log}
}

// Request is one authorization query.
type Request struct {
	AccessToken    string
	RequiredRoles  []string
	RequiredScopes []string
	Now            time.Time
}

// Result is a decision plus enough detail to explain it.
type Result struct {
	Decision Decision
	Claims   *tokens.Claims
	Reason   string
	AuthCode auth.ErrorCode // populated when Decision == DenyUnauthenticated
}

// Authorize returns a stable four-way decision.
func (a *Authorizer) Authorize(req Request) Result {
	if req.AccessToken == "" {
		a.logf("authorize: no token presented => %s", DecisionDenyNoCredentials)
		return Result{Decision: DecisionDenyNoCredentials, Reason: "no access token presented"}
	}
	claims, err := a.authn.Authenticate(req.AccessToken, req.Now)
	if err != nil {
		code := auth.ErrTokenMalformed
		if ae, ok := auth.AsError(err); ok {
			code = ae.Code
		}
		a.logf("authorize: token=%s verification failed code=%s err=%v => %s",
			shortToken(req.AccessToken), code, err, DecisionDenyUnauthenticated)
		return Result{
			Decision: DecisionDenyUnauthenticated,
			Reason:   err.Error(), AuthCode: code,
		}
	}

	granted := a.pol.grantedScopes(claims.Roles)
	for _, sc := range claims.Scopes {
		granted[sc] = true
	}

	var missing []string
	for _, role := range req.RequiredRoles {
		if !contains(claims.Roles, role) {
			missing = append(missing, "role:"+role)
		}
	}
	for _, sc := range req.RequiredScopes {
		if !granted[sc] {
			missing = append(missing, "scope:"+sc)
		}
	}
	if len(missing) > 0 {
		a.logf("authorize: subject=%s roles=%v scopes=%v missing=[%s] => %s",
			claims.Subject, claims.Roles, claims.Scopes, strings.Join(missing, ","), DecisionDenyForbidden)
		return Result{
			Decision: DecisionDenyForbidden, Claims: claims,
			Reason: "authenticated but missing required entitlements: " + strings.Join(missing, ", "),
		}
	}
	a.logf("authorize: subject=%s roles=%v scopes=%v required_roles=%v required_scopes=%v => %s",
		claims.Subject, claims.Roles, claims.Scopes, req.RequiredRoles, req.RequiredScopes, DecisionAllow)
	return Result{Decision: DecisionAllow, Claims: claims, Reason: "all required roles and scopes satisfied"}
}

func (a *Authorizer) logf(format string, args ...any) {
	if a.log != nil {
		a.log.Printf(format, args...)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func shortToken(raw string) string {
	if len(raw) > 12 {
		return raw[:12] + "..."
	}
	return "(short)"
}
