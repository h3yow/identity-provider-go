// Package server exposes the identity service over a small HTTP API.
//
// Endpoints:
//
//	POST /login    {subject}                 -> access_token, refresh_token
//	POST /refresh  {refresh_token}           -> rotated access/refresh tokens
//	POST /verify   {access_token}            -> claims or classified 401
//	POST /authz    {access_token, roles?, scopes?} -> allow or 401/403
//
// HTTP status mapping is fixed:
//
//	missing/expired/bad token, unknown/retired key -> 401
//	verified but lacking role or scope             -> 403
//	replayed / concurrent refresh                  -> 401 with error code
//
// Response bodies always carry the machine-readable error code plus a
// human-readable reason so conclusions are explainable at every entry point.
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/h3yow/identity-provider-go/internal/auth"
	"github.com/h3yow/identity-provider-go/internal/authz"
)

// Clock allows tests to pin time.
type Clock func() time.Time

// Config wires the assembled dependencies.
type Config struct {
	Auth  *auth.Service
	Authz *authz.Authorizer
	Now   Clock
}

// Server is the HTTP adapter.
type Server struct {
	cfg Config
	mux *http.ServeMux
}

func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/refresh", s.handleRefresh)
	s.mux.HandleFunc("/verify", s.handleVerify)
	s.mux.HandleFunc("/authz", s.handleAuthz)
}

type apiError struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method_not_allowed", Reason: "use POST"})
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "bad_request", Reason: err.Error()})
		return false
	}
	return true
}

type loginReq struct {
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
	Scopes  []string `json:"scopes"`
}

type tokenResp struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	KeyID        string   `json:"key_id"`
	Subject      string   `json:"subject"`
	Roles        []string `json:"roles"`
	Scopes       []string `json:"scopes"`
	ExpiresAt    string   `json:"expires_at"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decode(w, r, &req) {
		return
	}
	if req.Subject == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "bad_request", Reason: "subject is required"})
		return
	}
	res, err := s.cfg.Auth.Login(req.Subject, req.Roles, req.Scopes, s.cfg.Now())
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResp{
		AccessToken: res.AccessToken.Raw, RefreshToken: res.RefreshToken,
		KeyID: res.AccessToken.KeyID, Subject: res.Session.Subject,
		Roles: res.Session.Roles, Scopes: res.Session.Scopes,
		ExpiresAt: res.AccessToken.Claims.ExpiresAt.Format(time.RFC3339),
	})
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if !decode(w, r, &req) {
		return
	}
	res, err := s.cfg.Auth.Refresh(req.RefreshToken, s.cfg.Now())
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResp{
		AccessToken: res.AccessToken.Raw, RefreshToken: res.RefreshToken,
		KeyID: res.AccessToken.KeyID, Subject: res.Session.Subject,
		Roles: res.Session.Roles, Scopes: res.Session.Scopes,
		ExpiresAt: res.AccessToken.Claims.ExpiresAt.Format(time.RFC3339),
	})
}

type verifyReq struct {
	AccessToken string `json:"access_token"`
}

type verifyResp struct {
	Subject   string   `json:"subject"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if !decode(w, r, &req) {
		return
	}
	claims, err := s.cfg.Auth.Authenticate(req.AccessToken, s.cfg.Now())
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyResp{
		Subject: claims.Subject, Roles: claims.Roles, Scopes: claims.Scopes,
		IssuedAt: claims.IssuedAt.Format(time.RFC3339), ExpiresAt: claims.ExpiresAt.Format(time.RFC3339),
	})
}

type authzReq struct {
	AccessToken string   `json:"access_token"`
	Roles       []string `json:"roles"`
	Scopes      []string `json:"scopes"`
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	var req authzReq
	if !decode(w, r, &req) {
		return
	}
	res := s.cfg.Authz.Authorize(authz.Request{
		AccessToken:    req.AccessToken,
		RequiredRoles:  req.Roles,
		RequiredScopes: req.Scopes,
		Now:            s.cfg.Now(),
	})
	switch res.Decision {
	case authz.DecisionAllow:
		writeJSON(w, http.StatusOK, map[string]any{
			"decision": "allow", "reason": res.Reason,
			"subject": res.Claims.Subject, "roles": res.Claims.Roles, "scopes": res.Claims.Scopes,
		})
	case authz.DecisionDenyNoCredentials:
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "missing_token", Reason: res.Reason})
	case authz.DecisionDenyUnauthenticated:
		writeJSON(w, http.StatusUnauthorized, apiError{Error: string(res.AuthCode), Reason: res.Reason})
	default:
		writeJSON(w, http.StatusForbidden, apiError{Error: "forbidden", Reason: res.Reason})
	}
}

// writeAuthError maps classified auth errors to stable HTTP status codes.
func writeAuthError(w http.ResponseWriter, err error) {
	ae, ok := auth.AsError(err)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal", Reason: err.Error()})
		return
	}
	status := http.StatusUnauthorized
	switch ae.Code {
	case auth.ErrInvalidCredentials,
		auth.ErrMissingToken,
		auth.ErrTokenMalformed,
		auth.ErrTokenExpired,
		auth.ErrSignatureMismatch,
		auth.ErrUnknownKeyVersion,
		auth.ErrKeyRetired,
		auth.ErrRefreshNotFound,
		auth.ErrRefreshReplayed,
		auth.ErrRefreshExpired,
		auth.ErrConcurrentRefresh:
		status = http.StatusUnauthorized
	}
	writeJSON(w, status, apiError{Error: string(ae.Code), Reason: ae.Reason})
}
