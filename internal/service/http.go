package service

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	idp "github.com/h3yow/identity-provider-go/internal"
	"github.com/h3yow/identity-provider-go/internal/authz"
	"github.com/h3yow/identity-provider-go/internal/sessions"
)

// HTTPHandler 暴露本地认证服务的 HTTP 入口。
type HTTPHandler struct {
	svc *Service
}

// NewHTTPHandler 创建 HTTP 处理器。
func NewHTTPHandler(svc *Service) *HTTPHandler { return &HTTPHandler{svc: svc} }

type loginReq struct {
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
	Scopes  []string `json:"scopes"`
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type authorizeReq struct {
	AccessToken string   `json:"access_token"`
	NeedAnyRole []string `json:"need_any_role"`
	NeedScopes  []string `json:"need_scopes"`
}

type introspectReq struct {
	AccessToken string `json:"access_token"`
}

type errorResp struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Handler 装配全部路由。
func (h *HTTPHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/refresh", h.handleRefresh)
	mux.HandleFunc("/authorize", h.handleAuthorize)
	mux.HandleFunc("/introspect", h.handleIntrospect)
	mux.HandleFunc("/admin/keys/rotate", h.handleRotateKey)
	return mux
}

func (h *HTTPHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	log.Printf("login input: subject=%q roles=%v scopes=%v", req.Subject, req.Roles, req.Scopes)
	res, err := h.svc.Login(req.Subject, sessions.Grants{Roles: req.Roles, Scopes: req.Scopes})
	if err != nil {
		log.Printf("login denied: subject=%q reason=%v", req.Subject, err)
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	log.Printf("login ok: subject=%q session=%s key=%s", req.Subject, res.SessionID, res.KeyVersion)
	writeJSON(w, http.StatusOK, res)
}

func (h *HTTPHandler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req refreshReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	// 日志只打印凭据指纹，避免完整泄露。
	log.Printf("refresh input: credential_fingerprint=%s len=%d", fingerprint(req.RefreshToken), len(req.RefreshToken))
	res, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		var ie *idp.Error
		if errors.As(err, &ie) {
			status := http.StatusForbidden
			if ie.Reason == idp.ReasonInvalidGrant {
				status = http.StatusUnauthorized
			}
			log.Printf("refresh denied: fingerprint=%s reason=%s detail=%q", fingerprint(req.RefreshToken), ie.Reason, ie.Message)
			writeError(w, status, string(ie.Reason), ie.Message)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	log.Printf("refresh ok: session=%s new_credential_fingerprint=%s key=%s",
		res.SessionID, fingerprint(res.RefreshToken), res.KeyVersion)
	writeJSON(w, http.StatusOK, res)
}

func (h *HTTPHandler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req authorizeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	token := req.AccessToken
	if token == "" {
		// 也允许 Authorization: Bearer 头作为入口。
		token = bearer(r)
	}
	out := h.svc.Authorizer().Authorize(r.Context(), token, authz.Policy{
		NeedAnyRole: req.NeedAnyRole,
		NeedScopes:  req.NeedScopes,
	})
	logInput := token
	log.Printf("authorize input: token_fingerprint=%s need_any_role=%v need_scopes=%v",
		fingerprint(logInput), req.NeedAnyRole, req.NeedScopes)

	resp := map[string]any{
		"decision": out.Decision.String(),
		"reason":   out.Reason,
		"detail":   out.Detail,
	}
	if out.Envelope != nil {
		resp["subject"] = out.Envelope.Claims.Subject
		resp["key_version"] = string(out.Envelope.KeyVersion)
		resp["roles"] = out.Envelope.Claims.Roles
		resp["scopes"] = out.Envelope.Claims.Scopes
	}
	switch out.Decision {
	case authz.DecisionAllow:
		log.Printf("authorize allow: subject=%v key=%v basis=%q", resp["subject"], resp["key_version"], out.Detail)
		writeJSON(w, http.StatusOK, resp)
	case authz.DecisionDenyUnauthenticated:
		log.Printf("authorize deny(unauthenticated): reason=%s basis=%q", out.Reason, out.Detail)
		writeJSON(w, http.StatusUnauthorized, resp)
	default:
		log.Printf("authorize deny(forbidden): reason=%s basis=%q", out.Reason, out.Detail)
		writeJSON(w, http.StatusForbidden, resp)
	}
}

func (h *HTTPHandler) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req introspectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	env, err := h.svc.Introspect(req.AccessToken)
	if err != nil {
		var ie *idp.Error
		if errors.As(err, &ie) {
			log.Printf("introspect inactive: fingerprint=%s reason=%s detail=%q",
				fingerprint(req.AccessToken), ie.Reason, ie.Message)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"active": false,
				"reason": string(ie.Reason),
				"detail": ie.Message,
			})
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	log.Printf("introspect active: subject=%q key=%s session=%s cred_version=%d",
		env.Claims.Subject, env.KeyVersion, env.Claims.SessionID, env.Claims.CredVersion)
	writeJSON(w, http.StatusOK, map[string]any{
		"active":       true,
		"subject":      env.Claims.Subject,
		"roles":        env.Claims.Roles,
		"scopes":       env.Claims.Scopes,
		"key_version":  string(env.KeyVersion),
		"session_id":   env.Claims.SessionID,
		"cred_version": env.Claims.CredVersion,
		"expires_at":   env.ExpiresAt,
	})
}

func (h *HTTPHandler) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	v, err := h.svc.RotateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key_rotation_failed", err.Error())
		return
	}
	states := map[string]string{}
	for _, k := range h.svc.Ring().Versions() {
		states[string(k)] = h.svc.Ring().StateOf(k).String()
	}
	log.Printf("key rotated: new_active=%s ring_states=%v", v, states)
	writeJSON(w, http.StatusOK, map[string]any{
		"active":         string(v),
		"version_states": states,
	})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, errorResp{Error: code, ErrorDescription: desc})
}

func fingerprint(s string) string {
	if len(s) <= 8 {
		return "short"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
