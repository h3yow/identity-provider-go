package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func do(t *testing.T, h http.Handler, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestHTTPEndToEndStatusSemantics(t *testing.T) {
	svc := New(Config{AccessTokenTTL: 0, RefreshTokenTTL: 0})
	h := NewHTTPHandler(svc).Handler()

	// 登录
	st, body := do(t, h, "/login", map[string]any{
		"subject": "alice", "roles": []string{"viewer"}, "scopes": []string{"read"},
	})
	if st != http.StatusOK {
		t.Fatalf("login status=%d body=%v", st, body)
	}
	access := body["AccessToken"].(string)
	refresh := body["RefreshToken"].(string)

	// 鉴权通过
	st, body = do(t, h, "/authorize", map[string]any{"access_token": access, "need_scopes": []string{"read"}})
	t.Logf("[http] authorize enough-scope => status=%d decision=%v", st, body["decision"])
	if st != http.StatusOK || body["decision"] != "allow" {
		t.Fatalf("allow: %d %v", st, body)
	}

	// 权限不足 -> 403 forbidden
	st, body = do(t, h, "/authorize", map[string]any{"access_token": access, "need_scopes": []string{"write"}})
	t.Logf("[http] authorize missing-scope => status=%d decision=%v reason=%v", st, body["decision"], body["reason"])
	if st != http.StatusForbidden || body["decision"] != "deny_forbidden" {
		t.Fatalf("forbidden: %d %v", st, body)
	}

	// 未认证 -> 401 unauthenticated（格式错误）
	st, body = do(t, h, "/authorize", map[string]any{"access_token": "garbage.token"})
	t.Logf("[http] authorize malformed => status=%d decision=%v reason=%v", st, body["decision"], body["reason"])
	if st != http.StatusUnauthorized || body["reason"] != "malformed_token" {
		t.Fatalf("malformed: %d %v", st, body)
	}
	// 未认证 -> 未知密钥版本同样 401，但原因码可区分
	st, body = do(t, h, "/authorize", map[string]any{"access_token": mutateKid(access, "ghost")})
	if st != http.StatusUnauthorized || body["reason"] != "unknown_key" {
		t.Fatalf("unknown key: %d %v", st, body)
	}
	t.Logf("[http] authorize kid=ghost => status=401 reason=unknown_key（与 malformed 区分）")

	// 刷新
	st, body = do(t, h, "/refresh", map[string]any{"refresh_token": refresh})
	if st != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", st, body)
	}
	newRefresh := body["RefreshToken"].(string)

	// 旧凭据重放 -> 403 session_revoked
	st, body = do(t, h, "/refresh", map[string]any{"refresh_token": refresh})
	t.Logf("[http] replay old credential => status=%d error=%v", st, body["error"])
	if st != http.StatusForbidden || body["error"] != "session_revoked" {
		t.Fatalf("replay: %d %v", st, body)
	}
	// 链路已终止：新凭据也被拒
	st, body = do(t, h, "/refresh", map[string]any{"refresh_token": newRefresh})
	if st != http.StatusForbidden {
		t.Fatalf("post-replay current cred status=%d", st)
	}

	// 无法识别的凭据 -> 401 invalid_grant（与重放的 403 区分）
	st, body = do(t, h, "/refresh", map[string]any{"refresh_token": "bogus"})
	t.Logf("[http] unknown credential => status=%d error=%v", st, body["error"])
	if st != http.StatusUnauthorized || body["error"] != "invalid_grant" {
		t.Fatalf("unknown grant: %d %v", st, body)
	}

	// introspect 有效/无效
	st, body = do(t, h, "/introspect", map[string]any{"access_token": access})
	if st != http.StatusOK || body["active"] != true {
		t.Fatalf("introspect active: %d %v", st, body)
	}
	st, body = do(t, h, "/introspect", map[string]any{"access_token": mutateKid(access, "ghost")})
	if st != http.StatusUnauthorized || body["reason"] != "unknown_key" {
		t.Fatalf("introspect unknown: %d %v", st, body)
	}

	// 密钥轮换接口
	st, body = do(t, h, "/admin/keys/rotate", map[string]any{})
	if st != http.StatusOK || body["active"] == "" {
		t.Fatalf("rotate key: %d %v", st, body)
	}
	t.Logf("[http] rotate key => new active=%v states=%v", body["active"], body["version_states"])
}
