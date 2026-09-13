package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestTrackingValidation(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		origins      []string
		bad          bool
	}{
		{"javascript", `window.addEventListener('hunter:pageview',e=>void e.detail)`, nil, false},
		{"script tags", `<!-- internal analytics --><script src="https://stats.internal/a.js" data-site="hunter" defer></script><script>window.count = 1</script>`, []string{"https://stats.internal"}, false},
		{"unapproved source", `<script src="https://unapproved.internal/a.js"></script>`, nil, true},
		{"relative source", `<script src="/api/auth/me"></script>`, nil, true},
		{"event attribute", `<script onload="alert(1)"></script>`, nil, true},
		{"refresh", `<meta http-equiv="refresh" content="0;url=https://example.org">`, nil, true},
		{"noscript", `<noscript><img src="https://stats.internal/a"></noscript>`, nil, true},
		{"nested", `<script>window.a=1</script><iframe src="https://stats.internal"></iframe>`, nil, true},
		{"unterminated", `<script>window.a=1`, nil, true},
		{"wildcard", `void 0`, []string{"https://*.internal"}, true},
		{"csp injection", `void 0`, []string{"https://stats.internal; script-src *"}, true},
		{"same origin", `void 0`, []string{"https://hunter.internal:443/"}, true},
		{"userinfo", `void 0`, []string{"https://secret@stats.internal"}, true},
		{"path", `void 0`, []string{"https://stats.internal/collect"}, true},
		{"port", `void 0`, []string{"https://stats.internal:65536"}, true},
		{"oversize", strings.Repeat("a", 32769), nil, true},
		{"large origin", `void 0`, []string{"https://" + strings.Repeat("a", 2048) + ".internal"}, true},
		{"large label", `void 0`, []string{"https://" + strings.Repeat("a", 64) + ".internal"}, true},
		{"numeric IP alias", `void 0`, []string{"http://2130706433"}, true},
		{"hex IP alias", `void 0`, []string{"http://0x7f000001"}, true},
		{"short IP alias", `void 0`, []string{"http://127.1"}, true},
		{"same origin zero port", `void 0`, []string{"https://hunter.internal:00443"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := trackingConfig{Name: "방문", Script: tc.script, AllowedOrigins: tc.origins}
			_, err := validateTracking(&c, []string{"https://hunter.internal"})
			if (err != nil) != tc.bad {
				t.Fatalf("validation bad=%v err=%v", tc.bad, err)
			}
		})
	}
}
func TestTrackingAdminIsolationAndRevision(t *testing.T) {
	a, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	initial := mustRequest(t, s, "GET", "/api/admin/tracking", nil, cookie, 200)
	if initial["enabled"] != false || initial["revision"] != float64(0) {
		t.Fatal(initial)
	}
	mustRequest(t, s, "GET", "/api/admin/tracking", nil, "", 401)
	mustRequest(t, s, "GET", "/api/tracking/config", nil, "", 401)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "admin test", "scopes": []string{"admin:manage"}, "expires_days": 1}, cookie, 201)
	mustRequest(t, s, "GET", "/api/admin/tracking", nil, asString(key["token"]), 403)
	draft := map[string]any{"enabled": true, "name": "내부 통계", "script": `window.trackingSecretMarker="public-browser-code";`, "allowed_origins": []string{"https://stats.internal"}, "revision": 0}
	code, _, _ := request(t, s, "PUT", "/api/admin/tracking", draft, cookie, false)
	if code != 403 {
		t.Fatalf("csrf %d", code)
	}
	saved := mustRequest(t, s, "PUT", "/api/admin/tracking", draft, cookie, 200)
	if saved["revision"] != float64(1) {
		t.Fatal(saved)
	}
	mustRequest(t, s, "PUT", "/api/admin/tracking", draft, cookie, 409)
	var cipher string
	if err := a.DB.QueryRow(context.Background(), `SELECT config_encrypted FROM visitor_tracking_config`).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cipher, "trackingSecretMarker") {
		t.Fatal("plaintext script stored")
	}
	var audit string
	if err := a.DB.QueryRow(context.Background(), `SELECT coalesce(string_agg(detail::text,''),'') FROM audit_logs`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, "trackingSecretMarker") || strings.Contains(audit, "public-browser-code") {
		t.Fatal("script leaked to audit")
	}
	runtime := mustRequest(t, s, "GET", "/api/tracking/config", nil, cookie, 200)
	if _, ok := runtime["script"]; ok {
		t.Fatal("runtime config leaked script")
	}
	status, body, headers := request(t, s, "GET", asString(runtime["frame_url"]), nil, cookie, true)
	if status != 200 || !strings.Contains(string(body), "trackingSecretMarker") {
		t.Fatalf("frame %d", status)
	}
	csp := headers.Get("Content-Security-Policy")
	for _, part := range []string{"sandbox allow-scripts;", "frame-ancestors 'self'", "connect-src https://stats.internal;", "worker-src 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, part) {
			t.Fatalf("CSP missing %s", part)
		}
	}
	if strings.Contains(csp, "allow-same-origin") || strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "connect-src 'self'") {
		t.Fatal(csp)
	}
	if headers.Get("Referrer-Policy") != "no-referrer" || headers.Get("Cache-Control") != "no-store" {
		t.Fatal(headers)
	}
	saved["enabled"] = false
	mustRequest(t, s, "PUT", "/api/admin/tracking", saved, cookie, 200)
	mustRequest(t, s, "GET", asString(runtime["frame_url"]), nil, cookie, 404)
}
func TestTrackingPreviewScopeExpiryReplayAndEscaping(t *testing.T) {
	a, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "viewer", "name": "열람자", "password": "test-password-1234", "role": "viewer"}, cookie, 201)
	viewer := loginTest(t, s, "viewer", "test-password-1234")
	mustRequest(t, s, "GET", "/api/admin/tracking", nil, viewer, 403)
	draft := map[string]any{"enabled": false, "name": "초안", "script": `window.x="</script><script>parent.evil=1</script>";`, "allowed_origins": []string{}, "revision": 0}
	mustRequest(t, s, "POST", "/api/admin/tracking/test", draft, viewer, 403)
	preview := mustRequest(t, s, "POST", "/api/admin/tracking/test", draft, cookie, 200)
	path := asString(preview["preview_url"])
	mustRequest(t, s, "GET", path, nil, viewer, 403)
	status, body, _ := request(t, s, "GET", path, nil, cookie, true)
	if status != 200 || strings.Count(string(body), "</script>") != 1 || !strings.Contains(string(body), `\u003c/script\u003e`) {
		t.Fatalf("unsafe frame escaping %d", status)
	}
	mustRequest(t, s, "GET", path, nil, cookie, 404)
	before := mustRequest(t, s, "GET", "/api/admin/tracking", nil, cookie, 200)
	if before["revision"] != float64(0) || before["enabled"] != false || before["script"] != "" {
		t.Fatal("preview modified live settings")
	}
	preview = mustRequest(t, s, "POST", "/api/admin/tracking/test", draft, cookie, 200)
	if _, e := a.DB.Exec(context.Background(), `UPDATE visitor_tracking_previews SET expires_at=now()-interval '1 minute'`); e != nil {
		t.Fatal(e)
	}
	mustRequest(t, s, "GET", asString(preview["preview_url"]), nil, cookie, 404)
	// Current role is checked again when the preview is opened.
	preview = mustRequest(t, s, "POST", "/api/admin/tracking/test", draft, cookie, 200)
	if _, e := a.DB.Exec(context.Background(), `UPDATE users SET role='viewer' WHERE username='admin'`); e != nil {
		t.Fatal(e)
	}
	mustRequest(t, s, "GET", asString(preview["preview_url"]), nil, cookie, 403)
}
func TestTrackingFrameOriginAndCrossSiteMutation(t *testing.T) {
	_, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	draft := map[string]any{"enabled": true, "name": "통계", "script": "void 0", "allowed_origins": []string{s.URL}, "revision": 0}
	mustRequest(t, s, "PUT", "/api/admin/tracking", draft, cookie, 400)
	draft["allowed_origins"] = []string{}
	data, _ := json.Marshal(draft)
	r, _ := http.NewRequest("PUT", s.URL+"/api/admin/tracking", strings.NewReader(string(data)))
	r.Header.Set("Cookie", cookie)
	r.Header.Set("X-Hunter-CSRF", "1")
	r.Header.Set("Origin", "null")
	res, e := s.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("opaque frame mutation accepted")
	}
}

func TestTrackingOriginHeaderBudget(t *testing.T) {
	c := trackingConfig{Name: "헤더 예산", Script: "void 0"}
	for _, prefix := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		c.AllowedOrigins = append(c.AllowedOrigins, "https://"+prefix+strings.Repeat("x", 60)+"."+strings.Repeat("y", 61)+"."+strings.Repeat("z", 61)+".internal")
	}
	if _, e := validateTracking(&c, nil); e == nil {
		t.Fatal("excessive combined origin header accepted")
	}
}
