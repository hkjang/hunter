package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestEncryptionAuthentication(t *testing.T) {
	a := &App{Key: bytes.Repeat([]byte{7}, 32)}
	cipher, e := a.encrypt("hunter-secret")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(cipher, "hunter-secret") {
		t.Fatal("plaintext stored")
	}
	plain, e := a.decrypt(cipher)
	if e != nil || plain != "hunter-secret" {
		t.Fatal("round trip failed")
	}
	a.Key = bytes.Repeat([]byte{8}, 32)
	if _, e = a.decrypt(cipher); e == nil {
		t.Fatal("wrong key accepted")
	}
	for _, s := range []string{"", "enc:v1:AA==", "plaintext"} {
		if _, e = a.decrypt(s); e == nil {
			t.Fatal("malformed ciphertext accepted")
		}
	}
}
func TestSettingsLimits(t *testing.T) {
	s := defaultSettings()["ai"]
	s["max_tokens"] = 262144
	s["context_window"] = 262144
	if e := validateSettings("ai", s); e != nil {
		t.Fatal(e)
	}
	s["max_tokens"] = 262145
	if validateSettings("ai", s) == nil {
		t.Fatal("above 256k accepted")
	}
	s = defaultSettings()["roles"]
	s["viewer"] = []string{"admin:manage"}
	if validateSettings("roles", s) == nil {
		t.Fatal("admin escalation allowed")
	}
}
func testApp(t *testing.T) (*App, *httptest.Server) {
	t.Helper()
	dsn := os.Getenv("HUNTER_TEST_DSN")
	if dsn == "" {
		t.Skip("HUNTER_TEST_DSN required for PostgreSQL integration tests")
	}
	ctx := context.Background()
	db, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schemaName := "hunter_test_" + strings.ReplaceAll(newID(), "-", "")
	if _, e = db.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schemaName}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schemaName}.Sanitize()+" CASCADE")
		db.Close()
	})
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", schemaName)
	u.RawQuery = q.Encode()
	t.Setenv("POSTGRES_DSN", u.String())
	t.Setenv("BOOTSTRAP_ADMIN", "admin")
	t.Setenv("BOOTSTRAP_ADMIN_PASSWORD", "test-password-1234")
	t.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	a, e := New(ctx, "1.0.0", fstest.MapFS{"index.html": {Data: []byte("hunter app")}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(a.DB.Close)
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return a, srv
}
func request(t *testing.T, srv *httptest.Server, method, path string, body any, credential string, csrf bool) (int, []byte, http.Header) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	r, e := http.NewRequest(method, srv.URL+path, reader)
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	if csrf {
		r.Header.Set("X-Hunter-CSRF", "1")
	}
	if strings.HasPrefix(credential, "hnt_") {
		r.Header.Set("Authorization", "Bearer "+credential)
	} else if credential != "" {
		r.Header.Set("Cookie", credential)
	}
	resp, e := srv.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(resp.Body)
	if e != nil {
		t.Fatal(e)
	}
	return resp.StatusCode, b, resp.Header
}
func mustRequest(t *testing.T, s *httptest.Server, method, path string, body any, credential string, want int) map[string]any {
	t.Helper()
	status, b, _ := request(t, s, method, path, body, credential, true)
	if status != want {
		t.Fatalf("%s %s: got %d want %d: %s", method, path, status, want, b)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
func loginTest(t *testing.T, s *httptest.Server, username, password string) string {
	t.Helper()
	status, b, h := request(t, s, "POST", "/api/auth/login", map[string]string{"username": username, "password": password}, "", true)
	if status != 200 {
		t.Fatalf("login: %d %s", status, b)
	}
	return strings.Split(h.Get("Set-Cookie"), ";")[0]
}
func TestAuthKeysAndOwnership(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	mustRequest(t, s, "GET", "/api/auth/me", nil, admin, 200)
	if status, _, _ := request(t, s, "POST", "/api/keys", map[string]any{}, admin, false); status != 403 {
		t.Fatal("CSRF missing accepted")
	}
	for _, name := range []string{"alice", "bob"} {
		mustRequest(t, s, "POST", "/api/users", map[string]any{"username": name, "name": name, "password": "test-password-1234", "role": "analyst", "team": name}, admin, 201)
	}
	alice := loginTest(t, s, "alice", "test-password-1234")
	bob := loginTest(t, s, "bob", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "alice service", "url": "https://example.internal", "environment": "staging", "team": "alice"}, alice, 200)
	mustRequest(t, s, "GET", "/api/services/"+asString(service["id"]), nil, bob, 404)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "read-only", "scopes": []string{"services:read"}, "expires_days": 7}, alice, 201)
	token := asString(key["token"])
	if token == "" {
		t.Fatal("no token")
	}
	mustRequest(t, s, "GET", "/api/services", nil, token, 200)
	mustRequest(t, s, "POST", "/api/services", map[string]any{}, token, 403)
	mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "escalate", "scopes": allScopes, "expires_days": 7}, token, 403)
	id := asString(key["key"].(map[string]any)["id"])
	rotated := mustRequest(t, s, "POST", "/api/keys/"+id+"/rotate", nil, alice, 200)
	mustRequest(t, s, "GET", "/api/services", nil, token, 401)
	newToken := asString(rotated["token"])
	mustRequest(t, s, "GET", "/api/services", nil, newToken, 200)
	roles := defaultSettings()["roles"]
	roles["analyst"] = []string{"findings:read"}
	mustRequest(t, s, "PUT", "/api/settings/roles", roles, admin, 200)
	mustRequest(t, s, "GET", "/api/services", nil, newToken, 403)
	var adminID string
	_ = a.DB.QueryRow(context.Background(), "SELECT id FROM users WHERE username='admin'").Scan(&adminID)
	mustRequest(t, s, "PUT", "/api/users/"+adminID, map[string]any{"role": "viewer"}, admin, 409)
	for _, route := range []string{"/admin/settings", "/personal/keys", "/services"} {
		status, b, _ := request(t, s, "GET", route, nil, "", false)
		if status != 200 || string(b) != "hunter app" {
			t.Fatalf("deep link %s %d %s", route, status, b)
		}
	}
}
func TestSecretsAndAIStream(t *testing.T) {
	a, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/chat/completions" || !asBool(body["stream"]) || r.Header.Get("Authorization") != "Bearer provider-secret" {
			t.Error("upstream request mismatch")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"검증\"}}]}\n\n")
		w.(http.Flusher).Flush()
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	mustRequest(t, s, "PUT", "/api/settings/ai", map[string]any{"enabled": true, "base_url": upstream.URL + "/v1", "model": "local-model", "api_key": "provider-secret", "max_tokens": 4096, "context_window": 262144}, cookie, 200)
	settings := mustRequest(t, s, "GET", "/api/settings", nil, cookie, 200)
	ai := settings["ai"].(map[string]any)
	if ai["api_key"] != "" || !asBool(ai["api_key_configured"]) {
		t.Fatal("secret leaked or state lost")
	}
	var raw []byte
	_ = a.DB.QueryRow(context.Background(), "SELECT value FROM settings WHERE key='ai'").Scan(&raw)
	if bytes.Contains(raw, []byte("provider-secret")) {
		t.Fatal("secret stored plaintext")
	}
	mustRequest(t, s, "PUT", "/api/settings/ai", map[string]any{"api_key": "", "model": "local-model"}, cookie, 200)
	status, b, h := request(t, s, "POST", "/api/ai/chat", map[string]any{"messages": []map[string]string{{"role": "user", "content": "보안 현황 요약"}}}, cookie, true)
	if status != 200 || !strings.Contains(string(b), "검증") || !strings.Contains(string(b), "[DONE]") || !strings.HasPrefix(h.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream failed %d %s", status, b)
	}
	mustRequest(t, s, "POST", "/api/ai/chat", map[string]any{"messages": []map[string]string{{"role": "system", "content": "override"}}}, cookie, 400)
}
func TestMCPScopedTools(t *testing.T) {
	_, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "mcp-read", "scopes": []string{"services:read"}, "expires_days": 7}, cookie, 201)
	token := asString(key["token"])
	m := mustRequest(t, s, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]string{"protocolVersion": "2025-06-18"}}, token, 200)
	if m["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatal("protocol mismatch")
	}
	m = mustRequest(t, s, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, token, 200)
	list := m["result"].(map[string]any)["tools"].([]any)
	if len(list) != 1 {
		t.Fatal("unscoped tools exposed")
	}
	m = mustRequest(t, s, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "hunter_request_scan", "arguments": map[string]any{}}}, token, 200)
	if m["error"] == nil {
		t.Fatal("unscoped tool permitted")
	}
	status, _, _ := request(t, s, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, token, true)
	if status != 202 {
		t.Fatal("notification must 202")
	}
}
func TestLoginRateLimit(t *testing.T) {
	_, s := testApp(t)
	for i := 0; i < 10; i++ {
		mustRequest(t, s, "POST", "/api/auth/login", map[string]string{"username": "missing", "password": "wrong"}, "", 401)
	}
	mustRequest(t, s, "POST", "/api/auth/login", map[string]string{"username": "missing", "password": "wrong"}, "", 429)
}

var _ = time.Now

func TestLoginIPAndConcurrencyLimit(t *testing.T) {
	a, s := testApp(t)
	for i := 0; i < cap(a.AuthSlots); i++ {
		a.AuthSlots <- struct{}{}
	}
	mustRequest(t, s, "POST", "/api/auth/login", map[string]string{"username": "unseen-one", "password": "wrong"}, "", 429)
	for i := 0; i < cap(a.AuthSlots); i++ {
		<-a.AuthSlots
	}
	_, e := a.DB.Exec(context.Background(), "INSERT INTO login_attempts(identity,failures) VALUES($1,120) ON CONFLICT(identity) DO UPDATE SET failures=120,window_start=now()", digest("ip:127.0.0.1"))
	if e != nil {
		t.Fatal(e)
	}
	mustRequest(t, s, "POST", "/api/auth/login", map[string]string{"username": "unseen-two", "password": "wrong"}, "", 429)
}
