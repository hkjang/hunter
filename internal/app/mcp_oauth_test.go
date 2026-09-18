package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// A fake Keycloak: real key pair, discovery and JWKS. Tokens are signed here
// with whatever claims a test needs, so every refusal is exercised with a
// genuinely signed JWT rather than a stub.
type mcpOAuthIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	issuer string
	jwks   atomic.Int32
}

func newMCPOAuthIdP(t *testing.T) *mcpOAuthIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &mcpOAuthIdP{key: key}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/corp/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": p.issuer, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			p.jwks.Add(1)
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "corp-1", Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	p.issuer = p.server.URL + "/realms/corp"
	t.Cleanup(p.server.Close)
	return p
}

// token signs an access token shaped like Keycloak 26's: aud=["account"],
// azp=<client>, typ=JWT. Overrides replace or (nil) delete claims; header
// overrides change typ/kid.
func (p *mcpOAuthIdP) token(t *testing.T, overrides map[string]any, header map[string]any) string {
	t.Helper()
	claims := map[string]any{"iss": p.issuer, "sub": "employee-1", "aud": []string{"account"}, "azp": "claude-mcp", "typ": "Bearer", "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "preferred_username": "employee", "scope": "openid profile"}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	options := (&jose.SignerOptions{}).WithHeader("kid", "corp-1").WithType("JWT")
	for k, v := range header {
		options = options.WithHeader(jose.HeaderKey(k), v)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, options)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(claims)
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mcpBearer(t *testing.T, s *httptest.Server, path, bearer string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	var reader io.Reader
	method := "GET"
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
		method = "POST"
	}
	r, err := http.NewRequest(method, s.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m, resp.Header
}

func mcpToolsList(body map[string]any) []string {
	names := []string{}
	result, _ := body["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	for _, tool := range tools {
		names = append(names, str(object(tool), "name"))
	}
	return names
}

// mcpOAuthSetup switches SSO on for the web (the prerequisite) and registers
// the employee the way the web sign-in would — the subject hash is what the
// callback stores, so the token lookup follows the same key.
func mcpOAuthSetup(t *testing.T) (*App, *httptest.Server, string, *mcpOAuthIdP) {
	t.Helper()
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	idp := newMCPOAuthIdP(t)
	mustRequest(t, s, "PUT", "/api/settings/general", map[string]any{"service_name": "hunter", "public_url": "https://hunter.example"}, admin, 200)
	mustRequest(t, s, "PUT", "/api/settings/oidc", map[string]any{"enabled": true, "auto_login": false, "issuer": idp.issuer, "client_id": "hunter-web", "client_secret": "web-secret", "default_role": "viewer"}, admin, 200)
	if _, err := a.DB.Exec(context.Background(), `INSERT INTO users(id,username,name,role,oidc_subject) VALUES($1,$2,$3,$4,$5)`, newID(), "employee-"+digest(idp.issuer+"|employee-1")[:10], "SSO 직원", "analyst", digest(idp.issuer+"|employee-1")); err != nil {
		t.Fatal(err)
	}
	return a, s, admin, idp
}

func TestMCPOAuthOffByDefault(t *testing.T) {
	_, s, admin, idp := mcpOAuthSetup(t)
	settings := mustRequest(t, s, "GET", "/api/settings", nil, admin, 200)
	oauth := object(object(settings["mcp"])["oauth"])
	if asBool(oauth["enabled"]) || asString(oauth["resource"]) != "" || len(stringSlice(oauth["scopes"])) != 3 {
		t.Fatalf("default mcp.oauth must be off with read scopes: %v", oauth)
	}
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		if status, _, _ := mcpBearer(t, s, path, "", nil); status != 404 {
			t.Fatalf("%s must be 404 while off, got %d", path, status)
		}
	}
	// No token: the challenge carries no metadata pointer while off.
	status, body, h := mcpBearer(t, s, "/mcp", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"})
	if status != 401 || strings.Contains(h.Get("WWW-Authenticate"), "resource_metadata") || asString(body["error"]) != "개인 API 키가 필요합니다" {
		t.Fatalf("off: %d %q %v", status, h.Get("WWW-Authenticate"), body)
	}
	// A perfectly good token is refused exactly like a bad key: 401, no tools.
	status, body, h = mcpBearer(t, s, "/mcp", idp.token(t, map[string]any{"aud": []string{"https://hunter.example/mcp"}}, nil), map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	if status != 401 || body["result"] != nil || strings.Contains(h.Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("token while off: %d %v", status, body)
	}
	if idp.jwks.Load() != 0 {
		t.Fatal("keys must not be fetched while off")
	}
	// A bearer that is neither key nor token stays the generic refusal.
	if status, body, _ := mcpBearer(t, s, "/mcp", "not-a-key", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); status != 401 || asString(body["error"]) != "로그인이 필요합니다" {
		t.Fatalf("garbage bearer: %d %v", status, body)
	}
	// Switching on without SSO configured for the web is refused at save time.
	mustRequest(t, s, "PUT", "/api/settings/oidc", map[string]any{"enabled": false, "auto_login": false, "issuer": "", "client_id": "", "default_role": "viewer"}, admin, 200)
	mustRequest(t, s, "PUT", "/api/settings/mcp", map[string]any{"oauth": map[string]any{"enabled": true}}, admin, 400)
}

func TestMCPOAuthSettingsValidation(t *testing.T) {
	for name, in := range map[string]map[string]any{
		"enabled not bool":    {"oauth": map[string]any{"enabled": "yes"}},
		"resource not url":    {"oauth": map[string]any{"enabled": false, "resource": "hunter.example/mcp"}},
		"resource with query": {"oauth": map[string]any{"enabled": false, "resource": "https://hunter.example/mcp?x=1"}},
		"unknown scope":       {"oauth": map[string]any{"enabled": false, "scopes": []string{"mcp:read"}}},
		"enabled no scopes":   {"oauth": map[string]any{"enabled": true, "scopes": []string{}}},
		"audience with space": {"oauth": map[string]any{"enabled": false, "audience": []string{"claude mcp"}}},
	} {
		if validateSettings("mcp", in) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	v := map[string]any{"oauth": map[string]any{"enabled": true, "resource": " https://hunter.example/mcp ", "audience": "claude-mcp cursor claude-mcp", "scopes": "services:read services:read findings:read"}}
	if err := validateSettings("mcp", v); err != nil {
		t.Fatal(err)
	}
	o := object(v["oauth"])
	if asString(o["resource"]) != "https://hunter.example/mcp" || strings.Join(stringSlice(o["audience"]), ",") != "claude-mcp,cursor" || strings.Join(stringSlice(o["scopes"]), ",") != "services:read,findings:read" {
		t.Fatalf("normalization: %v", o)
	}
	// A stored map from an older version keeps defaults for missing keys.
	if o := mcpOAuthValues(map[string]any{"oauth": map[string]any{"enabled": true}}); len(stringSlice(o["scopes"])) != 3 || asString(o["resource"]) != "" {
		t.Fatalf("defaults not layered: %v", o)
	}
}

func TestMCPOAuthTokens(t *testing.T) {
	a, s, admin, idp := mcpOAuthSetup(t)
	mustRequest(t, s, "PUT", "/api/settings/mcp", map[string]any{"oauth": map[string]any{"enabled": true, "audience": []string{}, "scopes": []string{"services:read", "findings:read", "admin:manage"}}}, admin, 200)
	resource := "https://hunter.example/mcp"

	// 1. Metadata: bare JSON, no auth, CORS open, both paths.
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		status, doc, h := mcpBearer(t, s, path, "", nil)
		if status != 200 || h.Get("Access-Control-Allow-Origin") != "*" || asString(doc["resource"]) != resource || strings.Join(stringSlice(doc["authorization_servers"]), ",") != idp.issuer || strings.Join(stringSlice(doc["bearer_methods_supported"]), ",") != "header" || strings.Join(stringSlice(doc["scopes_supported"]), ",") != "services:read,findings:read,admin:manage" || doc["error"] != nil {
			t.Fatalf("%s: %d %v", path, status, doc)
		}
	}
	// 2. The 401 points at the metadata on the MCP path only.
	status, _, h := mcpBearer(t, s, "/mcp", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"})
	if status != 401 || h.Get("WWW-Authenticate") != `Bearer realm="hunter", resource_metadata="https://hunter.example/.well-known/oauth-protected-resource/mcp"` {
		t.Fatalf("challenge: %d %q", status, h.Get("WWW-Authenticate"))
	}
	status, _, h = mcpBearer(t, s, "/api/auth/me", "", nil)
	if status != 401 || h.Get("WWW-Authenticate") != "" {
		t.Fatalf("rest 401 must not carry the challenge: %d %q", status, h.Get("WWW-Authenticate"))
	}

	call := func(bearer string) (int, map[string]any, http.Header) {
		return mcpBearer(t, s, "/mcp", bearer, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	}
	// 3. A token for this server (Audience mapper path) opens the tools the
	// role and the ceiling both allow — the analyst role has no admin:manage.
	status, body, _ := call(idp.token(t, map[string]any{"aud": []string{"account", resource}}, nil))
	if status != 200 || strings.Join(mcpToolsList(body), ",") != "hunter_list_services,hunter_list_components,hunter_finding_queue,hunter_list_findings" {
		t.Fatalf("mapper token: %d %v", status, body)
	}
	// The tool call is audited as an SSO subject of the existing account.
	mcpBearer(t, s, "/mcp", idp.token(t, map[string]any{"aud": []string{resource}}, nil), map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "hunter_list_services", "arguments": map[string]any{}}})
	var detail map[string]any
	var username string
	if err := a.DB.QueryRow(context.Background(), `SELECT username,detail FROM audit_logs WHERE action='mcp.hunter_list_services' ORDER BY created_at DESC LIMIT 1`).Scan(&username, &detail); err != nil || !strings.HasPrefix(username, "employee-") || asString(detail["auth"]) != "sso" {
		t.Fatalf("audit: %v %s %v", err, username, detail)
	}

	// 4. A token for another application: refused, and the message names what
	// was seen and what fixes it.
	status, body, h = call(idp.token(t, nil, nil))
	msg := asString(body["error"])
	if status != 401 || !strings.Contains(msg, "aud [account]") || !strings.Contains(msg, `azp "claude-mcp"`) || !strings.Contains(msg, `"claude-mcp"`) || !strings.Contains(msg, resource) || !strings.Contains(h.Get("WWW-Authenticate"), `error="invalid_token"`) || !strings.Contains(h.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("foreign audience: %d %q %q", status, msg, h.Get("WWW-Authenticate"))
	}
	// 5. The administrator lists the azp: the same token passes without a mapper.
	mustRequest(t, s, "PUT", "/api/settings/mcp", map[string]any{"oauth": map[string]any{"enabled": true, "audience": "claude-mcp", "scopes": []string{"services:read"}}}, admin, 200)
	if status, body, _ := call(idp.token(t, nil, nil)); status != 200 || strings.Join(mcpToolsList(body), ",") != "hunter_list_services,hunter_list_components" {
		t.Fatalf("azp allow-list: %d %v", status, body)
	}
	// The web sign-in client is accepted as an audience without any list entry.
	if status, _, _ := call(idp.token(t, map[string]any{"azp": "hunter-web"}, nil)); status != 200 {
		t.Fatalf("web client azp: %d", status)
	}

	// 6. Each strict check refuses on its own.
	other := newMCPOAuthIdP(t)
	for name, bearer := range map[string]string{
		"expired":       idp.token(t, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}, nil),
		"not yet valid": idp.token(t, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}, nil),
		"other issuer":  other.token(t, map[string]any{"aud": []string{resource}}, nil),
		"id token":      idp.token(t, map[string]any{"aud": []string{"hunter-web"}}, map[string]any{"typ": "ID"}),
		"cnf bound":     idp.token(t, map[string]any{"cnf": map[string]any{"jkt": "x"}}, nil),
		"no subject":    idp.token(t, map[string]any{"sub": nil}, nil),
		"unregistered":  idp.token(t, map[string]any{"sub": "stranger"}, nil),
		"garbage jwt":   "a.b.c",
	} {
		if status, body, h := call(bearer); status != 401 || !strings.Contains(h.Get("WWW-Authenticate"), `error="invalid_token"`) || asString(body["error"]) == "" {
			t.Fatalf("%s: %d %v %q", name, status, body, h.Get("WWW-Authenticate"))
		}
	}
	if status, body, _ := call(idp.token(t, map[string]any{"sub": "stranger"}, nil)); status != 401 || !strings.Contains(asString(body["error"]), "웹으로 한 번 로그인") {
		t.Fatalf("unregistered message: %d %v", status, body)
	}
	var count int
	_ = a.DB.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&count)
	if count != 2 {
		t.Fatalf("a token must never create an account, users=%d", count)
	}
	// HS256 with the public key material as secret: the header check refuses
	// it before any key fetch.
	fetched := idp.jwks.Load()
	hs, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("shared-secret-shared-secret-1234")}, (&jose.SignerOptions{}).WithType("JWT"))
	raw, _ := json.Marshal(map[string]any{"iss": idp.issuer, "sub": "employee-1", "azp": "claude-mcp", "exp": time.Now().Add(time.Minute).Unix()})
	signed, _ := hs.Sign(raw)
	hsToken, _ := signed.CompactSerialize()
	if status, body, _ := call(hsToken); status != 401 || !strings.Contains(asString(body["error"]), "알고리즘") || idp.jwks.Load() != fetched {
		t.Fatalf("hs256: %d %v jwks=%d/%d", status, body, idp.jwks.Load(), fetched)
	}

	// 7. Disabled account: refused, not revived.
	if _, err := a.DB.Exec(context.Background(), `UPDATE users SET disabled=true WHERE oidc_subject=$1`, digest(idp.issuer+"|employee-1")); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := call(idp.token(t, nil, nil)); status != 401 {
		t.Fatalf("disabled account accepted: %d", status)
	}
	_, _ = a.DB.Exec(context.Background(), `UPDATE users SET disabled=false WHERE oidc_subject=$1`, digest(idp.issuer+"|employee-1"))

	// 8. Empty intersection of ceiling and role is a refusal, never unlimited.
	mustRequest(t, s, "PUT", "/api/settings/mcp", map[string]any{"oauth": map[string]any{"enabled": true, "audience": "claude-mcp", "scopes": []string{"admin:manage"}}}, admin, 200)
	if status, body, _ := call(idp.token(t, nil, nil)); status != 401 || !strings.Contains(asString(body["error"]), "권한이 없습니다") {
		t.Fatalf("empty intersection: %d %v", status, body)
	}
	mustRequest(t, s, "PUT", "/api/settings/mcp", map[string]any{"oauth": map[string]any{"enabled": true, "audience": "claude-mcp", "scopes": []string{"services:read"}}}, admin, 200)

	// 9. A valid token opens nothing outside /mcp.
	good := idp.token(t, nil, nil)
	for _, path := range []string{"/api/auth/me", "/api/settings/public", "/api/services"} {
		if status, _, h := mcpBearer(t, s, path, good, nil); status != 401 || h.Get("WWW-Authenticate") != "" {
			t.Fatalf("token accepted on %s: %d", path, status)
		}
	}
	if status, _, _ := mcpBearer(t, s, "/api/graphql", good, map[string]any{"query": "{ __typename }"}); status != 401 {
		t.Fatalf("token accepted on graphql: %d", status)
	}

	// 10. Keys are untouched: the same key test surface still works with SSO on.
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "mcp-read", "scopes": []string{"services:read"}, "expires_days": 7}, admin, 201)
	if status, body, _ := call(asString(key["token"])); status != 200 || len(mcpToolsList(body)) != 2 {
		t.Fatalf("key with sso on: %d %v", status, body)
	}
	if status, _, h := mcpBearer(t, s, "/mcp", "hnt_unknown", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); status != 401 || !strings.Contains(h.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("bad key challenge: %d %q", status, h.Get("WWW-Authenticate"))
	}
	// Signed-in people learn on the key page that SSO is an option.
	public := mustRequest(t, s, "GET", "/api/settings/public", nil, admin, 200)
	if !asBool(public["mcp_sso_enabled"]) || asString(public["mcp_sso_url"]) != resource {
		t.Fatalf("public config: %v", public)
	}

	// 11. Switching off again closes the door immediately.
	mustRequest(t, s, "PUT", "/api/settings/mcp", map[string]any{"oauth": map[string]any{"enabled": false}}, admin, 200)
	if status, _, _ := call(good); status != 401 {
		t.Fatal("token accepted after switch-off")
	}
	if status, _, _ := mcpBearer(t, s, "/.well-known/oauth-protected-resource/mcp", "", nil); status != 404 {
		t.Fatal("metadata served after switch-off")
	}
}

func TestMCPOAuthCustomResource(t *testing.T) {
	_, s, admin, idp := mcpOAuthSetup(t)
	mustRequest(t, s, "PUT", "/api/settings/mcp", map[string]any{"oauth": map[string]any{"enabled": true, "resource": "https://mcp.hunter.example/mcp", "scopes": []string{"services:read"}}}, admin, 200)
	status, doc, _ := mcpBearer(t, s, "/.well-known/oauth-protected-resource/mcp", "", nil)
	if status != 200 || asString(doc["resource"]) != "https://mcp.hunter.example/mcp" {
		t.Fatalf("custom resource: %d %v", status, doc)
	}
	// The metadata pointer still lives under the public address this server answers at.
	if _, _, h := mcpBearer(t, s, "/mcp", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); !strings.Contains(h.Get("WWW-Authenticate"), `resource_metadata="https://hunter.example/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("challenge: %q", h.Get("WWW-Authenticate"))
	}
	if status, _, _ := mcpBearer(t, s, "/mcp", idp.token(t, map[string]any{"aud": []string{"https://mcp.hunter.example/mcp"}}, nil), map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); status != 200 {
		t.Fatalf("custom audience token: %d", status)
	}
	if status, _, _ := mcpBearer(t, s, "/mcp", idp.token(t, map[string]any{"aud": []string{"https://hunter.example/mcp"}}, nil), map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); status != 401 {
		t.Fatalf("derived resource must not be accepted once overridden: %d", status)
	}
}
