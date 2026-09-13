package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type automaticOIDCTestProvider struct {
	issuerPath     string
	server         *httptest.Server
	discoveries    atomic.Int32
	authorizations atomic.Int32
	exchanges      atomic.Int32
	badNonce       atomic.Bool
	unavailable    atomic.Bool
	mu             sync.Mutex
	requests       map[string]url.Values
}

func newAutomaticOIDCTestProvider(t *testing.T, trailing ...bool) *automaticOIDCTestProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerPath := "/realm"
	if len(trailing) > 0 && trailing[0] {
		issuerPath += "/"
	}
	p := &automaticOIDCTestProvider{issuerPath: issuerPath, requests: map[string]url.Values{}}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realm/.well-known/openid-configuration":
			p.discoveries.Add(1)
			if p.unavailable.Load() {
				http.Error(w, "synthetic unavailable", 503)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"issuer": p.server.URL + p.issuerPath, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "synthetic", Algorithm: "RS256", Use: "sig"}}})
		case "/authorize":
			p.authorizations.Add(1)
			q := r.URL.Query()
			target, err := url.Parse(q.Get("redirect_uri"))
			if err != nil {
				t.Error(err)
				http.Error(w, "bad redirect", 400)
				return
			}
			values := url.Values{"state": {q.Get("state")}, "iss": {p.server.URL + p.issuerPath}}
			if c, e := r.Cookie("synthetic_idp_session"); e != nil || c.Value != "existing" {
				values.Set("error", "login_required")
			} else {
				code := newID()
				p.mu.Lock()
				p.requests[code] = q
				p.mu.Unlock()
				values.Set("code", code)
			}
			target.RawQuery = values.Encode()
			http.Redirect(w, r, target.String(), 303)
		case "/token":
			p.exchanges.Add(1)
			r.ParseForm()
			p.mu.Lock()
			q, ok := p.requests[r.Form.Get("code")]
			delete(p.requests, r.Form.Get("code"))
			p.mu.Unlock()
			hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || base64.RawURLEncoding.EncodeToString(hash[:]) != q.Get("code_challenge") {
				http.Error(w, "bad verifier", 400)
				return
			}
			nonce := q.Get("nonce")
			if p.badNonce.Load() {
				nonce = "different-nonce"
			}
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "synthetic"))
			claims, _ := json.Marshal(map[string]any{"iss": p.server.URL + p.issuerPath, "sub": "synthetic-employee", "aud": "hunter-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce, "name": "기존 SSO 사용자", "preferred_username": "existing"})
			signed, _ := signer.Sign(claims)
			jwt, _ := signed.CompactSerialize()
			json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access", "token_type": "Bearer", "id_token": jwt, "expires_in": 3600})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}
func automaticOIDCClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}
func automaticOIDCGet(t *testing.T, c *http.Client, target string) *http.Response {
	t.Helper()
	response, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response
}
func automaticOIDCSetup(t *testing.T, trailing ...bool) (*App, *httptest.Server, string, *automaticOIDCTestProvider) {
	t.Helper()
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	p := newAutomaticOIDCTestProvider(t, trailing...)
	mustRequest(t, s, "PUT", "/api/settings/general", map[string]any{"public_url": s.URL}, admin, 200)
	mustRequest(t, s, "PUT", "/api/settings/oidc", map[string]any{"enabled": true, "auto_login": true, "issuer": p.server.URL + p.issuerPath, "client_id": "hunter-client", "client_secret": "synthetic-client-secret", "default_role": "viewer"}, admin, 200)
	return a, s, admin, p
}
func automaticOIDCConfig(t *testing.T, c *http.Client, s *httptest.Server) map[string]any {
	t.Helper()
	r, e := c.Get(s.URL + "/api/auth/config")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	var data map[string]any
	if json.NewDecoder(r.Body).Decode(&data) != nil {
		t.Fatal("config JSON")
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("cookie-dependent config must not be cached")
	}
	return data
}
func automaticOIDCExistingIDP(c *http.Client, p *automaticOIDCTestProvider) {
	u, _ := url.Parse(p.server.URL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: "synthetic_idp_session", Value: "existing", Path: "/"}})
}
func automaticOIDCSession(c *http.Client, s *httptest.Server) string {
	u, _ := url.Parse(s.URL)
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == "hunter_session" {
			return cookie.Name + "=" + cookie.Value
		}
	}
	return ""
}

func TestOIDCAutomaticExistingSSODeepLinkAndHunterSessionReuse(t *testing.T) {
	a, s, _, p := automaticOIDCSetup(t)
	c := automaticOIDCClient(t)
	automaticOIDCExistingIDP(c, p)
	destination := "/findings?severity=high&q=" + url.QueryEscape("한국어 검색") + "#finding-section"
	start := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=auto&return_to="+url.QueryEscape(destination))
	if start.StatusCode != 302 {
		t.Fatalf("auto login status %d", start.StatusCode)
	}
	authURL, _ := url.Parse(start.Header.Get("Location"))
	q := authURL.Query()
	if q.Get("prompt") != "none" || q.Get("response_mode") != "query" || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatal("automatic authorization controls missing")
	}
	var saved string
	if err := a.DB.QueryRow(context.Background(), `SELECT context_encrypted FROM oidc_states WHERE state_hash=$1`, digest(q.Get("state"))).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(saved, "enc:v1:") || strings.Contains(saved, "findings") {
		t.Fatal("return context not encrypted")
	}
	authorize := automaticOIDCGet(t, c, authURL.String())
	callbackURL := authorize.Header.Get("Location")
	callback := automaticOIDCGet(t, c, callbackURL)
	if callback.StatusCode != 303 || callback.Header.Get("Location") != destination {
		t.Fatalf("deep link lost: %d %q", callback.StatusCode, callback.Header.Get("Location"))
	}
	session := automaticOIDCSession(c, s)
	if session == "" {
		t.Fatal("silent SSO session missing")
	}
	me := mustRequest(t, s, "GET", "/api/auth/me", nil, session, 200)
	if me["user"].(map[string]any)["role"] != "viewer" {
		t.Fatal("unexpected SSO role")
	}
	if p.authorizations.Load() != 1 || p.exchanges.Load() != 1 {
		t.Fatal("unexpected IdP calls")
	}
	count := p.discoveries.Load()
	p.unavailable.Store(true)
	existing := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=auto&return_to="+url.QueryEscape(destination))
	if existing.StatusCode != 303 || existing.Header.Get("Location") != destination || p.discoveries.Load() != count {
		t.Fatal("existing Hunter session unnecessarily consulted IdP")
	}
}

func TestOIDCAutomaticFailureFallbackIsBoundedAndStateValidated(t *testing.T) {
	a, s, _, p := automaticOIDCSetup(t)
	for _, code := range []string{"login_required", "interaction_required", "consent_required", "account_selection_required", "access_denied"} {
		t.Run(code, func(t *testing.T) {
			c := automaticOIDCClient(t)
			start := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=auto&return_to="+url.QueryEscape("/agents/abc?tab=tasks#plan"))
			authURL, _ := url.Parse(start.Header.Get("Location"))
			state := authURL.Query().Get("state")
			callback := s.URL + "/api/auth/oidc/callback?state=" + url.QueryEscape(state) + "&error=" + code + "&error_description=" + url.QueryEscape("untrusted-secret-description")
			before := p.exchanges.Load()
			r := automaticOIDCGet(t, c, callback)
			location, _ := url.Parse(r.Header.Get("Location"))
			expected := "oidc_interaction_required"
			if code == "login_required" {
				expected = "oidc_login_required"
			}
			if code == "access_denied" {
				expected = "oidc_authentication"
			}
			if r.StatusCode != 303 || location.Path != "/login" || location.Query().Get("sso") != "skip" || location.Query().Get("error") != expected || location.Query().Get("return_to") != "/agents/abc?tab=tasks#plan" || strings.Contains(r.Header.Get("Location"), "untrusted") {
				t.Fatalf("bad bounded fallback: %s", r.Header.Get("Location"))
			}
			if p.exchanges.Load() != before || automaticOIDCSession(c, s) != "" {
				t.Fatal("error callback exchanged code or created session")
			}
			var states int
			a.DB.QueryRow(context.Background(), `SELECT count(*) FROM oidc_states WHERE state_hash=$1`, digest(state)).Scan(&states)
			if states != 0 {
				t.Fatal("error callback state was not consumed")
			}
			if automaticOIDCConfig(t, c, s)["oidc_auto_login_allowed"] != false {
				t.Fatal("automatic redirect not suppressed")
			}
			calls := p.discoveries.Load()
			retry := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=auto")
			if retry.StatusCode != 303 || p.discoveries.Load() != calls {
				t.Fatal("automatic retry loop")
			}
			replay := automaticOIDCGet(t, c, callback)
			if !strings.Contains(replay.Header.Get("Location"), "error=oidc_authentication") {
				t.Fatal("error state replay accepted")
			}
		})
	}
	c := automaticOIDCClient(t)
	start := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=auto")
	u, _ := url.Parse(start.Header.Get("Location"))
	state := u.Query().Get("state")
	wrong := automaticOIDCClient(t)
	bad := automaticOIDCGet(t, wrong, s.URL+"/api/auth/oidc/callback?state="+url.QueryEscape(state)+"&error=login_required")
	if !strings.Contains(bad.Header.Get("Location"), "oidc_authentication") || automaticOIDCConfig(t, wrong, s)["oidc_auto_login_allowed"] != false {
		t.Fatal("unbound error callback accepted or allowed loop")
	}
	var states int
	a.DB.QueryRow(context.Background(), `SELECT count(*) FROM oidc_states WHERE state_hash=$1`, digest(state)).Scan(&states)
	if states != 1 {
		t.Fatal("unbound browser consumed another browser's state")
	}
}

func TestOIDCLogoutLocalBypassAndUnavailableProviderRecovery(t *testing.T) {
	_, s, admin, p := automaticOIDCSetup(t)
	c := automaticOIDCClient(t)
	u, _ := url.Parse(s.URL)
	parts := strings.SplitN(admin, "=", 2)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: parts[0], Value: parts[1], Path: "/"}})
	r, _ := http.NewRequest("POST", s.URL+"/api/auth/logout", nil)
	r.Header.Set("X-Hunter-CSRF", "1")
	response, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	if automaticOIDCConfig(t, c, s)["oidc_auto_login_allowed"] != false {
		t.Fatal("logout permits automatic SSO")
	}
	calls := p.discoveries.Load()
	suppressed := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=auto")
	if suppressed.StatusCode != 303 || p.discoveries.Load() != calls {
		t.Fatal("logout immediately reauthenticated")
	}
	bypass := automaticOIDCGet(t, automaticOIDCClient(t), s.URL+"/api/auth/oidc/login?mode=auto&local=1&return_to=%2Fservices")
	if bypass.StatusCode != 303 || p.discoveries.Load() != calls {
		t.Fatal("explicit local bypass consulted IdP")
	}
	manual := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=interactive")
	manualURL, _ := url.Parse(manual.Header.Get("Location"))
	if manual.StatusCode != 302 || manualURL.Query().Get("prompt") != "" {
		t.Fatal("explicit SSO cannot override logout")
	}
	p.unavailable.Store(true)
	fresh := automaticOIDCClient(t)
	failed := automaticOIDCGet(t, fresh, s.URL+"/api/auth/oidc/login?mode=auto&return_to=%2Fservices")
	if failed.StatusCode != 303 || !strings.Contains(failed.Header.Get("Location"), "oidc_configuration") {
		t.Fatal("provider outage did not return local fallback")
	}
	request, _ := http.NewRequest("POST", s.URL+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"test-password-1234"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hunter-CSRF", "1")
	local, e := fresh.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	local.Body.Close()
	if local.StatusCode != 200 || automaticOIDCSession(fresh, s) == "" {
		t.Fatal("IdP outage blocked local administrator")
	}
	if automaticOIDCConfig(t, fresh, s)["oidc_auto_login_allowed"] != true {
		t.Fatal("local success did not clear suppression")
	}
}

func TestOIDCCallbackNonceExpiryAndSettingsChangeRejected(t *testing.T) {
	a, s, admin, p := automaticOIDCSetup(t)
	for _, failure := range []string{"nonce", "expired", "settings", "issuer", "auto_disabled"} {
		t.Run(failure, func(t *testing.T) {
			c := automaticOIDCClient(t)
			automaticOIDCExistingIDP(c, p)
			start := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=auto")
			auth, _ := url.Parse(start.Header.Get("Location"))
			authorize := automaticOIDCGet(t, c, auth.String())
			callback := authorize.Header.Get("Location")
			switch failure {
			case "nonce":
				p.badNonce.Store(true)
				defer p.badNonce.Store(false)
			case "expired":
				a.DB.Exec(context.Background(), `UPDATE oidc_states SET expires_at=now()-interval '1 second' WHERE state_hash=$1`, digest(auth.Query().Get("state")))
			case "settings":
				mustRequest(t, s, "PUT", "/api/settings/oidc", map[string]any{"default_role": "analyst"}, admin, 200)
			case "auto_disabled":
				mustRequest(t, s, "PUT", "/api/settings/oidc", map[string]any{"auto_login": false}, admin, 200)
			case "issuer":
				u, _ := url.Parse(callback)
				q := u.Query()
				q.Set("iss", "https://wrong.example.invalid")
				u.RawQuery = q.Encode()
				callback = u.String()
			}
			final := automaticOIDCGet(t, c, callback)
			if !strings.Contains(final.Header.Get("Location"), "error=oidc_authentication") || automaticOIDCSession(c, s) != "" {
				t.Fatalf("%s was accepted", failure)
			}
		})
	}
}

func TestOIDCReturnToRejectsExternalAndAuthLoops(t *testing.T) {
	for _, value := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example/", "/%2f%2fevil.example/", "/%5cevil.example/", "/api/auth/oidc/login", "/login?return_to=/login", "/x/../api/auth/logout", "/%2e%2e/api", "/findings\r\nLocation: evil", "/" + strings.Repeat("x", 4096)} {
		if got := oidcReturnTo(value); got != "/dashboard" {
			t.Errorf("accepted unsafe return %q => %q", value, got)
		}
	}
	for _, value := range []string{"/findings?status=confirmed&page=3#row", "/agents/abc", "/services?q=%ED%95%9C%EA%B8%80", "/"} {
		if got := oidcReturnTo(value); got != value {
			t.Errorf("lost safe return %q => %q", value, got)
		}
	}
}

// Discovery and the JWT issuer are exact identifiers, including a final slash.
// Providers such as ReSSO may publish that literal value without normalization.
func TestOIDCExactTrailingSlashIssuer(t *testing.T) {
	_, server, _, provider := automaticOIDCSetup(t, true)
	client := automaticOIDCClient(t)
	automaticOIDCExistingIDP(client, provider)
	start := automaticOIDCGet(t, client, server.URL+"/api/auth/oidc/login?mode=auto&return_to=%2Fservices%3Fpage%3D2")
	if start.StatusCode != 302 {
		t.Fatalf("literal issuer discovery failed: %d", start.StatusCode)
	}
	authorization, _ := url.Parse(start.Header.Get("Location"))
	if authorization.Query().Get("prompt") != "none" {
		t.Fatal("automatic prompt missing")
	}
	authorized := automaticOIDCGet(t, client, authorization.String())
	callbackURL, _ := url.Parse(authorized.Header.Get("Location"))
	if callbackURL.Query().Get("iss") != provider.server.URL+"/realm/" {
		t.Fatal("fixture did not publish literal issuer")
	}
	callback := automaticOIDCGet(t, client, callbackURL.String())
	if callback.StatusCode != 303 || callback.Header.Get("Location") != "/services?page=2" || automaticOIDCSession(client, server) == "" {
		t.Fatal("matching discovery/JWT/callback trailing-slash issuer was rejected")
	}
	// A callback that removes the slash identifies a different issuer and must
	// fail before the code is exchanged; no permissive normalized fallback.
	other := automaticOIDCClient(t)
	automaticOIDCExistingIDP(other, provider)
	start = automaticOIDCGet(t, other, server.URL+"/api/auth/oidc/login?mode=auto")
	authorized = automaticOIDCGet(t, other, start.Header.Get("Location"))
	wrong, _ := url.Parse(authorized.Header.Get("Location"))
	q := wrong.Query()
	q.Set("iss", provider.server.URL+"/realm")
	wrong.RawQuery = q.Encode()
	before := provider.exchanges.Load()
	rejected := automaticOIDCGet(t, other, wrong.String())
	if !strings.Contains(rejected.Header.Get("Location"), "error=oidc_authentication") || automaticOIDCSession(other, server) != "" || provider.exchanges.Load() != before {
		t.Fatal("issuer without the required slash was accepted")
	}
}

// auto_login is an administrator opt-in. A default installation, an OIDC record
// saved without the key, or a crafted ?mode=auto URL must never send prompt=none.
func TestOIDCAutomaticLoginIsOptInByDefault(t *testing.T) {
	for _, s := range []map[string]any{{"enabled": true}, {"enabled": true, "auto_login": "true"}, {"enabled": true, "auto_login": nil}, {"enabled": false, "auto_login": true}} {
		if oidcAutoEnabled(s) {
			t.Errorf("auto login enabled for %v", s)
		}
	}
	if !oidcAutoEnabled(map[string]any{"enabled": true, "auto_login": true}) {
		t.Fatal("explicit auto login ignored")
	}
	if defaultSettings()["oidc"]["auto_login"] != false {
		t.Fatal("auto_login default is not off")
	}
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	p := newAutomaticOIDCTestProvider(t)
	mustRequest(t, s, "PUT", "/api/settings/general", map[string]any{"public_url": s.URL}, admin, 200)
	mustRequest(t, s, "PUT", "/api/settings/oidc", map[string]any{"enabled": true, "issuer": p.server.URL + p.issuerPath, "client_id": "hunter-client", "client_secret": "synthetic-client-secret", "default_role": "viewer"}, admin, 200)
	c := automaticOIDCClient(t)
	automaticOIDCExistingIDP(c, p)
	config := automaticOIDCConfig(t, c, s)
	if config["oidc_enabled"] != true || config["oidc_auto_login"] != false || config["oidc_auto_login_allowed"] != false {
		t.Fatalf("default config advertises automatic login: %v", config)
	}
	calls := p.discoveries.Load()
	start := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=auto&return_to=%2Fservices%3Fpage%3D2")
	location, _ := url.Parse(start.Header.Get("Location"))
	if start.StatusCode != 303 || location.Path != "/login" || location.Query().Get("sso") != "skip" || location.Query().Get("return_to") != "/services?page=2" || location.Query().Get("error") != "" {
		t.Fatalf("unrequested silent attempt was not turned into an ordinary login: %s", start.Header.Get("Location"))
	}
	if p.discoveries.Load() != calls || p.authorizations.Load() != 0 || automaticOIDCSession(c, s) != "" {
		t.Fatal("auto_login off still contacted the IdP")
	}
	manual := automaticOIDCGet(t, c, s.URL+"/api/auth/oidc/login?mode=interactive")
	manualURL, _ := url.Parse(manual.Header.Get("Location"))
	if manual.StatusCode != 302 || manualURL.Query().Get("prompt") != "" || manualURL.Query().Get("state") == "" {
		t.Fatal("explicit SSO unavailable while auto_login is off")
	}
	mustRequest(t, s, "PUT", "/api/settings/oidc", map[string]any{"auto_login": true}, admin, 200)
	fresh := automaticOIDCClient(t)
	if automaticOIDCConfig(t, fresh, s)["oidc_auto_login_allowed"] != true {
		t.Fatal("enabling auto_login did not advertise automatic login")
	}
	enabled := automaticOIDCGet(t, fresh, s.URL+"/api/auth/oidc/login?mode=auto")
	enabledURL, _ := url.Parse(enabled.Header.Get("Location"))
	if enabled.StatusCode != 302 || enabledURL.Query().Get("prompt") != "none" {
		t.Fatal("explicit auto_login did not start a silent attempt")
	}
}
