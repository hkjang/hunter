package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Exercise discovery, PKCE, state, nonce, issuer, JWT signature and replay rejection.
func TestOIDCDiscoveryPKCEAndReplay(t *testing.T) {
	_, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var provider *httptest.Server
	var mu sync.Mutex
	nonce, challenge := "", ""
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realm/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": provider.URL + "/realm", "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			_ = r.ParseForm()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			mu.Lock()
			currentChallenge, currentNonce := challenge, nonce
			mu.Unlock()
			if base64.RawURLEncoding.EncodeToString(sum[:]) != currentChallenge || r.Form.Get("code") != "valid-code" {
				http.Error(w, "bad verifier", 400)
				return
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
			if err != nil {
				t.Error(err)
				return
			}
			claims, _ := json.Marshal(map[string]any{"iss": provider.URL + "/realm", "sub": "employee-123", "aud": "hunter-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": currentNonce, "name": "사내 사용자", "preferred_username": "employee"})
			signed, _ := signer.Sign(claims)
			jwt, _ := signed.CompactSerialize()
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token", "token_type": "Bearer", "id_token": jwt, "expires_in": 3600})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	mustRequest(t, s, "PUT", "/api/settings/general", map[string]any{"public_url": s.URL}, cookie, 200)
	mustRequest(t, s, "PUT", "/api/settings/oidc", map[string]any{"enabled": true, "issuer": provider.URL + "/realm", "client_id": "hunter-client", "client_secret": "oidc-secret", "default_role": "viewer"}, cookie, 200)
	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	start, e := client.Get(s.URL + "/api/auth/oidc/login")
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, start.Body)
	start.Body.Close()
	if start.StatusCode != 302 {
		t.Fatalf("OIDC start %d", start.StatusCode)
	}
	authURL, _ := url.Parse(start.Header.Get("Location"))
	q := authURL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "hunter-client" {
		t.Fatal("missing PKCE")
	}
	mu.Lock()
	nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
	mu.Unlock()
	stateCookie := ""
	for _, cookie := range start.Cookies() {
		if cookie.Name == "hunter_oidc_state" {
			stateCookie = cookie.Name + "=" + cookie.Value
		}
	}
	if stateCookie == "" {
		t.Fatal("missing browser-bound state cookie")
	}
	callback := s.URL + "/api/auth/oidc/callback?state=" + url.QueryEscape(q.Get("state")) + "&code=valid-code"
	r, _ := http.NewRequest("GET", callback, nil)
	r.Header.Set("Cookie", stateCookie)
	resp, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("callback failed %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	session := ""
	for _, c := range resp.Cookies() {
		if c.Name == "hunter_session" {
			session = c.Name + "=" + c.Value
		}
	}
	if session == "" {
		t.Fatal("no SSO session")
	}
	me := mustRequest(t, s, "GET", "/api/auth/me", nil, session, 200)
	if me["user"].(map[string]any)["role"] != "viewer" {
		t.Fatal("SSO default role mismatch")
	}
	r, _ = http.NewRequest("GET", callback, nil)
	r.Header.Set("Cookie", stateCookie)
	resp, e = client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "error=oidc_authentication") {
		t.Fatal("authorization code/state replay accepted")
	}
}
