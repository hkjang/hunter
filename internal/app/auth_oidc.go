package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// The browser callback context is encrypted independently of the PKCE verifier.
// Existing in-flight v1.8 requests safely expire; no unbound redirect is accepted.
func (a *App) initAuth(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `ALTER TABLE oidc_states ADD COLUMN IF NOT EXISTS context_encrypted text NOT NULL DEFAULT ''`)
	return err
}

type oidcFlowContext struct {
	ReturnTo    string `json:"return_to"`
	Mode        string `json:"mode"`
	Fingerprint string `json:"fingerprint"`
	Issuer      string `json:"issuer"`
}

type oidcSuppression struct {
	Reason string `json:"reason"`
	Until  int64  `json:"until"`
}

// Silent prompt=none attempts are an explicit administrator opt-in: a missing or
// non-boolean auto_login means off, so a default installation never redirects.
func oidcAutoEnabled(s map[string]any) bool {
	return asBool(s["enabled"]) && asBool(s["auto_login"])
}

// Internal app URLs only. Encoded slash/backslash and dot traversal variants are
// rejected before redirect so URL parsers cannot disagree about the destination.
func oidcReturnTo(raw string) string {
	if raw == "" || len(raw) > 4096 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "/dashboard"
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" {
		return "/dashboard"
	}
	p := u.Path
	if strings.Contains(p, "\\") || strings.HasPrefix(p, "//") || strings.IndexFunc(p, unicode.IsControl) >= 0 || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") || strings.Contains(strings.ToLower(u.EscapedPath()), "%5c") {
		return "/dashboard"
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." {
			return "/dashboard"
		}
	}
	if p == "/login" || strings.HasPrefix(p, "/login/") || p == "/api" || strings.HasPrefix(p, "/api/") {
		return "/dashboard"
	}
	return u.String()
}

func (a *App) oidcSuppressionState(r *http.Request) (oidcSuppression, bool) {
	var value oidcSuppression
	c, err := r.Cookie("hunter_oidc_bypass")
	if err != nil || len(c.Value) > 2048 {
		return value, false
	}
	plain, err := a.decrypt(c.Value)
	if err != nil || json.Unmarshal([]byte(plain), &value) != nil || value.Until <= time.Now().Unix() || value.Until > time.Now().Add(25*time.Hour).Unix() {
		return oidcSuppression{}, false
	}
	return value, value.Reason == "attempt" || value.Reason == "fallback" || value.Reason == "logout"
}
func (a *App) oidcSuppressed(r *http.Request) bool { _, ok := a.oidcSuppressionState(r); return ok }
func (a *App) setOIDCSuppression(w http.ResponseWriter, r *http.Request, reason string, duration time.Duration) {
	until := time.Now().Add(duration).Unix()
	if old, ok := a.oidcSuppressionState(r); ok && old.Until > until {
		reason, until = old.Reason, old.Until
	}
	b, _ := json.Marshal(oidcSuppression{Reason: reason, Until: until})
	encrypted, err := a.encrypt(string(b))
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "hunter_oidc_bypass", Value: encrypted, Path: "/", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: int(until - time.Now().Unix())})
}
func (a *App) clearOIDCSuppression(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "hunter_oidc_bypass", Value: "", Path: "/", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func (a *App) clearOIDCStateCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "hunter_oidc_state", Value: "", Path: "/api/auth/oidc", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func (a *App) oidcFallback(w http.ResponseWriter, r *http.Request, returnTo, code string) {
	a.setOIDCSuppression(w, r, "fallback", 10*time.Minute)
	values := url.Values{"sso": {"skip"}, "return_to": {oidcReturnTo(returnTo)}}
	if code != "" {
		values.Set("error", code)
	}
	http.Redirect(w, r, "/login?"+values.Encode(), http.StatusSeeOther)
}
func oidcFingerprint(s map[string]any, c *oauth2.Config) string {
	b, _ := json.Marshal([]any{s["enabled"], asString(s["issuer"]), c.ClientID, c.ClientSecret, c.RedirectURL, s["default_role"], oidcAutoEnabled(s)})
	return digest(string(b))
}
func (a *App) oidcSettings(ctx context.Context) (*oauth2.Config, map[string]any, error) {
	s, err := a.setting(ctx, "oidc")
	if err != nil || !asBool(s["enabled"]) {
		return nil, nil, fmt.Errorf("SSO를 사용할 수 없습니다")
	}
	g, err := a.setting(ctx, "general")
	if err != nil {
		return nil, nil, err
	}
	return &oauth2.Config{ClientID: asString(s["client_id"]), ClientSecret: asString(s["client_secret"]), RedirectURL: strings.TrimSuffix(asString(g["public_url"]), "/") + "/api/auth/oidc/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}, s, nil
}
func (a *App) oidcProvider(ctx context.Context) (*oidc.Provider, *oauth2.Config, map[string]any, error) {
	c, s, err := a.oidcSettings(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := a.outboundClient(ctx, 15*time.Second)
	if err != nil {
		return nil, nil, nil, err
	}
	defer client.CloseIdleConnections()
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, client), asString(s["issuer"]))
	if err != nil {
		return nil, nil, nil, err
	}
	c.Endpoint = p.Endpoint()
	return p, c, s, nil
}

func (a *App) oidcLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	returnTo := oidcReturnTo(r.URL.Query().Get("return_to"))
	// A current Hunter browser session wins without discovery or a new IdP flow.
	if _, err := r.Cookie("hunter_session"); err == nil && r.Header.Get("Authorization") == "" {
		if _, err = a.authenticate(r); err == nil {
			http.Redirect(w, r, returnTo, 303)
			return
		}
	}
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "interactive"
	}
	if mode != "auto" && mode != "interactive" {
		a.oidcFallback(w, r, returnTo, "oidc_configuration")
		return
	}
	if r.URL.Query().Get("local") == "1" {
		a.oidcFallback(w, r, returnTo, "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if mode == "auto" {
		s, err := a.setting(ctx, "oidc")
		if err != nil || !oidcAutoEnabled(s) || a.oidcSuppressed(r) {
			a.oidcFallback(w, r, returnTo, "")
			return
		}
		// Before discovery: back/reload after unreachable IdP cannot start a loop.
		a.setOIDCSuppression(w, r, "attempt", 10*time.Minute)
	} else {
		a.clearOIDCSuppression(w, r)
	}
	_, c, s, err := a.oidcProvider(ctx)
	if err != nil {
		a.oidcFallback(w, r, returnTo, "oidc_configuration")
		return
	}
	state, nonce, verifier := randomToken(), randomToken(), oauth2.GenerateVerifier()
	encrypted, err := a.encrypt(verifier)
	if err != nil {
		a.oidcFallback(w, r, returnTo, "oidc_authentication")
		return
	}
	flow, _ := json.Marshal(oidcFlowContext{ReturnTo: returnTo, Mode: mode, Fingerprint: oidcFingerprint(s, c), Issuer: asString(s["issuer"])})
	encryptedFlow, err := a.encrypt(string(flow))
	if err != nil {
		a.oidcFallback(w, r, returnTo, "oidc_authentication")
		return
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO oidc_states(state_hash,nonce,verifier,expires_at,context_encrypted) VALUES($1,$2,$3,now()+interval '10 minutes',$4)`, digest(state), nonce, encrypted, encryptedFlow)
	if err != nil {
		a.oidcFallback(w, r, returnTo, "oidc_authentication")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "hunter_oidc_state", Value: state, Path: "/api/auth/oidc", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	options := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("response_mode", "query")}
	if mode == "auto" {
		options = append(options, oauth2.SetAuthURLParam("prompt", "none"))
	}
	http.Redirect(w, r, c.AuthCodeURL(state, options...), 302)
}

func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	returnTo := "/dashboard"
	reject := func() { a.oidcFallback(w, r, returnTo, "oidc_authentication") }
	q := r.URL.Query()
	state := q.Get("state")
	cookie, err := r.Cookie("hunter_oidc_state")
	if err != nil || state == "" || len(state) > 256 || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		reject()
		return
	}
	a.clearOIDCStateCookie(w, r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var nonce, encrypted, encryptedFlow string
	err = a.DB.QueryRow(ctx, `DELETE FROM oidc_states WHERE state_hash=$1 AND expires_at>now() RETURNING nonce,verifier,context_encrypted`, digest(state)).Scan(&nonce, &encrypted, &encryptedFlow)
	if err != nil {
		reject()
		return
	}
	var flow oidcFlowContext
	plain, err := a.decrypt(encryptedFlow)
	if err != nil || json.Unmarshal([]byte(plain), &flow) != nil || (flow.Mode != "auto" && flow.Mode != "interactive") {
		reject()
		return
	}
	returnTo = oidcReturnTo(flow.ReturnTo)
	if suppression, ok := a.oidcSuppressionState(r); ok && suppression.Reason == "logout" {
		reject()
		return
	}
	c, s, err := a.oidcSettings(ctx)
	if err != nil || oidcFingerprint(s, c) != flow.Fingerprint || (q.Get("iss") != "" && (len(q["iss"]) != 1 || q.Get("iss") != flow.Issuer)) {
		reject()
		return
	}
	// Error callbacks still require the browser state and an unexpired one-use DB
	// record. Provider text/error_description is never reflected in Hunter output.
	if q.Get("error") != "" {
		if len(q["error"]) != 1 || q.Get("code") != "" {
			reject()
			return
		}
		code := "oidc_authentication"
		if flow.Mode == "auto" {
			switch q.Get("error") {
			case "login_required":
				code = "oidc_login_required"
			case "interaction_required", "consent_required", "account_selection_required":
				code = "oidc_interaction_required"
			}
		}
		a.oidcFallback(w, r, returnTo, code)
		return
	}
	if q.Get("code") == "" || len(q["code"]) != 1 || len(q.Get("code")) > 8192 {
		reject()
		return
	}
	// A local login completed while SSO was pending; retain that browser identity.
	if _, err := r.Cookie("hunter_session"); err == nil && r.Header.Get("Authorization") == "" {
		if _, err = a.authenticate(r); err == nil {
			a.clearOIDCSuppression(w, r)
			http.Redirect(w, r, returnTo, 303)
			return
		}
	}
	verifier, err := a.decrypt(encrypted)
	if err != nil {
		reject()
		return
	}
	p, c, s, err := a.oidcProvider(ctx)
	if err != nil || oidcFingerprint(s, c) != flow.Fingerprint {
		reject()
		return
	}
	client, err := a.outboundClient(ctx, 15*time.Second)
	if err != nil {
		reject()
		return
	}
	defer client.CloseIdleConnections()
	ctx = oidc.ClientContext(ctx, client)
	token, err := c.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		reject()
		return
	}
	raw, _ := token.Extra("id_token").(string)
	id, err := p.Verifier(&oidc.Config{ClientID: c.ClientID}).Verify(ctx, raw)
	if err != nil || id.Nonce != nonce || id.Subject == "" {
		reject()
		return
	}
	var claims struct {
		Name     string `json:"name"`
		Username string `json:"preferred_username"`
	}
	if id.Claims(&claims) != nil {
		reject()
		return
	}
	// Reject a concurrent settings change before mapping or issuing a session.
	latest, latestSettings, err := a.oidcSettings(ctx)
	if err != nil || oidcFingerprint(latestSettings, latest) != flow.Fingerprint {
		reject()
		return
	}
	subject := digest(asString(s["issuer"]) + "|" + id.Subject)
	var u User
	err = a.DB.QueryRow(ctx, `SELECT id,username,name,role,team FROM users WHERE oidc_subject=$1 AND NOT disabled`, subject).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	if errors.Is(err, pgx.ErrNoRows) {
		username := claims.Username
		if username == "" {
			username = "sso"
		}
		username = username + "-" + subject[:10]
		name := claims.Name
		if name == "" {
			name = claims.Username
		}
		if name == "" {
			name = "SSO 사용자"
		}
		_, err = a.DB.Exec(ctx, `INSERT INTO users(id,username,name,role,oidc_subject) VALUES($1,$2,$3,$4,$5) ON CONFLICT(oidc_subject) DO NOTHING`, newID(), username, name, asString(s["default_role"]), subject)
		if err == nil {
			err = a.DB.QueryRow(ctx, `SELECT id,username,name,role,team FROM users WHERE oidc_subject=$1 AND NOT disabled`, subject).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
		}
	}
	if err != nil || a.session(w, r, u) != nil {
		reject()
		return
	}
	a.clearOIDCSuppression(w, r)
	a.audit(r.WithContext(context.WithValue(r.Context(), userContextKey{}, u)), "auth.oidc_login", u.ID, map[string]string{"mode": flow.Mode})
	http.Redirect(w, r, returnTo, 303)
}
