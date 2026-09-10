package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

func (a *App) csrfOK(r *http.Request) bool {
	if r.Header.Get("X-Hunter-CSRF") != "1" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	if e != nil {
		return false
	}
	if u.Host == r.Host {
		return true
	}
	g, e := a.setting(r.Context(), "general")
	return e == nil && strings.TrimSuffix(asString(g["public_url"]), "/") == origin
}
func (a *App) protect(scope string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, e := a.authenticate(r)
		if e != nil {
			fail(w, 401, "로그인이 필요합니다")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && !a.csrfOK(r) {
			fail(w, 403, "요청 출처를 확인할 수 없습니다")
			return
		}
		if scope != "" && !slices.Contains(u.Scopes, scope) {
			fail(w, 403, "이 기능에 대한 권한이 없습니다")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, u)))
	}
}
func (a *App) authenticate(r *http.Request) (User, error) {
	var u User
	var err error
	header := r.Header.Get("Authorization")
	var keyScopes []string
	if strings.HasPrefix(header, "Bearer ") {
		token := strings.TrimPrefix(header, "Bearer ")
		var b []byte
		var keyID string
		err = a.DB.QueryRow(r.Context(), "SELECT u.id,u.username,u.name,u.role,u.team,k.scopes,k.id FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.token_hash=$1 AND k.revoked_at IS NULL AND k.expires_at>now() AND NOT u.disabled", digest(token)).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team, &b, &keyID)
		if err == nil {
			u.KeyID = keyID
			_ = json.Unmarshal(b, &keyScopes)
			_, _ = a.DB.Exec(r.Context(), "UPDATE api_keys SET last_used_at=now() WHERE id=$1 AND (last_used_at IS NULL OR last_used_at<now()-interval '1 minute')", keyID)
		}
	} else {
		c, e := r.Cookie("hunter_session")
		if e != nil {
			return u, e
		}
		err = a.DB.QueryRow(r.Context(), "SELECT u.id,u.username,u.name,u.role,u.team FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND NOT u.disabled", digest(c.Value)).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	}
	if err != nil {
		return u, err
	}
	u.Scopes = a.roleScopes(r.Context(), u.Role)
	if strings.HasPrefix(header, "Bearer ") {
		effective := []string{}
		for _, s := range u.Scopes {
			if slices.Contains(keyScopes, s) {
				effective = append(effective, s)
			}
		}
		u.Scopes = effective
	}
	return u, nil
}
func (a *App) secureCookie(r *http.Request) bool {
	g, _ := a.setting(r.Context(), "general")
	return r.TLS != nil || strings.HasPrefix(asString(g["public_url"]), "https://")
}
func (a *App) session(w http.ResponseWriter, r *http.Request, u User) error {
	token := randomToken()
	s, _ := a.setting(r.Context(), "security")
	hours := asInt(s["session_hours"])
	if hours < 1 {
		hours = 12
	}
	_, e := a.DB.Exec(r.Context(), "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)", digest(token), u.ID, time.Now().Add(time.Duration(hours)*time.Hour))
	if e != nil {
		return e
	}
	http.SetCookie(w, &http.Cookie{Name: "hunter_session", Value: token, Path: "/", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: hours * 3600})
	return nil
}
func (a *App) registerAuth(m *http.ServeMux) {
	m.HandleFunc("GET /api/auth/config", func(w http.ResponseWriter, r *http.Request) {
		o, _ := a.setting(r.Context(), "oidc")
		g, _ := a.setting(r.Context(), "general")
		jsonResponse(w, 200, map[string]any{"version": a.Version, "oidc_enabled": asBool(o["enabled"]), "service_name": g["service_name"]})
	})
	m.HandleFunc("POST /api/auth/login", a.login)
	m.HandleFunc("GET /api/auth/me", a.protect("", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]any{"user": currentUser(r)})
	}))
	m.HandleFunc("POST /api/auth/logout", a.protect("", func(w http.ResponseWriter, r *http.Request) {
		if c, e := r.Cookie("hunter_session"); e == nil {
			_, _ = a.DB.Exec(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", digest(c.Value))
		}
		http.SetCookie(w, &http.Cookie{Name: "hunter_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode})
		jsonResponse(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("GET /api/auth/oidc/login", a.oidcLogin)
	m.HandleFunc("GET /api/auth/oidc/callback", a.oidcCallback)
	m.HandleFunc("GET /api/users", a.protect("admin:manage", a.listUsers))
	m.HandleFunc("POST /api/users", a.protect("admin:manage", a.createUser))
	m.HandleFunc("PUT /api/users/{id}", a.protect("admin:manage", a.updateUser))
	m.HandleFunc("GET /api/profile", a.sessionOnly(func(w http.ResponseWriter, r *http.Request) {
		u := currentUser(r)
		var prefs any
		e := a.DB.QueryRow(r.Context(), "SELECT preferences FROM users WHERE id=$1", u.ID).Scan(&prefs)
		if e != nil {
			fail(w, 500, "프로필 조회 실패")
			return
		}
		jsonResponse(w, 200, map[string]any{"id": u.ID, "username": u.Username, "name": u.Name, "role": u.Role, "team": u.Team, "scopes": u.Scopes, "preferences": prefs})
	}))
	m.HandleFunc("PUT /api/profile", a.sessionOnly(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name        string         `json:"name"`
			Preferences map[string]any `json:"preferences"`
		}
		if decode(r, &in) != nil || strings.TrimSpace(in.Name) == "" || len(in.Name) > 200 {
			fail(w, 400, "표시 이름을 확인해 주세요")
			return
		}
		if in.Preferences == nil {
			in.Preferences = map[string]any{}
		}
		b, _ := json.Marshal(in.Preferences)
		if len(b) > 16000 {
			fail(w, 400, "개인 설정이 너무 큽니다")
			return
		}
		_, e := a.DB.Exec(r.Context(), "UPDATE users SET name=$1,preferences=$2 WHERE id=$3", in.Name, b, currentUser(r).ID)
		if e != nil {
			fail(w, 500, "프로필 저장 실패")
			return
		}
		a.audit(r, "profile.update", currentUser(r).ID, nil)
		jsonResponse(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("POST /api/profile/password", a.sessionOnly(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Current string `json:"current_password"`
			New     string `json:"new_password"`
		}
		if decode(r, &in) != nil || len(in.New) < 12 || len(in.New) > 72 {
			fail(w, 400, "새 비밀번호는 12~72바이트로 입력해 주세요")
			return
		}
		var hash string
		_ = a.DB.QueryRow(r.Context(), "SELECT password_hash FROM users WHERE id=$1", currentUser(r).ID).Scan(&hash)
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Current)) != nil {
			fail(w, 400, "현재 비밀번호가 일치하지 않습니다")
			return
		}
		h, _ := bcrypt.GenerateFromPassword([]byte(in.New), 12)
		tx, e := a.DB.Begin(r.Context())
		if e != nil {
			fail(w, 500, "비밀번호 변경 실패")
			return
		}
		defer tx.Rollback(r.Context())
		_, e = tx.Exec(r.Context(), "UPDATE users SET password_hash=$1 WHERE id=$2", string(h), currentUser(r).ID)
		if e == nil {
			_, e = tx.Exec(r.Context(), "DELETE FROM sessions WHERE user_id=$1", currentUser(r).ID)
		}
		if e != nil || tx.Commit(r.Context()) != nil {
			fail(w, 500, "비밀번호 변경 실패")
			return
		}
		_ = a.session(w, r, currentUser(r))
		a.audit(r, "profile.password", currentUser(r).ID, nil)
		jsonResponse(w, 200, map[string]bool{"ok": true})
	}))
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.csrfOK(r) {
		fail(w, 403, "요청 출처를 확인할 수 없습니다")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decode(r, &in) != nil || len(in.Username) > 200 || len(in.Password) > 72 {
		fail(w, 400, "로그인 정보를 확인해 주세요")
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	// Global local-login concurrency and an independent IP window prevent username
	// rotation from bypassing the per-account bcrypt work budget.
	select {
	case a.AuthSlots <- struct{}{}:
		defer func() { <-a.AuthSlots }()
	default:
		fail(w, 429, "로그인 요청이 많습니다. 잠시 후 다시 시도해 주세요")
		return
	}
	var ipAttempts int
	ipErr := a.DB.QueryRow(r.Context(), "INSERT INTO login_attempts(identity,failures) VALUES($1,1) ON CONFLICT(identity) DO UPDATE SET failures=CASE WHEN login_attempts.window_start<now()-interval '1 minute' THEN 1 ELSE login_attempts.failures+1 END,window_start=CASE WHEN login_attempts.window_start<now()-interval '1 minute' THEN now() ELSE login_attempts.window_start END RETURNING failures", digest("ip:"+ip)).Scan(&ipAttempts)
	if ipErr != nil {
		fail(w, 503, "로그인을 처리할 수 없습니다")
		return
	}
	if ipAttempts > 120 {
		fail(w, 429, "동일 접속 경로에서 로그인 시도가 많습니다. 1분 뒤 다시 시도해 주세요")
		return
	}
	identity := digest(ip + ":" + strings.ToLower(in.Username))
	var failures int
	e := a.DB.QueryRow(r.Context(), "INSERT INTO login_attempts(identity,failures) VALUES($1,1) ON CONFLICT(identity) DO UPDATE SET failures=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN 1 ELSE login_attempts.failures+1 END,window_start=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN now() ELSE login_attempts.window_start END RETURNING failures", identity).Scan(&failures)
	if e != nil {
		fail(w, 503, "로그인을 처리할 수 없습니다")
		return
	}
	if failures > 10 {
		fail(w, 429, "로그인 시도가 많습니다. 15분 뒤 다시 시도해 주세요")
		return
	}
	var u User
	var hash string
	e = a.DB.QueryRow(r.Context(), "SELECT id,username,name,role,team,password_hash FROM users WHERE username=$1 AND NOT disabled", in.Username).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team, &hash)
	if e != nil || hash == "" {
		hash = "$2a$12$ZGGbuMuAfBN0wYSxQ.j.yeNWZ8Gsl2b39NOdKYKRwwtv/wEWpj6fu"
	}
	valid := bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) == nil
	if e != nil || !valid {
		a.audit(r, "auth.login_failed", in.Username, map[string]string{"ip": ip})
		fail(w, 401, "아이디 또는 비밀번호가 일치하지 않습니다")
		return
	}
	if a.session(w, r, u) != nil {
		fail(w, 500, "세션을 만들 수 없습니다")
		return
	}
	_, _ = a.DB.Exec(r.Context(), "DELETE FROM login_attempts WHERE identity=$1", identity)
	u.Scopes = a.roleScopes(r.Context(), u.Role)
	a.audit(r.WithContext(context.WithValue(r.Context(), userContextKey{}, u)), "auth.login", u.ID, nil)
	jsonResponse(w, 200, map[string]any{"user": u})
}
func (a *App) oidcProvider(ctx context.Context) (*oidc.Provider, *oauth2.Config, map[string]any, error) {
	s, e := a.setting(ctx, "oidc")
	if e != nil || !asBool(s["enabled"]) {
		return nil, nil, nil, fmt.Errorf("SSO를 사용할 수 없습니다")
	}
	client, e := a.outboundClient(ctx, 15*time.Second)
	if e != nil {
		return nil, nil, nil, e
	}
	ctx = oidc.ClientContext(ctx, client)
	p, e := oidc.NewProvider(ctx, strings.TrimSuffix(asString(s["issuer"]), "/"))
	if e != nil {
		return nil, nil, nil, e
	}
	g, e := a.setting(ctx, "general")
	if e != nil {
		return nil, nil, nil, e
	}
	c := &oauth2.Config{ClientID: asString(s["client_id"]), ClientSecret: asString(s["client_secret"]), Endpoint: p.Endpoint(), RedirectURL: strings.TrimSuffix(asString(g["public_url"]), "/") + "/api/auth/oidc/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	return p, c, s, nil
}
func (a *App) oidcLogin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	_, c, _, e := a.oidcProvider(ctx)
	if e != nil {
		http.Redirect(w, r, "/login?error=oidc_configuration", 303)
		return
	}
	state, nonce, verifier := randomToken(), randomToken(), oauth2.GenerateVerifier()
	enc, _ := a.encrypt(verifier)
	_, e = a.DB.Exec(ctx, "INSERT INTO oidc_states(state_hash,nonce,verifier,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes')", digest(state), nonce, enc)
	if e != nil {
		fail(w, 500, "SSO 인증 요청 생성 실패")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "hunter_oidc_state", Value: state, Path: "/api/auth/oidc", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, c.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), 302)
}
func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	reject := func() { http.Redirect(w, r, "/login?error=oidc_authentication", 303) }
	state := r.URL.Query().Get("state")
	cookie, e := r.Cookie("hunter_oidc_state")
	if e != nil || state == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		reject()
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "hunter_oidc_state", Value: "", Path: "/api/auth/oidc", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var nonce, enc string
	e = a.DB.QueryRow(ctx, "DELETE FROM oidc_states WHERE state_hash=$1 AND expires_at>now() RETURNING nonce,verifier", digest(state)).Scan(&nonce, &enc)
	if e != nil {
		reject()
		return
	}
	verifier, e := a.decrypt(enc)
	if e != nil {
		reject()
		return
	}
	p, c, s, e := a.oidcProvider(ctx)
	if e != nil {
		reject()
		return
	}
	client, e := a.outboundClient(ctx, 15*time.Second)
	if e != nil {
		reject()
		return
	}
	defer client.CloseIdleConnections()
	ctx = oidc.ClientContext(ctx, client)
	token, e := c.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if e != nil {
		reject()
		return
	}
	raw, _ := token.Extra("id_token").(string)
	id, e := p.Verifier(&oidc.Config{ClientID: c.ClientID}).Verify(ctx, raw)
	if e != nil || id.Nonce != nonce {
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
	subject := digest(asString(s["issuer"]) + "|" + id.Subject)
	var u User
	e = a.DB.QueryRow(ctx, "SELECT id,username,name,role,team FROM users WHERE oidc_subject=$1 AND NOT disabled", subject).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	if e == pgx.ErrNoRows {
		var exists bool
		_ = a.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE oidc_subject=$1)", subject).Scan(&exists)
		if exists {
			reject()
			return
		}
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
		u = User{ID: newID(), Username: username, Name: name, Role: asString(s["default_role"])}
		_, e = a.DB.Exec(ctx, "INSERT INTO users(id,username,name,role,oidc_subject) VALUES($1,$2,$3,$4,$5)", u.ID, u.Username, u.Name, u.Role, subject)
	}
	if e != nil || a.session(w, r, u) != nil {
		reject()
		return
	}
	a.audit(r.WithContext(context.WithValue(r.Context(), userContextKey{}, u)), "auth.oidc_login", u.ID, nil)
	http.Redirect(w, r, "/dashboard", 303)
}
