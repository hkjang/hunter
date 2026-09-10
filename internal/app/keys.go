package app

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
)

func (a *App) sessionOnly(h http.HandlerFunc) http.HandlerFunc {
	return a.protect("", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			fail(w, 403, "개인 설정과 키 관리는 브라우저 로그인으로만 가능합니다")
			return
		}
		h(w, r)
	})
}
func (a *App) registerKeys(m *http.ServeMux) {
	m.HandleFunc("GET /api/keys", a.sessionOnly(a.listKeys))
	m.HandleFunc("POST /api/keys", a.sessionOnly(a.createKey))
	m.HandleFunc("PUT /api/keys/{id}", a.sessionOnly(a.updateKey))
	m.HandleFunc("POST /api/keys/{id}/rotate", a.sessionOnly(a.rotateKey))
	m.HandleFunc("DELETE /api/keys/{id}", a.sessionOnly(a.revokeKey))
}
func (a *App) listKeys(w http.ResponseWriter, r *http.Request) {
	rows, e := a.DB.Query(r.Context(), "SELECT id,name,prefix,scopes,expires_at,created_at,last_used_at,revoked_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC", currentUser(r).ID)
	if e != nil {
		fail(w, 500, "키 조회 실패")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, prefix string
		var scopes any
		var expires, created time.Time
		var used, revoked *time.Time
		if rows.Scan(&id, &name, &prefix, &scopes, &expires, &created, &used, &revoked) != nil {
			fail(w, 500, "키 조회 실패")
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "prefix": prefix, "scopes": scopes, "expires_at": expires, "created_at": created, "last_used_at": used, "revoked_at": revoked})
	}
	jsonResponse(w, 200, out)
}
func validateKey(u User, name string, scopes []string) bool {
	if strings.TrimSpace(name) == "" || len(name) > 200 || len(scopes) == 0 {
		return false
	}
	for _, s := range scopes {
		if !slices.Contains(u.Scopes, s) {
			return false
		}
	}
	return true
}
func (a *App) createKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
		Days   int      `json:"expires_days"`
	}
	u := currentUser(r)
	if decode(r, &in) != nil || !validateKey(u, in.Name, in.Scopes) {
		fail(w, 400, "키 이름과 본인 역할 내 권한을 선택해 주세요")
		return
	}
	settings, _ := a.setting(r.Context(), "security")
	maxDays := asInt(settings["key_max_days"])
	if in.Days < 1 || in.Days > maxDays {
		fail(w, 400, "키 유효기간은 관리자가 지정한 상한 이내여야 합니다")
		return
	}
	id, token := newID(), "hnt_"+randomToken()
	prefix := token[:12]
	expires := time.Now().Add(time.Duration(in.Days) * 24 * time.Hour)
	scopes, _ := json.Marshal(in.Scopes)
	_, e := a.DB.Exec(r.Context(), "INSERT INTO api_keys(id,user_id,name,prefix,token_hash,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)", id, u.ID, in.Name, prefix, digest(token), scopes, expires)
	if e != nil {
		fail(w, 500, "키 발급 실패")
		return
	}
	a.audit(r, "keys.create", id, map[string]any{"name": in.Name, "scopes": in.Scopes})
	jsonResponse(w, 201, map[string]any{"token": token, "key": map[string]any{"id": id, "name": in.Name, "prefix": prefix, "scopes": in.Scopes, "expires_at": expires}})
}
func (a *App) updateKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if decode(r, &in) != nil || !validateKey(currentUser(r), in.Name, in.Scopes) {
		fail(w, 400, "키 이름과 본인 역할 내 권한을 선택해 주세요")
		return
	}
	b, _ := json.Marshal(in.Scopes)
	tag, e := a.DB.Exec(r.Context(), "UPDATE api_keys SET name=$1,scopes=$2 WHERE id=$3 AND user_id=$4 AND revoked_at IS NULL AND expires_at>now()", in.Name, b, r.PathValue("id"), currentUser(r).ID)
	if e != nil {
		fail(w, 500, "키 수정 실패")
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "활성 키를 찾을 수 없습니다")
		return
	}
	a.audit(r, "keys.update", r.PathValue("id"), in)
	jsonResponse(w, 200, map[string]bool{"ok": true})
}
func (a *App) rotateKey(w http.ResponseWriter, r *http.Request) {
	tx, e := a.DB.Begin(r.Context())
	if e != nil {
		fail(w, 500, "키 회전 실패")
		return
	}
	defer tx.Rollback(r.Context())
	var name string
	var b []byte
	var expires time.Time
	e = tx.QueryRow(r.Context(), "UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() RETURNING name,scopes,expires_at", r.PathValue("id"), currentUser(r).ID).Scan(&name, &b, &expires)
	if e != nil {
		fail(w, 404, "활성 키를 찾을 수 없습니다")
		return
	}
	var oldScopes []string
	_ = json.Unmarshal(b, &oldScopes)
	effective := []string{}
	for _, s := range oldScopes {
		if slices.Contains(currentUser(r).Scopes, s) {
			effective = append(effective, s)
		}
	}
	if len(effective) == 0 {
		fail(w, 403, "현재 역할에 허용된 키 권한이 없습니다")
		return
	}
	b, _ = json.Marshal(effective)
	id, token := newID(), "hnt_"+randomToken()
	_, e = tx.Exec(r.Context(), "INSERT INTO api_keys(id,user_id,name,prefix,token_hash,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)", id, currentUser(r).ID, name, token[:12], digest(token), b, expires)
	if e != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "키 회전 실패")
		return
	}
	a.audit(r, "keys.rotate", r.PathValue("id"), map[string]string{"replacement_id": id})
	jsonResponse(w, 200, map[string]any{"token": token, "key": map[string]any{"id": id, "name": name, "prefix": token[:12], "scopes": effective, "expires_at": expires}})
}
func (a *App) revokeKey(w http.ResponseWriter, r *http.Request) {
	tag, e := a.DB.Exec(r.Context(), "UPDATE api_keys SET revoked_at=coalesce(revoked_at,now()) WHERE id=$1 AND user_id=$2", r.PathValue("id"), currentUser(r).ID)
	if e != nil {
		fail(w, 500, "키 폐기 실패")
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "키를 찾을 수 없습니다")
		return
	}
	a.audit(r, "keys.revoke", r.PathValue("id"), nil)
	jsonResponse(w, 200, map[string]bool{"ok": true})
}
