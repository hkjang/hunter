package app

import (
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"slices"
	"strings"
	"time"
)

func (a *App) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, e := a.DB.Query(r.Context(), "SELECT id,username,name,role,team,disabled,oidc_subject IS NOT NULL,created_at FROM users ORDER BY created_at")
	if e != nil {
		fail(w, 500, "사용자 조회 실패")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, username, name, role, team string
		var disabled, sso bool
		var created time.Time
		if rows.Scan(&id, &username, &name, &role, &team, &disabled, &sso, &created) != nil {
			fail(w, 500, "사용자 조회 실패")
			return
		}
		out = append(out, map[string]any{"id": id, "username": username, "name": name, "role": role, "team": team, "disabled": disabled, "sso": sso, "created_at": created})
	}
	jsonResponse(w, 200, out)
}
func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Team     string `json:"team"`
	}
	if decode(r, &in) != nil || strings.TrimSpace(in.Username) == "" || len(in.Username) > 200 || len(in.Password) < 12 || len(in.Password) > 72 || !slices.Contains([]string{"admin", "lead", "analyst", "viewer"}, in.Role) {
		fail(w, 400, "아이디, 12~72바이트 비밀번호와 역할을 확인해 주세요")
		return
	}
	if in.Name == "" {
		in.Name = in.Username
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(in.Password), 12)
	id := newID()
	_, e := a.DB.Exec(r.Context(), "INSERT INTO users(id,username,name,role,password_hash,team) VALUES($1,$2,$3,$4,$5,$6)", id, in.Username, in.Name, in.Role, string(h), in.Team)
	if e != nil {
		fail(w, 409, "사용자를 만들 수 없습니다. 아이디 중복을 확인해 주세요")
		return
	}
	a.audit(r, "users.create", id, map[string]string{"username": in.Username, "role": in.Role})
	jsonResponse(w, 201, map[string]any{"id": id, "username": in.Username, "name": in.Name, "role": in.Role})
}
func (a *App) updateUser(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if decode(r, &in) != nil {
		fail(w, 400, "입력값을 확인해 주세요")
		return
	}
	tx, e := a.DB.Begin(r.Context())
	if e != nil {
		fail(w, 500, "사용자 수정 실패")
		return
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(748621093)"); e != nil {
		fail(w, 500, "사용자 수정 실패")
		return
	}
	id := r.PathValue("id")
	var name, role, hash, team string
	var disabled bool
	e = tx.QueryRow(r.Context(), "SELECT name,role,password_hash,team,disabled FROM users WHERE id=$1 FOR UPDATE", id).Scan(&name, &role, &hash, &team, &disabled)
	if e != nil {
		fail(w, 404, "사용자를 찾을 수 없습니다")
		return
	}
	oldRole, oldDisabled := role, disabled
	if v, ok := in["team"]; ok {
		team = asString(v)
	}
	if v, ok := in["name"]; ok {
		name = asString(v)
	}
	if v, ok := in["role"]; ok {
		role = asString(v)
	}
	if v, ok := in["disabled"]; ok {
		disabled = asBool(v)
	}
	if name == "" || !slices.Contains([]string{"admin", "lead", "analyst", "viewer"}, role) {
		fail(w, 400, "이름과 역할을 확인해 주세요")
		return
	}
	if oldRole == "admin" && !oldDisabled && (role != "admin" || disabled) {
		var count int
		_ = tx.QueryRow(r.Context(), "SELECT count(*) FROM users WHERE role='admin' AND NOT disabled").Scan(&count)
		if count <= 1 {
			fail(w, 409, "마지막 활성 관리자는 비활성화하거나 역할을 변경할 수 없습니다")
			return
		}
	}
	if password := asString(in["password"]); password != "" {
		if len(password) < 12 || len(password) > 72 {
			fail(w, 400, "비밀번호는 12~72바이트여야 합니다")
			return
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		if err != nil {
			fail(w, 500, "사용자 수정 실패")
			return
		}
		hash = string(h)
	}
	_, e = tx.Exec(r.Context(), "UPDATE users SET name=$1,role=$2,disabled=$3,password_hash=$4,team=$6 WHERE id=$5", name, role, disabled, hash, id, team)
	if e == nil {
		_, e = tx.Exec(r.Context(), "DELETE FROM sessions WHERE user_id=$1", id)
	}
	if e != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "사용자 수정 실패")
		return
	}
	a.audit(r, "users.update", id, in)
	jsonResponse(w, 200, map[string]any{"id": id, "name": name, "role": role, "team": team, "disabled": disabled})
}
