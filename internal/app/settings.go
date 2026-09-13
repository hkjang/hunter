package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

var allScopes = []string{"services:read", "services:write", "findings:read", "findings:write", "scans:read", "scans:write", "scans:approve", "agents:read", "agents:write", "integrations:manage", "admin:manage", "audit:read", "ai:use"}

func defaultSettings() map[string]map[string]any {
	out := map[string]map[string]any{
		"general":  {"service_name": "hunter", "public_url": "http://localhost:8080"},
		"oidc":     {"enabled": false, "auto_login": true, "issuer": "", "client_id": "", "client_secret": "", "default_role": "viewer"},
		"ai":       {"enabled": false, "base_url": "", "api_key": "", "model": "", "max_tokens": 8192, "context_window": 262144},
		"agents":   {"enabled": false, "max_iterations": 24, "max_model_calls": 60, "max_tool_calls": 40, "timeout_minutes": 15, "allow_diagnosis": false, "allow_candidates": true, "memory_enabled": true},
		"workflow": {"approval_enabled": false},
		"security": {"session_hours": 12, "key_max_days": 90, "trusted_ca_pem": ""},
		"roles":    {"admin": allScopes, "lead": []string{"services:read", "services:write", "findings:read", "findings:write", "scans:read", "scans:write", "scans:approve", "agents:read", "agents:write", "ai:use"}, "analyst": []string{"services:read", "services:write", "findings:read", "findings:write", "scans:read", "scans:write", "agents:read", "agents:write", "ai:use"}, "viewer": []string{"services:read", "findings:read", "scans:read"}},
	}
	for group, values := range findingOpsDefaultSettings() {
		out[group] = values
	}
	out["inventory"] = map[string]any{"stale_after_days": 30, "review_licenses": []string{}}
	return out
}

var secretFields = map[string][]string{"oidc": {"client_secret"}, "ai": {"api_key"}}

func (a *App) setting(ctx context.Context, group string) (map[string]any, error) {
	defaults, ok := defaultSettings()[group]
	if !ok {
		defaults = map[string]any{}
	}
	var b []byte
	err := a.DB.QueryRow(ctx, "SELECT value FROM settings WHERE key=$1", group).Scan(&b)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if err == nil {
		var stored map[string]any
		if e := json.Unmarshal(b, &stored); e != nil {
			return nil, e
		}
		for k, v := range stored {
			defaults[k] = v
		}
	}
	for _, k := range secretFields[group] {
		if s, ok := defaults[k].(string); ok && s != "" {
			v, e := a.decrypt(s)
			if e != nil {
				return nil, fmt.Errorf("비밀 설정 복호화 실패")
			}
			defaults[k] = v
		}
	}
	return defaults, nil
}
func asString(v any) string { s, _ := v.(string); return s }
func asBool(v any) bool     { b, _ := v.(bool); return b }
func asInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	}
	return 0
}
func stringSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := []string{}
		for _, z := range x {
			if s, ok := z.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{}
}
func validURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func (a *App) roleScopes(ctx context.Context, role string) []string {
	if role == "admin" {
		return append([]string{}, allScopes...)
	}
	m, e := a.setting(ctx, "roles")
	if e != nil {
		return nil
	}
	return stringSlice(m[role])
}
func (a *App) registerSettings(m *http.ServeMux) {
	m.HandleFunc("GET /api/settings/public", a.protect("", func(w http.ResponseWriter, r *http.Request) {
		g, e := a.setting(r.Context(), "general")
		if e != nil {
			fail(w, 500, "설정을 읽을 수 없습니다")
			return
		}
		flow, _ := a.setting(r.Context(), "workflow")
		ai, _ := a.setting(r.Context(), "ai")
		agents, _ := a.setting(r.Context(), "agents")
		platformEnabled, _ := a.platformModelsEnabled(r.Context())
		jsonResponse(w, 200, map[string]any{"service_name": g["service_name"], "version": a.Version, "approval_enabled": flow["approval_enabled"], "ai_enabled": asBool(ai["enabled"]) || platformEnabled, "agents_enabled": agents["enabled"], "agent_upstream_commit": "ea665308baaff015b226f308438a68d929d0f29b"})
	}))
	m.HandleFunc("GET /api/settings", a.protect("admin:manage", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{}
		for group := range defaultSettings() {
			v, e := a.setting(r.Context(), group)
			if e != nil {
				fail(w, 500, "설정을 읽을 수 없습니다")
				return
			}
			for _, k := range secretFields[group] {
				v[k+"_configured"] = asString(v[k]) != ""
				v[k] = ""
			}
			out[group] = v
		}
		out["available_scopes"] = allScopes
		jsonResponse(w, 200, out)
	}))
	m.HandleFunc("PUT /api/settings/{group}", a.protect("admin:manage", func(w http.ResponseWriter, r *http.Request) {
		group := r.PathValue("group")
		allowed, ok := defaultSettings()[group]
		if !ok {
			fail(w, 404, "설정 그룹을 찾을 수 없습니다")
			return
		}
		var in map[string]any
		if decode(r, &in) != nil {
			fail(w, 400, "설정 값을 확인해 주세요")
			return
		}
		v, e := a.setting(r.Context(), group)
		if e != nil {
			fail(w, 500, "설정을 읽을 수 없습니다")
			return
		}
		for k, val := range in {
			if _, ok = allowed[k]; ok {
				if slices.Contains(secretFields[group], k) && asString(val) == "" {
					continue
				}
				v[k] = val
			}
		}
		for _, k := range secretFields[group] {
			if asBool(in["clear_"+k]) || asBool(in["clear_secret"]) {
				v[k] = ""
			}
		}
		if e = validateSettings(group, v); e != nil {
			fail(w, 400, e.Error())
			return
		}
		for _, k := range secretFields[group] {
			if s := asString(v[k]); s != "" {
				v[k], e = a.encrypt(s)
				if e != nil {
					fail(w, 500, "설정 암호화 실패")
					return
				}
			}
		}
		b, _ := json.Marshal(v)
		_, e = a.DB.Exec(r.Context(), "INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2,updated_at=now()", group, b)
		if e != nil {
			fail(w, 500, "설정을 저장하지 못했습니다")
			return
		}
		a.audit(r, "settings.update", group, in)
		for _, k := range secretFields[group] {
			v[k+"_configured"] = asString(v[k]) != ""
			v[k] = ""
		}
		jsonResponse(w, 200, v)
	}))
	m.HandleFunc("GET /api/audit", a.protect("audit:read", func(w http.ResponseWriter, r *http.Request) {
		rows, e := a.DB.Query(r.Context(), "SELECT id,user_id,username,action,target,detail,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 1000")
		if e != nil {
			fail(w, 500, "감사 기록 조회 실패")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, uid, username, action, target string
			var detail any
			var t any
			if e = rows.Scan(&id, &uid, &username, &action, &target, &detail, &t); e != nil {
				fail(w, 500, "감사 기록 조회 실패")
				return
			}
			out = append(out, map[string]any{"id": id, "user_id": uid, "username": username, "action": action, "target": target, "detail": detail, "created_at": t})
		}
		jsonResponse(w, 200, out)
	}))
}
func validateSettings(group string, v map[string]any) error {
	for key, def := range defaultSettings()[group] {
		if _, ok := def.(bool); ok {
			if _, ok := v[key].(bool); !ok {
				return fmt.Errorf("%s 값은 true 또는 false여야 합니다", key)
			}
		}
	}

	switch group {
	case "sla", "risk":
		return validateFindingOpsSettings(group, v)
	case "inventory":
		return validateInventorySettings(v)
	case "general":
		if strings.TrimSpace(asString(v["service_name"])) == "" || !validURL(asString(v["public_url"])) {
			return fmt.Errorf("서비스 이름과 유효한 서비스 주소를 입력해 주세요")
		}
	case "oidc":
		if !slices.Contains([]string{"viewer", "analyst", "lead"}, asString(v["default_role"])) {
			return fmt.Errorf("SSO 기본 역할은 열람자·분석가·팀장 중 선택해 주세요")
		}
		if asBool(v["enabled"]) && (!validURL(asString(v["issuer"])) || asString(v["client_id"]) == "" || asString(v["client_secret"]) == "") {
			return fmt.Errorf("SSO 발급자 주소, Client ID, Client Secret을 입력해 주세요")
		}
	case "ai":
		if asInt(v["max_tokens"]) < 1 || asInt(v["max_tokens"]) > 262144 || asInt(v["context_window"]) < 1024 || asInt(v["context_window"]) > 262144 || asInt(v["max_tokens"]) > asInt(v["context_window"]) {
			return fmt.Errorf("최대 토큰과 컨텍스트는 262144 이하이며 최대 토큰은 컨텍스트 이하여야 합니다")
		}
		if asBool(v["enabled"]) && (!validURL(asString(v["base_url"])) || asString(v["model"]) == "") {
			return fmt.Errorf("AI API 기본 주소와 모델을 입력해 주세요")
		}
	case "agents":
		for key, limit := range map[string][2]int{"max_iterations": {6, 100}, "max_model_calls": {5, 200}, "max_tool_calls": {1, 200}, "timeout_minutes": {1, 60}} {
			n := asInt(v[key])
			if n < limit[0] || n > limit[1] {
				return fmt.Errorf("%s 값은 %d~%d 범위여야 합니다", key, limit[0], limit[1])
			}
		}
	case "workflow":
		if _, ok := v["approval_enabled"].(bool); !ok {
			return fmt.Errorf("승인 사용 여부는 참/거짓이어야 합니다")
		}
	case "security":
		if pem := asString(v["trusted_ca_pem"]); pem != "" {
			if len(pem) > 200000 || !x509.NewCertPool().AppendCertsFromPEM([]byte(pem)) {
				return fmt.Errorf("유효한 PEM CA 인증서를 입력해 주세요")
			}
		}
		if asInt(v["session_hours"]) < 1 || asInt(v["session_hours"]) > 168 || asInt(v["key_max_days"]) < 1 || asInt(v["key_max_days"]) > 365 {
			return fmt.Errorf("세션은 1~168시간, 키 유효기간은 1~365일로 입력해 주세요")
		}
	case "roles":
		for role, scopes := range v {
			if role == "admin" {
				v[role] = allScopes
				continue
			}
			for _, scope := range stringSlice(scopes) {
				if !slices.Contains(allScopes, scope) || scope == "admin:manage" {
					return fmt.Errorf("역할에 허용되지 않은 권한입니다: %s", scope)
				}
			}
		}
	}
	return nil
}
