package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// A resource retains domain-specific fields without coupling connector payloads
// to a particular vendor. Authorization always uses the database owner column.
var errResourceConflict = errors.New("다른 요청이 이 항목을 변경했습니다. 새로고침 후 다시 시도하세요")

type domainResource struct {
	ID, Kind, OwnerID    string
	Data                 map[string]any
	CreatedAt, UpdatedAt time.Time
}

var domainKinds = map[string][2]string{
	"services":      {"services:read", "services:write"},
	"findings":      {"findings:read", "findings:write"},
	"scans":         {"scans:read", "scans:write"},
	"policies":      {"admin:manage", "admin:manage"},
	"scopes":        {"services:read", "admin:manage"},
	"auth-profiles": {"services:read", "admin:manage"},
	"integrations":  {"integrations:manage", "integrations:manage"},
	"discovery":     {"admin:manage", "admin:manage"},
	"reports":       {"findings:read", "findings:write"},
	"approvals":     {"scans:approve", "scans:approve"},
	"workers":       {"admin:manage", "admin:manage"},
	"events":        {"scans:read", "scans:write"},
	"scenarios":     {"services:read", "services:write"},
	"remediations":  {"findings:read", "findings:write"},
	"schedules":     {"scans:read", "scans:write"},
}

func (a *App) initDomain(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `
	CREATE INDEX IF NOT EXISTS resources_owner_kind ON resources(owner_id,kind);
	CREATE INDEX IF NOT EXISTS resources_service ON resources((data->>'service_id'));
	CREATE UNIQUE INDEX IF NOT EXISTS findings_fingerprint ON resources((data->>'service_id'),(data->>'fingerprint')) WHERE kind='findings' AND data->>'fingerprint' <> '';
	CREATE UNIQUE INDEX IF NOT EXISTS events_identity ON resources((data->>'service_id'),(data->>'event_type'),(data->>'reference')) WHERE kind='events' AND data->>'reference' <> '';
	CREATE UNIQUE INDEX IF NOT EXISTS schedule_occurrence ON resources((data->>'schedule_id'),(data->>'schedule_occurrence')) WHERE kind='scans' AND data->>'schedule_id' <> '';
	CREATE TABLE IF NOT EXISTS scan_jobs (
	 scan_id text PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
	 status text NOT NULL DEFAULT 'ready', available_at timestamptz NOT NULL DEFAULT now(),
	 lease_until timestamptz, worker_id text, attempts integer NOT NULL DEFAULT 0,
	 created_at timestamptz NOT NULL DEFAULT now());
	CREATE INDEX IF NOT EXISTS scan_jobs_claim ON scan_jobs(status,available_at,lease_until);
	CREATE TABLE IF NOT EXISTS domain_runtime (id integer PRIMARY KEY CHECK(id=1), emergency boolean NOT NULL DEFAULT false, reason text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now());
	CREATE TABLE IF NOT EXISTS policy_versions (id bigserial PRIMARY KEY,policy_id text NOT NULL,changed_by text NOT NULL,data jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
	CREATE INDEX IF NOT EXISTS policy_versions_policy ON policy_versions(policy_id,id);
	INSERT INTO domain_runtime(id) VALUES(1) ON CONFLICT DO NOTHING;`)
	if err != nil {
		return err
	}
	if err = a.repairLegacyFindingEvidence(ctx); err != nil {
		return err
	}
	return a.initAgents(ctx)
}

func (a *App) registerDomain(mux *http.ServeMux) {
	for kind, scopes := range domainKinds {
		kind, scopes := kind, scopes
		mux.HandleFunc("GET /api/"+kind, a.protect(scopes[0], func(w http.ResponseWriter, r *http.Request) { a.listDomain(w, r, kind) }))
		mux.HandleFunc("GET /api/"+kind+"/{id}", a.protect(scopes[0], func(w http.ResponseWriter, r *http.Request) { a.getDomain(w, r, kind) }))
		if kind == "workers" || kind == "approvals" {
			continue
		}
		mux.HandleFunc("POST /api/"+kind, a.protect(scopes[1], func(w http.ResponseWriter, r *http.Request) { a.saveDomain(w, r, kind, false) }))
		if kind == "scans" || kind == "events" {
			continue
		}
		mux.HandleFunc("PUT /api/"+kind+"/{id}", a.protect(scopes[1], func(w http.ResponseWriter, r *http.Request) { a.saveDomain(w, r, kind, true) }))
		mux.HandleFunc("DELETE /api/"+kind+"/{id}", a.protect(scopes[1], func(w http.ResponseWriter, r *http.Request) { a.deleteDomain(w, r, kind) }))
	}
	mux.HandleFunc("GET /api/dashboard", a.protect("findings:read", a.dashboard))
	mux.HandleFunc("GET /api/graph", a.protect("services:read", a.graph))
	mux.HandleFunc("GET /api/reports/export", a.protect("findings:read", a.exportReport))
	mux.HandleFunc("POST /api/scans/{id}/cancel", a.protect("scans:write", a.cancelScan))
	mux.HandleFunc("POST /api/scans/{id}/approve", a.protect("scans:approve", a.approveScan))
	mux.HandleFunc("POST /api/emergency-stop", a.protect("admin:manage", a.emergencyStop))
	mux.HandleFunc("POST /api/imports", a.protect("findings:write", a.importResults))
	mux.HandleFunc("POST /api/integrations/{id}/test", a.protect("integrations:manage", a.testIntegration))
	mux.HandleFunc("POST /api/integrations/{id}/sync", a.protect("integrations:manage", a.syncIntegration))
	mux.HandleFunc("POST /api/integrations/{id}/webhook", a.protect("integrations:manage", a.webhookIntegration))
	mux.HandleFunc("POST /api/discovery/{id}/register", a.protect("admin:manage", a.registerDiscovery))
	mux.HandleFunc("PUT /api/workers/{id}", a.protect("admin:manage", a.updateWorker))
	mux.HandleFunc("GET /api/policies/{id}/history", a.protect("admin:manage", a.policyHistory))
	mux.HandleFunc("GET /api/policies/export", a.protect("admin:manage", a.exportPolicies))
	a.registerFindingBulk(mux)
}

func elevated(u User) bool   { return u.Role == "admin" }
func managerial(u User) bool { return u.Role == "admin" || u.Role == "lead" }
func leadTeam(u User) string {
	if u.Role == "lead" {
		return u.Team
	}
	return ""
}
func str(m map[string]any, k string) string   { s, _ := m[k].(string); return s }
func boolean(m map[string]any, k string) bool { b, _ := m[k].(bool); return b }
func number(m map[string]any, k string, fallback int) int {
	v, ok := m[k]
	if !ok {
		return fallback
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return fallback
}
func stringList(v any) []string {
	out := []string{}
	switch a := v.(type) {
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, a...)
	}
	return out
}
func hasString(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func cloneMap(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (v domainResource) output() map[string]any {
	m := cloneMap(v.Data)
	m["id"] = v.ID
	m["owner_id"] = v.OwnerID
	m["created_at"] = v.CreatedAt
	m["updated_at"] = v.UpdatedAt
	for _, k := range []string{"secret", "password", "token", "headers", "cookies", "connection_string"} {
		if _, exists := m[k]; exists {
			m[k+"_configured"] = str(v.Data, k) != ""
			m[k] = ""
		}
	}
	return m
}

func (a *App) resourceOutput(v domainResource) map[string]any {
	m := v.output()
	if v.Kind == "findings" {
		if value, exists := v.Data["evidence"]; exists {
			if _, valid := value.(string); !valid {
				m["evidence"] = "[기존 증거 형식이 올바르지 않습니다. 항목을 수정하면 마스킹·암호화하여 복구합니다]"
			}
		}
	}
	if v.Kind == "findings" && boolean(v.Data, "evidence_encrypted") {
		plain, err := a.decrypt(str(v.Data, "evidence"))
		if err == nil {
			m["evidence"] = plain
		} else {
			m["evidence"] = "[암호화 증거를 읽을 수 없습니다]"
		}
	}
	delete(m, "evidence_encrypted")
	delete(m, "credential_key_id")
	return m
}

func scanResource(row pgx.Row) (domainResource, error) {
	var v domainResource
	var raw []byte
	err := row.Scan(&v.ID, &v.Kind, &v.OwnerID, &raw, &v.CreatedAt, &v.UpdatedAt)
	if err == nil {
		err = json.Unmarshal(raw, &v.Data)
	}
	return v, err
}

func (a *App) resource(ctx context.Context, kind, id string) (domainResource, error) {
	return scanResource(a.DB.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind=$1 AND id=$2`, kind, id))
}

func (a *App) canAccess(ctx context.Context, u User, v domainResource) bool {
	if elevated(u) || v.OwnerID == u.ID {
		return true
	}
	if u.Role == "lead" && u.Team != "" && v.Kind == "services" && str(v.Data, "team") == u.Team {
		return true
	}
	if id := str(v.Data, "service_id"); id != "" {
		var owner, team string
		return a.DB.QueryRow(ctx, `SELECT owner_id,COALESCE(data->>'team','') FROM resources WHERE kind='services' AND id=$1`, id).Scan(&owner, &team) == nil && (owner == u.ID || u.Role == "lead" && u.Team != "" && team == u.Team)
	}
	return false
}

func (a *App) ListResources(ctx context.Context, kind string, u User) ([]map[string]any, error) {
	if scopes, ok := domainKinds[kind]; !ok {
		return nil, errors.New("지원하지 않는 자원 유형입니다")
	} else if !hasString(u.Scopes, scopes[0]) {
		return nil, errors.New("요청한 자료의 조회 권한이 없습니다")
	}
	rows, err := a.DB.Query(ctx, `SELECT r.id,r.kind,r.owner_id,r.data,r.created_at,r.updated_at FROM resources r WHERE r.kind=$1 AND ($2 OR r.owner_id=$3 OR ($4<>'' AND r.kind='services' AND r.data->>'team'=$4) OR EXISTS(SELECT 1 FROM resources s WHERE s.kind='services' AND s.id=r.data->>'service_id' AND (s.owner_id=$3 OR ($4<>'' AND s.data->>'team'=$4)))) ORDER BY r.created_at DESC LIMIT 5000`, kind, elevated(u), u.ID, leadTeam(u))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		v, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a.resourceOutput(v))
	}
	return out, rows.Err()
}

func (a *App) listDomain(w http.ResponseWriter, r *http.Request, kind string) {
	if kind == "approvals" {
		cfg, _ := a.setting(r.Context(), "workflow")
		if !boolean(cfg, "approval_enabled") {
			jsonResponse(w, 200, []any{})
			return
		}
	}
	v, err := a.ListResources(r.Context(), kind, currentUser(r))
	if err != nil {
		fail(w, 500, "목록을 불러오지 못했습니다")
		return
	}
	jsonResponse(w, 200, v)
}
func (a *App) getDomain(w http.ResponseWriter, r *http.Request, kind string) {
	v, err := a.resource(r.Context(), kind, r.PathValue("id"))
	if err != nil || !a.canAccess(r.Context(), currentUser(r), v) {
		fail(w, 404, "항목을 찾을 수 없습니다")
		return
	}
	jsonResponse(w, 200, a.resourceOutput(v))
}

func (a *App) saveDomain(w http.ResponseWriter, r *http.Request, kind string, update bool) {
	m := map[string]any{}
	if decode(r, &m) != nil {
		fail(w, 400, "올바른 JSON을 입력하세요")
		return
	}
	u := currentUser(r)
	for _, key := range []string{"name", "title", "description", "evidence", "remediation"} {
		if value, exists := m[key]; exists {
			if _, ok := value.(string); !ok {
				fail(w, 400, key+" 값은 문자열이어야 합니다")
				return
			}
		}
	}
	if kind == "scans" {
		out, err := a.RequestScan(r.Context(), u, m)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		a.audit(r, "scan.request", str(out, "id"), map[string]any{"service_id": m["service_id"]})
		jsonResponse(w, 201, out)
		return
	}
	if kind == "events" {
		a.createEvent(w, r, m)
		return
	}
	v := domainResource{ID: newID(), Kind: kind, OwnerID: u.ID, Data: map[string]any{}}
	if update {
		old, err := a.resource(r.Context(), kind, r.PathValue("id"))
		if err != nil || !a.canAccess(r.Context(), u, old) {
			fail(w, 404, "항목을 찾을 수 없습니다")
			return
		}
		v = old
		if expected, exists := m["expected_updated_at"]; exists {
			raw, ok := expected.(string)
			revision, err := time.Parse(time.RFC3339Nano, raw)
			if !ok || err != nil {
				fail(w, 400, "expected_updated_at에는 조회한 변경 일시를 입력하세요")
				return
			}
			if !revision.Equal(old.UpdatedAt) {
				fail(w, 409, errResourceConflict.Error())
				return
			}
		}
	}
	previousOwner := v.OwnerID
	if owner := str(m, "owner_id"); owner != "" && owner != v.OwnerID {
		if u.Role != "admin" {
			fail(w, 403, "소유자 변경은 관리자만 가능합니다")
			return
		}
		var exists bool
		if a.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND NOT disabled)`, owner).Scan(&exists) != nil || !exists {
			fail(w, 400, "유효한 소유자가 필요합니다")
			return
		}
		v.OwnerID = owner
	}
	for _, k := range []string{"id", "owner_id", "created_at", "updated_at", "expected_updated_at", "observations", "verification", "verified_at", "resolved_at", "evidence_encrypted", "dispatch_state", "dispatch_started_at", "dispatch_http_status", "external_id", "external_url", "external_status", "external_updated_at", "last_synced_at", "sent_at", "credential_key_id", "last_run_at", "last_scan_id", "last_result", "last_error", "policy_version"} {
		delete(m, k)
	}
	oldData := cloneMap(v.Data)
	for k, value := range m {
		v.Data[k] = value
	}
	if err := a.validateResource(r.Context(), u, &v, oldData, update); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if kind == "services" && update && previousOwner != v.OwnerID {
		v.Data["approved"] = false
	}
	if err := a.sealDomainSecrets(&v, oldData, m); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if kind == "schedules" {
		v.Data["credential_key_id"] = ""
		if token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); token != r.Header.Get("Authorization") {
			var keyID string
			if err := a.DB.QueryRow(r.Context(), `SELECT id FROM api_keys WHERE token_hash=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, digest(token), u.ID).Scan(&keyID); err != nil {
				fail(w, 403, "예약 인증 키를 확인할 수 없습니다")
				return
			}
			v.Data["credential_key_id"] = keyID
		}
	}
	if kind == "policies" {
		v.Data["policy_version"] = number(oldData, "policy_version", 0) + 1
	}
	if err := a.persistResource(r.Context(), &v); err != nil {
		if errors.Is(err, errResourceConflict) {
			fail(w, 409, err.Error())
			return
		}
		var conflict *pgconn.PgError
		if errors.As(err, &conflict) && conflict.Code == "23505" && conflict.ConstraintName == "findings_fingerprint" {
			fail(w, 409, "동일한 서비스·위치·취약점의 발견 건이 이미 있습니다. 기존 발견 건을 검색해 확인하세요")
			return
		}
		fail(w, 500, "항목을 저장하지 못했습니다")
		return
	}
	if kind == "policies" {
		a.recordPolicyVersion(r.Context(), v, u.ID)
	}
	a.audit(r, kind+".save", v.ID, map[string]any{"name": v.Data["name"], "title": v.Data["title"]})
	jsonResponse(w, 200, a.resourceOutput(v))
}

func (a *App) persistResource(ctx context.Context, v *domainResource) error {
	raw, err := json.Marshal(v.Data)
	if err != nil {
		return err
	}
	err = a.DB.QueryRow(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data,owner_id=EXCLUDED.owner_id,updated_at=now() WHERE resources.updated_at=$5 RETURNING created_at,updated_at`, v.ID, v.Kind, v.OwnerID, raw, v.UpdatedAt).Scan(&v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return errResourceConflict
	}
	return err
}

func (a *App) validateResource(ctx context.Context, u User, v *domainResource, old map[string]any, update bool) error {
	m := v.Data
	for _, key := range []string{"name", "title", "description", "evidence", "remediation"} {
		if len(str(m, key)) > 100000 {
			return fmt.Errorf("%s 값이 너무 깁니다", key)
		}
	}
	if v.Kind != "findings" && strings.TrimSpace(str(m, "name")) == "" {
		return errors.New("이름을 입력하세요")
	}
	if sid := str(m, "service_id"); sid != "" {
		s, err := a.resource(ctx, "services", sid)
		if err != nil || !a.canAccess(ctx, u, s) {
			return errors.New("접근 가능한 서비스를 선택하세요")
		}
	}
	switch v.Kind {
	case "services":
		if !hasString([]string{"staging", "production", "development"}, str(m, "environment")) {
			return errors.New("환경은 staging, production, development 중 하나입니다")
		}
		if str(m, "criticality") == "" {
			m["criticality"] = "tier3"
		}
		if !hasString([]string{"tier1", "tier2", "tier3", "tier4"}, str(m, "criticality")) {
			return errors.New("중요도는 tier1~tier4 입니다")
		}
		if str(m, "url") != "" {
			if _, err := parseTarget(str(m, "url")); err != nil {
				return err
			}
		}
		if boolean(m, "approved") != boolean(old, "approved") && u.Role != "admin" {
			return errors.New("진단 대상 승인은 관리자만 변경할 수 있습니다")
		}
		// Changed targets must be explicitly authorized again, even for an admin.
		if update {
			for _, key := range []string{"url", "environment", "network", "team", "owner", "criticality", "targets", "repository", "image"} {
				oldJSON, _ := json.Marshal(old[key])
				newJSON, _ := json.Marshal(m[key])
				if string(oldJSON) != string(newJSON) {
					m["approved"] = false
					break
				}
			}
		}
	case "findings":
		if err := validateFindingOpsResource(m); err != nil {
			return err
		}
		if strings.TrimSpace(str(m, "title")) == "" || str(m, "service_id") == "" {
			return errors.New("발견 제목과 서비스가 필요합니다")
		}
		if !hasString([]string{"critical", "high", "medium", "low", "info"}, str(m, "severity")) {
			return errors.New("올바른 심각도를 선택하세요")
		}
		if str(m, "status") == "" {
			m["status"] = "candidate"
		}
		if !hasString([]string{"candidate", "confirmed", "in_progress", "retest", "resolved", "inconclusive", "false_positive", "accepted"}, str(m, "status")) {
			return errors.New("올바른 상태를 선택하세요")
		}
		if str(m, "status") == "resolved" && str(old, "status") != "resolved" {
			return errors.New("해결 상태는 실제 재검증 성공 후에만 설정됩니다. 재검증을 요청하세요")
		}
		if (str(m, "status") == "accepted" || str(m, "status") == "false_positive") && str(m, "decision_reason") == "" && str(m, "remediation") == "" {
			return errors.New("위험 수용 또는 오탐 처리 사유를 입력하세요")
		}
		if str(m, "source") == "" {
			m["source"] = "manual"
		}
		if !update {
			m["source"] = "manual"
			m["fingerprint"] = findingFingerprint(m)
			m["observations"] = []any{}
		} else {
			if str(m, "service_id") != str(old, "service_id") {
				return errors.New("발견 건의 대상 서비스는 변경할 수 없습니다")
			}
			m["fingerprint"] = old["fingerprint"]
			m["source"] = old["source"]
			if str(old, "source") != "manual" {
				for _, key := range []string{"rule_id", "location", "component", "cve"} {
					m[key] = old[key]
				}
			}
		}
		if str(m, "status") == "accepted" {
			expiry, err := time.Parse(time.RFC3339, str(m, "expires_at"))
			if err != nil || !expiry.After(time.Now()) {
				return errors.New("위험 수용 만료 일시(RFC3339)를 입력하세요")
			}
		}
		cfg, _ := a.setting(ctx, "workflow")
		if boolean(cfg, "approval_enabled") && (str(m, "status") == "accepted" || str(m, "status") == "false_positive") && str(old, "status") != str(m, "status") && !managerial(u) {
			return errors.New("검토 프로세스가 켜져 있어 팀장 또는 관리자 판단이 필요합니다")
		}
		// Points are reviewed contributions, never a self-assigned reward.
		if !managerial(u) {
			m["contribution_points"] = old["contribution_points"]
		}
		if number(m, "contribution_points", 0) < 0 || number(m, "contribution_points", 0) > 10000 {
			return errors.New("기여 점수는 0~10000 범위입니다")
		}
	case "scopes":
		return validateScope(m)
	case "policies":
		return validatePolicy(m)
	case "schedules":
		return validateSchedule(m)
	case "integrations":
		return validateIntegration(m)
	case "auth-profiles":
		if containsNestedSecret(m["config"]) {
			return errors.New("config에는 비밀 값을 저장할 수 없습니다. token, password, headers 전용 필드를 사용하세요")
		}
		if str(m, "service_id") == "" {
			return errors.New("인증 프로파일의 대상 서비스가 필요합니다")
		}
		if str(m, "type") == "" {
			m["type"] = "bearer"
		}
		if !hasString([]string{"bearer", "basic", "headers"}, str(m, "type")) {
			return errors.New("인증 방식은 bearer, basic, headers 입니다")
		}
	case "scenarios":
		if str(m, "service_id") == "" {
			return errors.New("권한 검증 대상 서비스를 선택하세요")
		}
		if str(m, "path") == "" {
			return errors.New("검증할 읽기 전용 API 경로를 입력하세요")
		}
		if !strings.HasPrefix(str(m, "path"), "/") || strings.HasPrefix(str(m, "path"), "//") {
			return errors.New("검증 경로는 서비스 내 절대 경로여야 합니다")
		}
		if str(m, "authorized_profile_id") == "" || str(m, "unauthorized_profile_id") == "" {
			return errors.New("정상 사용자와 권한 없는 사용자 인증 프로파일을 지정하세요")
		}
		if str(m, "authorized_profile_id") == str(m, "unauthorized_profile_id") {
			return errors.New("두 역할의 인증 프로파일은 달라야 합니다")
		}
		if str(m, "marker") == "" {
			return errors.New("합성 테스트 데이터 식별 문자열(marker)이 필요합니다")
		}
		if !validScopePath(str(m, "unauthorized_control_path")) || str(m, "unauthorized_control_marker") == "" {
			return errors.New("비교 사용자의 정상 인증을 확인할 자기 데이터 경로와 합성 데이터 식별 문자열이 필요합니다")
		}
		for _, k := range []string{"authorized_profile_id", "unauthorized_profile_id"} {
			p, err := a.resource(ctx, "auth-profiles", str(m, k))
			if err != nil || str(p.Data, "service_id") != str(m, "service_id") {
				return errors.New("동일 서비스에 등록된 인증 프로파일이 필요합니다")
			}
		}
		m["method"] = "GET" // State-changing probes are deliberately unavailable.
	case "remediations":
		if update && hasString([]string{"sending", "sent", "uncertain"}, str(old, "dispatch_state")) && (str(m, "finding_id") != str(old, "finding_id") || str(m, "integration_id") != str(old, "integration_id")) {
			return errors.New("전송된 개선 요청의 발견 건·연동 대상은 변경할 수 없습니다")
		}
		if fid := str(m, "finding_id"); fid != "" {
			f, err := a.resource(ctx, "findings", fid)
			if err != nil || !a.canAccess(ctx, u, f) {
				return errors.New("접근 가능한 발견 항목이 필요합니다")
			}
			m["service_id"] = str(f.Data, "service_id")
		}
		if str(m, "status") == "" {
			m["status"] = "draft"
		}
	}
	return nil
}

func (a *App) sealDomainSecrets(v *domainResource, old, input map[string]any) error {
	if v.Kind == "findings" {
		evidence, provided := input["evidence"].(string)
		if !provided {
			if previous, exists := old["evidence"]; exists {
				if _, valid := previous.(string); !valid {
					raw, err := json.Marshal(previous)
					if err != nil {
						return errors.New("기존 증거 형식을 복구할 수 없습니다")
					}
					evidence = string(raw)
					provided = true
				}
			}
		}
		if provided {
			sealed, err := a.encrypt(maskAgentText(maskEvidence(evidence)))
			if err != nil {
				return err
			}
			v.Data["evidence"] = sealed
			v.Data["evidence_encrypted"] = true
		}
		return nil
	}
	if v.Kind != "integrations" && v.Kind != "auth-profiles" {
		return nil
	}
	for _, k := range []string{"secret", "password", "token", "headers", "cookies", "connection_string"} {
		if boolean(input, "clear_"+k) {
			v.Data[k] = ""
		} else if val, ok := input[k]; ok {
			s, ok := val.(string)
			if !ok {
				if k != "headers" {
					return errors.New("비밀 값은 문자열이어야 합니다")
				}
				raw, err := json.Marshal(val)
				if err != nil {
					return err
				}
				s = string(raw)
			}
			if s == "" {
				v.Data[k] = old[k]
			} else {
				enc, err := a.encrypt(s)
				if err != nil {
					return err
				}
				v.Data[k] = enc
			}
		}
		delete(v.Data, "clear_"+k)
		delete(v.Data, k+"_configured")
	}
	return nil
}

func (a *App) deleteDomain(w http.ResponseWriter, r *http.Request, kind string) {
	v, err := a.resource(r.Context(), kind, r.PathValue("id"))
	if err != nil || !a.canAccess(r.Context(), currentUser(r), v) {
		fail(w, 404, "항목을 찾을 수 없습니다")
		return
	}
	if kind == "services" || kind == "scopes" || kind == "auth-profiles" {
		var used bool
		key := "service_id"
		if kind == "scopes" {
			key = "scope_id"
		}
		if kind == "auth-profiles" {
			key = "authorized_profile_id"
		}
		err = a.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM resources WHERE (data->>$1=$2 OR data->>'unauthorized_profile_id'=$2) AND id<>$2)`, key, v.ID).Scan(&used)
		if err == nil && !used && (kind == "services" || kind == "scopes") {
			err = a.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM agent_runs WHERE service_id=$1 OR scope_id=$1)`, v.ID).Scan(&used)
		}
		if err != nil || used {
			fail(w, 409, "다른 항목에서 참조하고 있습니다. 연결 항목을 먼저 정리하세요")
			return
		}
	}
	if _, err = a.DB.Exec(r.Context(), `DELETE FROM resources WHERE id=$1`, v.ID); err != nil {
		fail(w, 500, "삭제하지 못했습니다")
		return
	}
	a.audit(r, kind+".delete", v.ID, nil)
	jsonResponse(w, 200, map[string]any{"deleted": true})
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	services := []map[string]any{}
	scans := []map[string]any{}
	restricted := []string{}
	if hasString(u.Scopes, "services:read") {
		var err error
		services, err = a.ListResources(r.Context(), "services", u)
		if err != nil {
			fail(w, 500, "통계를 불러오지 못했습니다")
			return
		}
	} else {
		restricted = append(restricted, "services")
	}
	findings, err := a.ListResources(r.Context(), "findings", u)
	if err != nil {
		fail(w, 500, "통계를 불러오지 못했습니다")
		return
	}
	if hasString(u.Scopes, "scans:read") {
		scans, err = a.ListResources(r.Context(), "scans", u)
		if err != nil {
			fail(w, 500, "통계를 불러오지 못했습니다")
			return
		}
	} else {
		restricted = append(restricted, "scans")
	}
	sev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	open := 0
	debt := 0
	critical := 0
	covered := map[string]bool{}
	byStatus := map[string]int{}
	owners := map[string]map[string]any{}
	for _, f := range findings {
		severity, status := str(f, "severity"), str(f, "status")
		sev[severity]++
		byStatus[status]++
		acceptedActive := false
		if status == "accepted" {
			expiry, e := time.Parse(time.RFC3339, str(f, "expires_at"))
			acceptedActive = e == nil && expiry.After(time.Now())
		}
		if status != "resolved" && status != "false_positive" && !acceptedActive {
			open++
			if severity == "critical" {
				critical++
			}
			weight := map[string]int{"critical": 10, "high": 5, "medium": 3, "low": 1, "info": 0}[severity]
			age := 1
			if t, ok := f["created_at"].(time.Time); ok {
				age += int(time.Since(t).Hours()/24) / 30
			}
			debt += weight * age
		}
		if points := number(f, "contribution_points", 0); points > 0 {
			owner := str(f, "owner_id")
			entry := owners[owner]
			if entry == nil {
				entry = map[string]any{"owner_id": owner, "points": 0, "findings": 0}
				owners[owner] = entry
			}
			entry["points"] = number(entry, "points", 0) + points
			entry["findings"] = number(entry, "findings", 0) + 1
		}
	}
	runningScans, queuedScans := 0, 0
	for _, s := range scans {
		if str(s, "status") == "running" {
			runningScans++
		}
		if str(s, "status") == "queued" || str(s, "status") == "pending_approval" {
			queuedScans++
		}
		if str(s, "status") == "completed" {
			covered[str(s, "service_id")] = true
		}
	}
	coverage := 0
	if len(services) > 0 {
		coverage = 100 * len(covered) / len(services)
	}
	contributions := []map[string]any{}
	for _, v := range owners {
		contributions = append(contributions, v)
	}
	sort.Slice(contributions, func(i, j int) bool {
		return number(contributions[i], "points", 0) > number(contributions[j], "points", 0)
	})
	var emergency bool
	_ = a.DB.QueryRow(r.Context(), `SELECT emergency FROM domain_runtime WHERE id=1`).Scan(&emergency)
	jsonResponse(w, 200, map[string]any{"restricted_datasets": restricted, "services": len(services), "findings": len(findings), "open_findings": open, "critical": critical, "scans": len(scans), "running_scans": runningScans, "queued_scans": queuedScans, "coverage": coverage, "coverage_definition": "완료 진단이 1회 이상 있는 서비스 비율 (기능별 보안 보장 아님)", "security_debt": debt, "security_debt_definition": "미해결 심각도 가중치 × (1 + 경과 30일 구간)", "by_severity": sev, "by_status": byStatus, "recent_findings": firstN(findings, 8), "recent_scans": firstN(scans, 8), "contributions": contributions, "emergency_stop": emergency})
}
func firstN(v []map[string]any, n int) []map[string]any {
	if len(v) > n {
		return v[:n]
	}
	return v
}

func (a *App) graph(w http.ResponseWriter, r *http.Request) {
	services, err := a.ListResources(r.Context(), "services", currentUser(r))
	if err != nil {
		fail(w, 500, "관계도를 불러오지 못했습니다")
		return
	}
	findings := []map[string]any{}
	if hasString(currentUser(r).Scopes, "findings:read") {
		findings, _ = a.ListResources(r.Context(), "findings", currentUser(r))
	}
	nodes := []map[string]any{}
	edges := []map[string]any{}
	seen := map[string]bool{}
	add := func(id, label, kind string) {
		if !seen[id] {
			seen[id] = true
			nodes = append(nodes, map[string]any{"id": id, "label": label, "type": kind})
		}
	}
	for _, s := range services {
		id := str(s, "id")
		add(id, str(s, "name"), "service")
		for _, key := range []string{"url", "repository", "image", "team"} {
			if value := str(s, key); value != "" {
				target := key + ":" + value
				add(target, value, key)
				edges = append(edges, map[string]any{"source": id, "target": target, "label": key})
			}
		}
		if targets, ok := s["targets"].([]any); ok {
			for _, target := range targets {
				t, ok := target.(map[string]any)
				if !ok {
					continue
				}
				value, kind := str(t, "value"), str(t, "type")
				if value == "" {
					continue
				}
				tid := kind + ":" + value
				add(tid, value, kind)
				edges = append(edges, map[string]any{"source": id, "target": tid, "label": "공격 표면"})
			}
		}
	}
	for _, f := range findings {
		if str(f, "status") == "resolved" || str(f, "status") == "false_positive" {
			continue
		}
		id := str(f, "id")
		add(id, str(f, "title"), "finding")
		edges = append(edges, map[string]any{"source": str(f, "service_id"), "target": id, "label": str(f, "severity")})
		for _, key := range []string{"cve", "component"} {
			if value := str(f, key); value != "" {
				tid := key + ":" + value
				add(tid, value, key)
				edges = append(edges, map[string]any{"source": id, "target": tid, "label": key})
			}
		}
	}
	jsonResponse(w, 200, map[string]any{"nodes": nodes, "edges": edges})
}

func (a *App) exportReport(w http.ResponseWriter, r *http.Request) {
	findings, err := a.ListResources(r.Context(), "findings", currentUser(r))
	if err != nil {
		fail(w, 500, "내보내기 실패")
		return
	}
	a.audit(r, "reports.export", "findings", map[string]any{"count": len(findings)})
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=hunter-findings.csv")
		_, _ = w.Write([]byte{0xef, 0xbb, 0xbf})
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"ID", "제목", "서비스 ID", "심각도", "상태", "출처", "CVE", "기여 점수"})
		for _, f := range findings {
			_ = cw.Write([]string{csvSafe(str(f, "id")), csvSafe(str(f, "title")), csvSafe(str(f, "service_id")), str(f, "severity"), str(f, "status"), csvSafe(str(f, "source")), csvSafe(str(f, "cve")), strconv.Itoa(number(f, "contribution_points", 0))})
		}
		cw.Flush()
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=hunter-findings.json")
	jsonResponse(w, 200, map[string]any{"generated_at": time.Now().UTC(), "version": a.Version, "findings": findings})
}
func csvSafe(s string) string {
	if s != "" && strings.ContainsAny(s[:1], "=+-@\t\r\n") {
		return "'" + s
	}
	return s
}
