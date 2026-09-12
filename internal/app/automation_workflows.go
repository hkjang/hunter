package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

type workflowChanges struct {
	Paths       []string `json:"paths"`
	APIPaths    []string `json:"api_paths"`
	Components  []string `json:"components"`
	Permissions []string `json:"permissions"`
}
type workflowChangeRule struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Enabled       bool            `json:"enabled"`
	IntegrationID string          `json:"integration_id"`
	ServiceID     string          `json:"service_id"`
	EventTypes    []string        `json:"event_types"`
	Match         workflowChanges `json:"match"`
	Profile       string          `json:"profile"`
	ScopeID       string          `json:"scope_id"`
	ScenarioID    string          `json:"scenario_id"`
}
type workflowTicketFields struct {
	ExternalID          string `json:"external_id"`
	Assignee            string `json:"assignee"`
	DueDate             string `json:"due_date"`
	Status              string `json:"status"`
	UpdatedAt           string `json:"updated_at"`
	DeploymentReference string `json:"deployment_reference"`
	DeploymentConfirmed string `json:"deployment_confirmed"`
}
type workflowTicketRule struct {
	ID                  string               `json:"id"`
	Name                string               `json:"name"`
	Enabled             bool                 `json:"enabled"`
	IntegrationID       string               `json:"integration_id"`
	ServiceID           string               `json:"service_id"`
	PollIntervalMinutes int                  `json:"poll_interval_minutes"`
	ReadURLTemplate     string               `json:"read_url_template"`
	FieldMap            workflowTicketFields `json:"field_map"`
	CompleteStatuses    []string             `json:"complete_statuses"`
	RetestOnDeploy      bool                 `json:"retest_on_deploy"`
	ScopeID             string               `json:"scope_id"`
}
type workflowConfig struct {
	Enabled          bool                 `json:"enabled"`
	ChangeRules      []workflowChangeRule `json:"change_rules"`
	TicketRules      []workflowTicketRule `json:"ticket_rules"`
	SigningSecret    string               `json:"signing_secret"`
	SecretConfigured bool                 `json:"signing_secret_configured"`
	UpdatedAt        time.Time            `json:"updated_at"`
	OwnerID          string               `json:"-"`
	KeyID            string               `json:"-"`
}
type workflowEvent struct {
	IntegrationID string          `json:"integration_id"`
	ServiceID     string          `json:"service_id"`
	EventType     string          `json:"event_type"`
	Reference     string          `json:"reference"`
	Changes       workflowChanges `json:"changes"`
}
type workflowRun struct {
	ID            string         `json:"id"`
	Kind          string         `json:"kind"`
	IntegrationID string         `json:"integration_id"`
	ServiceID     string         `json:"service_id"`
	Reference     string         `json:"reference"`
	Status        string         `json:"status"`
	Result        map[string]any `json:"result"`
	CreatedAt     time.Time      `json:"created_at"`
	Hash          string         `json:"-"`
}

var errWorkflowForbidden = errors.New("자동화 실행에 필요한 현재 권한이 없습니다")
var errWorkflowConflict = errors.New("다른 요청 또는 외부 자료가 변경되었습니다. 최신 자료를 확인하세요")
var workflowEvents = []string{"push", "pull_request", "merge", "image", "harbor_push", "deploy", "api_change", "iam_change", "prompt_change", "manual"}

func (a *App) initWorkflowAutomation(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS workflow_automation_config(id integer PRIMARY KEY CHECK(id=1),encrypted text NOT NULL,owner_id text NOT NULL DEFAULT '',key_id text NOT NULL DEFAULT '',updated_at timestamptz NOT NULL DEFAULT now());
 CREATE TABLE IF NOT EXISTS workflow_automation_runs(id text PRIMARY KEY,kind text NOT NULL,integration_id text NOT NULL,service_id text NOT NULL,reference text NOT NULL,payload_hash text NOT NULL,status text NOT NULL,result_encrypted text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(kind,integration_id,service_id,reference));
 CREATE INDEX IF NOT EXISTS workflow_runs_created ON workflow_automation_runs(created_at DESC);
 CREATE TABLE IF NOT EXISTS workflow_ticket_state(remediation_id text PRIMARY KEY,baseline_encrypted text NOT NULL DEFAULT '',last_external_at timestamptz);
 CREATE TABLE IF NOT EXISTS workflow_ticket_poll(remediation_id text PRIMARY KEY,next_poll_at timestamptz NOT NULL DEFAULT now(),lease_until timestamptz);
 CREATE TABLE IF NOT EXISTS workflow_deploy_retests(remediation_id text NOT NULL,deployment_reference text NOT NULL,scan_id text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(remediation_id,deployment_reference));`)
	if err != nil {
		return err
	}
	cipher, err := a.encrypt(`{"enabled":false,"change_rules":[],"ticket_rules":[],"signing_secret":""}`)
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO workflow_automation_config(id,encrypted) VALUES(1,$1) ON CONFLICT DO NOTHING`, cipher)
	return err
}
func (a *App) registerWorkflowAutomation(m *http.ServeMux) {
	m.HandleFunc("GET /api/workflow-automation", a.protect("admin:manage", a.getWorkflowConfig))
	m.HandleFunc("PUT /api/workflow-automation", a.protect("admin:manage", a.putWorkflowConfig))
	m.HandleFunc("POST /api/workflow-automation/preview", a.protect("admin:manage", a.previewWorkflow))
	m.HandleFunc("GET /api/workflow-automation/runs", a.protect("admin:manage", a.listWorkflowRuns))
	m.HandleFunc("POST /api/workflow-automation/sync", a.protect("admin:manage", a.manualWorkflowSync))
	m.HandleFunc("POST /api/integrations/{id}/tickets/callback", a.protect("integrations:manage", a.workflowTicketCallback))
}
func (a *App) workflowConfig(ctx context.Context) (workflowConfig, error) {
	var cfg workflowConfig
	var cipher string
	var updated time.Time
	err := a.DB.QueryRow(ctx, `SELECT encrypted,owner_id,key_id,updated_at FROM workflow_automation_config WHERE id=1`).Scan(&cipher, &cfg.OwnerID, &cfg.KeyID, &updated)
	if err != nil {
		return cfg, err
	}
	plain, err := a.decrypt(cipher)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal([]byte(plain), &cfg)
	cfg.UpdatedAt = updated
	return cfg, err
}
func workflowPublic(c workflowConfig) workflowConfig {
	c.SecretConfigured = c.SigningSecret != ""
	c.SigningSecret = ""
	return c
}
func (a *App) getWorkflowConfig(w http.ResponseWriter, r *http.Request) {
	c, e := a.workflowConfig(r.Context())
	if e != nil {
		fail(w, 500, "자동화 설정 조회 실패")
		return
	}
	jsonResponse(w, 200, workflowPublic(c))
}
func workflowText(s string, n int) bool {
	return len(s) <= n && !strings.ContainsFunc(s, unicode.IsControl)
}
func (c workflowChanges) groups() [][]string {
	return [][]string{c.Paths, c.APIPaths, c.Components, c.Permissions}
}
func validateWorkflowChanges(c workflowChanges, patterns bool) error {
	total := 0
	for _, g := range c.groups() {
		total += len(g)
		for _, v := range g {
			if strings.TrimSpace(v) == "" || !workflowText(v, 512) {
				return errors.New("변경 경로·식별자는 비어 있지 않은 512바이트 이하 문자열이어야 합니다")
			}
			if patterns {
				if strings.ContainsAny(v, "[]\\") {
					return errors.New("패턴은 *, **, ? 와 일반 문자만 사용하세요")
				}
				if _, err := path.Match(strings.ReplaceAll(v, "**", "*"), "test"); err != nil {
					return errors.New("변경 매칭 패턴이 올바르지 않습니다")
				}
			}
		}
	}
	limit := 1000
	if patterns {
		limit = 100
	}
	if total > limit {
		return fmt.Errorf("변경 항목은 최대 %d개입니다", limit)
	}
	return nil
}
func (a *App) validateWorkflowConfig(ctx context.Context, u User, c *workflowConfig) error {
	if len(c.ChangeRules) > 50 || len(c.TicketRules) > 50 {
		return errors.New("변경 규칙·ITSM 규칙은 각각 최대 50개입니다")
	}
	if c.Enabled && len(c.SigningSecret) < 32 {
		return errors.New("자동화를 켜려면 32바이트 이상의 서명 비밀값이 필요합니다")
	}
	if len(c.SigningSecret) > 16000 {
		return errors.New("서명 비밀값은 16000바이트 이하여야 합니다")
	}
	ids := map[string]bool{}
	targets := map[string]bool{}
	validate := func(id *string, name, iid, sid string) error {
		if *id == "" {
			*id = newID()
		}
		if !workflowText(*id, 100) || ids[*id] || strings.TrimSpace(name) == "" || !workflowText(name, 200) {
			return errors.New("규칙 ID는 중복될 수 없으며 이름은 200바이트 이하여야 합니다")
		}
		ids[*id] = true
		for kind, id := range map[string]string{"integrations": iid, "services": sid} {
			v, e := a.resource(ctx, kind, id)
			if e != nil || !a.canAccess(ctx, u, v) {
				return errors.New("접근 가능한 연동·서비스가 필요합니다")
			}
		}
		return nil
	}
	for i := range c.ChangeRules {
		v := &c.ChangeRules[i]
		if e := validate(&v.ID, v.Name, v.IntegrationID, v.ServiceID); e != nil {
			return e
		}
		if len(v.EventTypes) == 0 || len(v.EventTypes) > len(workflowEvents) {
			return errors.New("변경 이벤트 종류를 선택하세요")
		}
		for _, e := range v.EventTypes {
			if !hasString(workflowEvents, e) {
				return errors.New("지원하지 않는 변경 이벤트입니다")
			}
		}
		if e := validateWorkflowChanges(v.Match, true); e != nil {
			return e
		}
		count := 0
		for _, g := range v.Match.groups() {
			count += len(g)
		}
		if count == 0 {
			return errors.New("최소 한 개의 변경 매칭 조건이 필요합니다")
		}
		if !hasString([]string{"http-baseline", "authorization", "import-only"}, v.Profile) {
			return errors.New("지원하지 않는 진단 프로파일입니다")
		}
		if v.Profile == "authorization" && v.ScenarioID == "" {
			return errors.New("권한 검증 시나리오를 선택하세요")
		}
		if v.Profile != "authorization" && v.ScenarioID != "" {
			return errors.New("시나리오는 권한 프로파일에만 지정하세요")
		}
		integration, _ := a.resource(ctx, "integrations", v.IntegrationID)
		if str(integration.Data, "type") != "webhook" {
			return errors.New("변경 규칙에는 웹훅 연동을 선택하세요")
		}
		for kind, id := range map[string]string{"scopes": v.ScopeID, "scenarios": v.ScenarioID} {
			if id != "" {
				resource, e := a.resource(ctx, kind, id)
				if e != nil || str(resource.Data, "service_id") != v.ServiceID {
					return errors.New("범위·시나리오는 같은 서비스에 속해야 합니다")
				}
			}
		}
	}
	for i := range c.TicketRules {
		v := &c.TicketRules[i]
		if e := validate(&v.ID, v.Name, v.IntegrationID, v.ServiceID); e != nil {
			return e
		}
		key := v.IntegrationID + "/" + v.ServiceID
		if targets[key] {
			return errors.New("ITSM 연동·서비스 조합은 하나의 규칙만 사용할 수 있습니다")
		}
		targets[key] = true
		if v.PollIntervalMinutes == 0 {
			v.PollIntervalMinutes = 15
		}
		if v.PollIntervalMinutes < 5 || v.PollIntervalMinutes > 10080 {
			return errors.New("ITSM 조회 간격은 5~10080분입니다")
		}
		if e := validateTicketURL(v.ReadURLTemplate); e != nil {
			return e
		}
		fields := v.FieldMap
		if fields.ExternalID == "" || fields.Status == "" || fields.UpdatedAt == "" {
			return errors.New("외부 ID·상태·수정 시각 필드 경로가 필요합니다")
		}
		for _, p := range []string{fields.ExternalID, fields.Status, fields.UpdatedAt, fields.Assignee, fields.DueDate, fields.DeploymentReference, fields.DeploymentConfirmed} {
			if len(p) > 200 || p != "" && !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(p) {
				return errors.New("필드 경로는 영문·숫자·밑줄·점으로 설정하세요")
			}
		}
		if len(v.CompleteStatuses) > 20 {
			return errors.New("외부 완료 상태는 최대 20개입니다")
		}
		for _, state := range v.CompleteStatuses {
			if state == "" || !workflowText(state, 100) {
				return errors.New("외부 상태 값은 100바이트 이하여야 합니다")
			}
		}
		if v.RetestOnDeploy && len(v.CompleteStatuses) == 0 {
			return errors.New("재검증을 요청할 외부 완료 상태를 선택하세요")
		}
		if v.RetestOnDeploy && (fields.DeploymentReference == "" || fields.DeploymentConfirmed == "") {
			return errors.New("재검증에는 배포 식별자·확인 필드가 필요합니다")
		}
		if v.ScopeID != "" {
			scope, err := a.resource(ctx, "scopes", v.ScopeID)
			if err != nil || str(scope.Data, "service_id") != v.ServiceID {
				return errors.New("재검증 범위는 같은 서비스에 속해야 합니다")
			}
		}
		integration, _ := a.resource(ctx, "integrations", v.IntegrationID)
		if str(integration.Data, "type") != "rest" {
			return errors.New("ITSM에는 REST 연동을 선택하세요")
		}
		if sid := str(object(integration.Data["config"]), "service_id"); sid != "" && sid != v.ServiceID {
			return errors.New("연동의 허용 서비스와 일치하지 않습니다")
		}
	}
	return nil
}
func validateTicketURL(t string) error {
	if strings.Count(t, "{{external_id}}") != 1 || strings.Contains(strings.ReplaceAll(t, "{{external_id}}", ""), "{{") {
		return errors.New("조회 URL에는 {{external_id}}를 한 번 지정하세요")
	}
	u, e := parseTarget(strings.ReplaceAll(t, "{{external_id}}", "hunter-ticket"))
	if e != nil {
		return e
	}
	if strings.Contains(strings.Split(t, "://")[1][:strings.Index(strings.Split(t, "://")[1]+"/", "/")], "{{") {
		return errors.New("외부 ID는 호스트에 넣을 수 없습니다")
	}
	for k := range u.Query() {
		if secretField(k) {
			return errors.New("조회 URL에 비밀 정보를 넣을 수 없습니다")
		}
	}
	return nil
}
func (a *App) putWorkflowConfig(w http.ResponseWriter, r *http.Request) {
	var input struct {
		workflowConfig
		Expected string `json:"expected_updated_at"`
		Clear    bool   `json:"clear_secret"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "자동화 설정 JSON을 확인하세요")
		return
	}
	old, e := a.workflowConfig(r.Context())
	if e != nil {
		fail(w, 500, "자동화 설정 조회 실패")
		return
	}
	rev, e := time.Parse(time.RFC3339Nano, input.Expected)
	if e != nil {
		fail(w, 400, "조회한 updated_at을 expected_updated_at으로 전달하세요")
		return
	}
	if !rev.Equal(old.UpdatedAt) {
		fail(w, 409, errWorkflowConflict.Error())
		return
	}
	if input.Clear && input.SigningSecret != "" {
		fail(w, 400, "비밀 교체와 삭제는 함께 사용할 수 없습니다")
		return
	}
	if input.SigningSecret == "" && !input.Clear {
		input.SigningSecret = old.SigningSecret
	}
	c := input.workflowConfig
	if e = a.validateWorkflowConfig(r.Context(), currentUser(r), &c); e != nil {
		fail(w, 400, e.Error())
		return
	}
	c.UpdatedAt = time.Time{}
	raw, _ := json.Marshal(c)
	cipher, e := a.encrypt(string(raw))
	if e != nil {
		fail(w, 500, "자동화 설정 암호화 실패")
		return
	}
	u := currentUser(r)
	e = a.DB.QueryRow(r.Context(), `UPDATE workflow_automation_config SET encrypted=$1,owner_id=$2,key_id=$3,updated_at=now() WHERE id=1 AND updated_at=$4 RETURNING updated_at`, cipher, u.ID, u.KeyID, rev).Scan(&c.UpdatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		fail(w, 409, errWorkflowConflict.Error())
		return
	}
	if e != nil {
		fail(w, 500, "자동화 설정 저장 실패")
		return
	}
	a.audit(r, "workflow_automation.save", "1", map[string]any{"enabled": c.Enabled, "change_rules": len(c.ChangeRules), "ticket_rules": len(c.TicketRules)})
	jsonResponse(w, 200, workflowPublic(c))
}
func workflowScopes(u User, scopes ...string) error {
	for _, s := range scopes {
		if !hasString(u.Scopes, s) {
			return errWorkflowForbidden
		}
	}
	return nil
}
func (a *App) workflowPrincipal(ctx context.Context, c workflowConfig) (User, error) {
	var u User
	e := a.DB.QueryRow(ctx, `SELECT id,username,name,role,team FROM users WHERE id=$1 AND NOT disabled`, c.OwnerID).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	if e != nil {
		return u, e
	}
	u.Scopes = a.roleScopes(ctx, u.Role)
	u.KeyID = c.KeyID
	if c.KeyID != "" {
		var scopes []string
		if e = a.DB.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, c.KeyID, u.ID).Scan(&scopes); e != nil {
			return u, e
		}
		var effective []string
		for _, s := range u.Scopes {
			if hasString(scopes, s) {
				effective = append(effective, s)
			}
		}
		u.Scopes = effective
	}
	return u, workflowScopes(u, "admin:manage", "integrations:manage", "services:read", "findings:read", "findings:write")
}
func (a *App) workflowAccess(ctx context.Context, u User, iid, sid string) error {
	if e := workflowScopes(u, "integrations:manage", "services:read"); e != nil {
		return e
	}
	for kind, id := range map[string]string{"integrations": iid, "services": sid} {
		v, e := a.resource(ctx, kind, id)
		if e != nil || !a.canAccess(ctx, u, v) {
			return errors.New("현재 연동·서비스 접근 권한이 없습니다")
		}
		if kind == "integrations" {
			if !boolean(v.Data, "enabled") {
				return errors.New("연동이 비활성화되었습니다")
			}
			if bound := str(object(v.Data["config"]), "service_id"); bound != "" && bound != sid {
				return errors.New("연동에 허용되지 않은 서비스입니다")
			}
		}
	}
	return nil
}
func (a *App) workflowSignedBody(r *http.Request, c workflowConfig) ([]byte, error) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || len(c.SigningSecret) < 32 {
		return nil, errors.New("개인 API 키와 자동화 서명이 필요합니다")
	}
	stamp := r.Header.Get("X-Hunter-Timestamp")
	ts, e := strconv.ParseInt(stamp, 10, 64)
	if e != nil || time.Since(time.Unix(ts, 0)) > 5*time.Minute || time.Until(time.Unix(ts, 0)) > 5*time.Minute {
		return nil, errors.New("서명 시각이 허용 범위를 벗어났습니다")
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		return nil, errors.New("자동화 본문은 1 MiB 이하여야 합니다")
	}
	mac := hmac.New(sha256.New, []byte(c.SigningSecret))
	mac.Write([]byte(stamp + "\n"))
	mac.Write(raw)
	signature, e := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-Hunter-Signature"), "sha256="))
	if e != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, errors.New("자동화 서명이 올바르지 않습니다")
	}
	return raw, nil
}
func workflowCipher(a *App, v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	return a.encrypt(string(b))
}
func (a *App) workflowExisting(ctx context.Context, kind, iid, sid, ref string) (workflowRun, error) {
	var v workflowRun
	var encrypted string
	e := a.DB.QueryRow(ctx, `SELECT id,kind,integration_id,service_id,reference,payload_hash,status,result_encrypted,created_at FROM workflow_automation_runs WHERE kind=$1 AND integration_id=$2 AND service_id=$3 AND reference=$4`, kind, iid, sid, ref).Scan(&v.ID, &v.Kind, &v.IntegrationID, &v.ServiceID, &v.Reference, &v.Hash, &v.Status, &encrypted, &v.CreatedAt)
	if e == nil {
		plain, err := a.decrypt(encrypted)
		if err != nil {
			return v, err
		}
		e = json.Unmarshal([]byte(plain), &v.Result)
	}
	return v, e
}
func (a *App) workflowInsert(ctx context.Context, tx pgx.Tx, v *workflowRun) error {
	cipher, e := workflowCipher(a, v.Result)
	if e != nil {
		return e
	}
	return tx.QueryRow(ctx, `INSERT INTO workflow_automation_runs(id,kind,integration_id,service_id,reference,payload_hash,status,result_encrypted) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`, v.ID, v.Kind, v.IntegrationID, v.ServiceID, v.Reference, v.Hash, v.Status, cipher).Scan(&v.CreatedAt)
}
func (a *App) listWorkflowRuns(w http.ResponseWriter, r *http.Request) {
	if e := workflowScopes(currentUser(r), "integrations:manage", "services:read", "findings:read", "scans:read"); e != nil {
		fail(w, 403, e.Error())
		return
	}
	q := r.URL.Query()
	pageN, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("size"))
	if pageN < 1 {
		pageN = 1
	}
	if pageN > 1000000 {
		pageN = 1000000
	}
	if size < 1 || size > 100 {
		size = 25
	}
	kind, status := q.Get("kind"), q.Get("status")
	var total int
	if e := a.DB.QueryRow(r.Context(), `SELECT count(*) FROM workflow_automation_runs WHERE ($1='' OR kind=$1) AND ($2='' OR status=$2)`, kind, status).Scan(&total); e != nil {
		fail(w, 500, "자동화 이력 조회 실패")
		return
	}
	rows, e := a.DB.Query(r.Context(), `SELECT id,kind,integration_id,service_id,reference,status,result_encrypted,created_at FROM workflow_automation_runs WHERE ($1='' OR kind=$1) AND ($2='' OR status=$2) ORDER BY created_at DESC,id DESC LIMIT $3 OFFSET $4`, kind, status, size, (pageN-1)*size)
	if e != nil {
		fail(w, 500, "자동화 이력 조회 실패")
		return
	}
	defer rows.Close()
	items := []workflowRun{}
	for rows.Next() {
		var v workflowRun
		var encrypted string
		if e = rows.Scan(&v.ID, &v.Kind, &v.IntegrationID, &v.ServiceID, &v.Reference, &v.Status, &encrypted, &v.CreatedAt); e != nil {
			break
		}
		plain, err := a.decrypt(encrypted)
		if err != nil {
			e = err
			break
		}
		if e = json.Unmarshal([]byte(plain), &v.Result); e != nil {
			break
		}
		items = append(items, v)
	}
	if e != nil || rows.Err() != nil {
		fail(w, 500, "자동화 이력 조회 실패")
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "page": pageN, "page_size": size})
}

// URL interpolation is limited to an escaped ticket identifier, never a hostname.
func workflowTicketURL(template, id string) (string, error) {
	if id == "" || !workflowText(id, 200) || strings.Contains(id, "..") || !regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}._:-]*$`).MatchString(id) {
		return "", errors.New("외부 티켓 식별자가 올바르지 않습니다")
	}
	if e := validateTicketURL(template); e != nil {
		return "", e
	}
	return strings.ReplaceAll(template, "{{external_id}}", url.PathEscape(id)), nil
}
