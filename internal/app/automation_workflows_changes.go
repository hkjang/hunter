package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

func workflowGlob(pattern, value string) bool {
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, `\*\*`, "\x00")
	quoted = strings.ReplaceAll(quoted, `\*`, `[^/]*`)
	quoted = strings.ReplaceAll(quoted, `\?`, `[^/]`)
	quoted = strings.ReplaceAll(quoted, "\x00", `.*`)
	ok, _ := regexp.MatchString("^"+quoted+"$", value)
	return ok
}
func workflowMatches(patterns, changes workflowChanges) workflowChanges {
	out := make([][]string, 4)
	for i, g := range changes.groups() {
		seen := map[string]bool{}
		for _, value := range g {
			for _, p := range patterns.groups()[i] {
				if workflowGlob(p, value) && !seen[value] {
					out[i] = append(out[i], value)
					seen[value] = true
					break
				}
			}
		}
	}
	return workflowChanges{out[0], out[1], out[2], out[3]}
}
func workflowMatchCount(c workflowChanges) int {
	n := 0
	for _, g := range c.groups() {
		n += len(g)
	}
	return n
}
func validateWorkflowEvent(e workflowEvent) error {
	if !hasString(workflowEvents, e.EventType) {
		return errors.New("지원하는 변경 이벤트 종류가 필요합니다")
	}
	if e.ServiceID == "" || e.IntegrationID == "" {
		return errors.New("연동과 서비스를 지정하세요")
	}
	return validateWorkflowChanges(e.Changes, false)
}
func (a *App) workflowDecisions(ctx context.Context, u User, c workflowConfig, event workflowEvent) ([]map[string]any, []*preparedScan, error) {
	if err := validateWorkflowEvent(event); err != nil {
		return nil, nil, err
	}
	if err := a.workflowAccess(ctx, u, event.IntegrationID, event.ServiceID); err != nil {
		return nil, nil, err
	}
	decisions := []map[string]any{}
	prepared := []*preparedScan{}
	seen := map[string]string{}
	for _, rule := range c.ChangeRules {
		if !rule.Enabled || rule.ServiceID != event.ServiceID || rule.IntegrationID != event.IntegrationID || !hasString(rule.EventTypes, event.EventType) {
			continue
		}
		matches := workflowMatches(rule.Match, event.Changes)
		if workflowMatchCount(matches) == 0 {
			continue
		}
		item := map[string]any{"rule_id": rule.ID, "rule_name": rule.Name, "profile": rule.Profile, "scenario_id": rule.ScenarioID, "scope_id": rule.ScopeID, "matched_changes": matches, "allowed": false, "reason": ""}
		key := rule.Profile + "\n" + rule.ScopeID + "\n" + rule.ScenarioID
		if id := seen[key]; id != "" {
			item["reason"] = "같은 검사 대상이 다른 규칙에서 이미 선택되었습니다"
			item["duplicate_of_rule_id"] = id
			decisions = append(decisions, item)
			continue
		}
		seen[key] = rule.ID
		err := workflowScopes(u, "scans:read", "scans:write")
		var p *preparedScan
		if err == nil {
			p, err = a.prepareScan(ctx, u, map[string]any{"service_id": event.ServiceID, "profile": rule.Profile, "scope_id": rule.ScopeID, "scenario_id": rule.ScenarioID}, "", "")
		}
		if err != nil {
			item["reason"] = err.Error()
		} else if len(prepared) >= 20 {
			item["reason"] = "한 이벤트의 검사 한도 20개를 초과했습니다"
		} else {
			item["allowed"] = true
			item["scan_id"] = p.ID
			p.Data["change_rule_id"] = rule.ID
			p.Data["change_reference"] = event.Reference
			prepared = append(prepared, p)
		}
		decisions = append(decisions, item)
	}
	return decisions, prepared, nil
}
func (a *App) previewWorkflow(w http.ResponseWriter, r *http.Request) {
	var event workflowEvent
	if decode(r, &event) != nil {
		fail(w, 400, "미리보기 변경 목록을 확인하세요")
		return
	}
	c, e := a.workflowConfig(r.Context())
	if e != nil {
		fail(w, 500, "자동화 설정 조회 실패")
		return
	}
	decisions, prepared, e := a.workflowDecisions(r.Context(), currentUser(r), c, event)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	for _, d := range decisions {
		delete(d, "scan_id")
	}
	jsonResponse(w, 200, map[string]any{"matched": decisions, "scan_count": len(prepared), "enabled": c.Enabled, "preview": true})
}
func (a *App) runWorkflowChange(ctx context.Context, u User, c workflowConfig, event workflowEvent) (workflowRun, bool, error) {
	v := workflowRun{}
	if !c.Enabled {
		return v, false, errors.New("변경 자동화가 비활성화되어 있습니다")
	}
	if !workflowText(event.Reference, 200) || strings.TrimSpace(event.Reference) == "" {
		return v, false, errors.New("멱등 처리를 위한 200바이트 이하 reference가 필요합니다")
	}
	if err := a.workflowAccess(ctx, u, event.IntegrationID, event.ServiceID); err != nil {
		return v, false, err
	}
	if err := workflowScopes(u, "scans:read", "scans:write"); err != nil {
		return v, false, err
	}
	raw, _ := json.Marshal(event)
	hash := digest(string(raw))
	if old, e := a.workflowExisting(ctx, "change", event.IntegrationID, event.ServiceID, event.Reference); e == nil {
		if old.Hash != hash {
			return old, true, errWorkflowConflict
		}
		return old, true, nil
	}
	decisions, prepared, e := a.workflowDecisions(ctx, u, c, event)
	if e != nil {
		return v, false, e
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return v, false, e
	}
	defer tx.Rollback(ctx)
	// Serialize one event identity and re-read the immutable result, not a second DB connection.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "change/"+event.IntegrationID+"/"+event.ServiceID+"/"+event.Reference); e != nil {
		return v, false, e
	}
	var id, oldHash string
	e = tx.QueryRow(ctx, `SELECT id,payload_hash FROM workflow_automation_runs WHERE kind='change' AND integration_id=$1 AND service_id=$2 AND reference=$3`, event.IntegrationID, event.ServiceID, event.Reference).Scan(&id, &oldHash)
	if e == nil {
		tx.Rollback(ctx)
		if oldHash != hash {
			return v, true, errWorkflowConflict
		}
		old, err := a.workflowExisting(ctx, "change", event.IntegrationID, event.ServiceID, event.Reference)
		return old, true, err
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return v, false, e
	}
	if e = workflowConfigRevision(ctx, tx, c); e != nil {
		return v, false, e
	}
	if e = workflowAccessTx(ctx, tx, u, event.IntegrationID, event.ServiceID); e != nil {
		return v, false, e
	}
	scanIDs := []string{}
	v = workflowRun{ID: newID(), Kind: "change", IntegrationID: event.IntegrationID, ServiceID: event.ServiceID, Reference: event.Reference, Hash: hash, Status: "completed"}
	for _, p := range prepared {
		p.Data["automation_run_id"] = v.ID
		if _, e = a.insertPreparedScan(ctx, tx, u, p); e != nil {
			return v, false, e
		}
		scanIDs = append(scanIDs, p.ID)
	}
	if len(decisions) == 0 {
		v.Status = "no_match"
	} else if len(prepared) == 0 {
		v.Status = "blocked"
	} else {
		for _, d := range decisions {
			if !asBool(d["allowed"]) && str(d, "duplicate_of_rule_id") == "" {
				v.Status = "partial"
			}
		}
	}
	v.Result = map[string]any{"event_type": event.EventType, "changes": event.Changes, "decisions": decisions, "scan_ids": scanIDs}
	if e = a.workflowInsert(ctx, tx, &v); e != nil {
		return v, false, e
	}
	if e = workflowAuditTx(ctx, tx, u, "workflow.change", v.ID, map[string]any{"service_id": v.ServiceID, "status": v.Status, "scan_count": len(scanIDs)}); e != nil {
		return v, false, e
	}
	e = tx.Commit(ctx)
	return v, false, e
}
func workflowConfigRevision(ctx context.Context, tx pgx.Tx, c workflowConfig) error {
	var valid bool
	e := tx.QueryRow(ctx, `SELECT updated_at=$1 FROM workflow_automation_config WHERE id=1 FOR SHARE`, c.UpdatedAt).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return errWorkflowConflict
	}
	return nil
}
func workflowAccessTx(ctx context.Context, tx pgx.Tx, u User, iid, sid string) error {
	var id string
	if e := tx.QueryRow(ctx, `SELECT id FROM resources WHERE id=$1 AND kind='services' AND ($2 OR owner_id=$3 OR ($4<>'' AND data->>'team'=$4)) FOR SHARE`, sid, elevated(u), u.ID, leadTeam(u)).Scan(&id); e != nil {
		return errors.New("서비스 접근 권한이 변경되었습니다")
	}
	var data map[string]any
	var owner string
	if e := tx.QueryRow(ctx, `SELECT owner_id,data FROM resources WHERE id=$1 AND kind='integrations' FOR SHARE`, iid).Scan(&owner, &data); e != nil || !boolean(data, "enabled") || !elevated(u) && owner != u.ID {
		return errors.New("연동 권한·상태가 변경되었습니다")
	}
	if bound := str(object(data["config"]), "service_id"); bound != "" && bound != sid {
		return errors.New("연동 허용 서비스가 변경되었습니다")
	}
	var enabled bool
	if e := tx.QueryRow(ctx, `SELECT NOT disabled AND role=$2 AND team=$3 FROM users WHERE id=$1 FOR SHARE`, u.ID, u.Role, u.Team).Scan(&enabled); e != nil || !enabled {
		return errors.New("사용자 권한이 변경되었습니다")
	}
	if u.Role != "admin" {
		var roles map[string]any
		if err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key='roles' FOR SHARE`).Scan(&roles); err != nil {
			return errors.New("현재 역할 설정을 확인할 수 없습니다")
		}
		current := stringList(roles[u.Role])
		for _, scope := range u.Scopes {
			if !hasString(current, scope) {
				return errors.New("역할 권한 설정이 변경되었습니다")
			}
		}
	}
	if u.KeyID != "" {
		var scopes []string
		if e := tx.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() FOR SHARE`, u.KeyID, u.ID).Scan(&scopes); e != nil {
			return errors.New("실행 API 키를 사용할 수 없습니다")
		}
		for _, s := range u.Scopes {
			if !hasString(scopes, s) {
				return errors.New("API 키 권한이 변경되었습니다")
			}
		}
	}
	return nil
}
func workflowAuditTx(ctx context.Context, tx pgx.Tx, u User, action, target string, detail any) error {
	raw, _ := json.Marshal(detail)
	_, e := tx.Exec(ctx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,$3,$4,$5,$6)`, newID(), u.ID, u.Username, action, target, raw)
	return e
}

func (a *App) workflowChangeWebhook(w http.ResponseWriter, r *http.Request, integration domainResource, input map[string]any, raw []byte) bool {
	c, e := a.workflowConfig(r.Context())
	_, hasChanges := input["changes"]
	configured := false
	if e == nil && c.Enabled {
		for _, rule := range c.ChangeRules {
			if rule.Enabled && rule.IntegrationID == integration.ID {
				configured = true
				break
			}
		}
	}
	if _, assets := input["assets"]; assets && !hasChanges {
		return false
	}
	if !hasChanges && !configured {
		return false
	}
	if e != nil || !c.Enabled {
		fail(w, 400, "변경 영향 자동화가 비활성화되어 있습니다")
		return true
	}
	if !hasChanges {
		fail(w, 400, "이 연동은 실제 changes 목록을 전달해야 합니다")
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if _, e = a.workflowSignedBody(r, c); e != nil {
		fail(w, 401, e.Error())
		return true
	}
	var changes workflowChanges
	encoded, _ := json.Marshal(input["changes"])
	if json.Unmarshal(encoded, &changes) != nil {
		fail(w, 400, "changes에는 paths/api_paths/components/permissions 문자열 배열이 필요합니다")
		return true
	}
	event := workflowEvent{IntegrationID: integration.ID, ServiceID: str(input, "service_id"), EventType: firstString(input, "event_type", "type"), Reference: firstString(input, "reference", "event_id"), Changes: changes}
	v, duplicate, e := a.runWorkflowChange(r.Context(), currentUser(r), c, event)
	if e != nil {
		code := 400
		if errors.Is(e, errWorkflowConflict) {
			code = 409
		} else if errors.Is(e, errWorkflowForbidden) {
			code = 403
		}
		fail(w, code, e.Error())
		return true
	}
	code := 201
	if duplicate {
		code = 200
	}
	jsonResponse(w, code, map[string]any{"run": v, "duplicate": duplicate})
	return true
}
