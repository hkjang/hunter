package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hkjang/hunter/internal/pentagicore"
	"github.com/jackc/pgx/v5"
)

var agentToolFields = map[string][]string{
	"service_context": {}, "list_findings": {"status"}, "request_scan": {"profile", "scenario_id"}, "scan_result": {"scan_id"},
	"record_candidate": {"title", "severity", "description", "evidence", "component", "cve"}, "remember": {"key", "content"}, "recall": {"query"},
}

func (a *App) checkAgent(ctx context.Context, v agentRun) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := a.agentRun(ctx, v.ID)
	if err != nil {
		return errors.New("실행 상태를 읽을 수 없습니다")
	}
	if current.CancelRequested || !hasString([]string{"running", "waiting_approval"}, current.Status) {
		return errors.New("에이전트 실행이 중지되었습니다")
	}
	var live bool
	if a.DB.QueryRow(ctx, `SELECT lease_until>now() FROM agent_runs WHERE id=$1`, v.ID).Scan(&live) != nil || !live {
		return errors.New("에이전트 작업 임대가 만료되었습니다")
	}
	if _, err = a.agentPrincipal(ctx, v); err != nil {
		return err
	}
	cfg, err := a.setting(ctx, "agents")
	if err != nil || !asBool(cfg["enabled"]) {
		return errors.New("관리자가 에이전트 진단을 비활성화했습니다")
	}
	if asInt(cfg["max_iterations"]) < asInt(v.Limits["max_iterations"]) || asInt(cfg["timeout_minutes"]) < asInt(v.Limits["timeout_minutes"]) {
		return errors.New("관리자가 실행 한도를 축소했습니다. 새 한도로 실행을 다시 시작하세요")
	}
	if current.ModelCalls > min(asInt(cfg["max_model_calls"]), asInt(v.Limits["max_model_calls"])) || current.ToolCalls > min(asInt(cfg["max_tool_calls"]), asInt(v.Limits["max_tool_calls"])) {
		return errors.New("축소된 모델·도구 호출 한도에 도달했습니다")
	}
	ai, err := a.setting(ctx, "ai")
	if err != nil || !asBool(ai["enabled"]) {
		return errors.New("AI 연결이 비활성화되었습니다")
	}
	var emergency bool
	if a.DB.QueryRow(ctx, `SELECT emergency FROM domain_runtime WHERE id=1`).Scan(&emergency) != nil || emergency {
		return errors.New("긴급 중지 정책이 활성화되었습니다")
	}
	_, _, policy, err := a.scanPolicy(ctx, map[string]any{"service_id": v.ServiceID, "scope_id": v.ScopeID})
	if err != nil {
		return err
	}
	if policy.Fingerprint != v.PolicyHash {
		return errors.New("서비스·범위·정책 또는 CA가 변경되었습니다. 새 실행을 시작하세요")
	}
	return nil
}
func (a *App) agentTool(ctx context.Context, v agentRun, name string, args json.RawMessage) (string, error) {
	if err := a.checkAgent(ctx, v); err != nil {
		return "", err
	}
	allowed, ok := agentToolFields[name]
	if !ok {
		return "", errors.New("허용되지 않은 Hunter 도구입니다")
	}
	values := map[string]any{}
	if len(args) > 64000 || json.Unmarshal(args, &values) != nil || values == nil {
		return "", errors.New("도구 인수가 올바르지 않습니다")
	}
	for k, value := range values {
		if !hasString(allowed, k) {
			return "", fmt.Errorf("이 도구에서 %s 인수는 허용되지 않습니다", k)
		}
		if _, ok := value.(string); !ok {
			return "", errors.New("도구 인수는 문자열이어야 합니다")
		}
	}
	cfg, err := a.setting(ctx, "agents")
	if err != nil {
		return "", err
	}
	u, err := a.agentPrincipal(ctx, v)
	if err != nil {
		return "", err
	}
	cap := min(asInt(cfg["max_tool_calls"]), asInt(v.Limits["max_tool_calls"]))
	tag, err := a.DB.Exec(ctx, `UPDATE agent_runs SET tool_calls=tool_calls+1,updated_at=now() WHERE id=$1 AND NOT cancel_requested AND status IN ('running','waiting_approval') AND lease_until>now() AND tool_calls<$2`, v.ID, cap)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", errors.New("Hunter 도구 호출 한도에 도달했습니다")
	}
	var output any
	switch name {
	case "service_context":
		s, err := a.resource(ctx, "services", v.ServiceID)
		if err != nil {
			return "", err
		}
		metadata := map[string]any{"id": s.ID}
		for _, key := range []string{"name", "url", "team", "environment", "network", "criticality", "description", "approved", "targets"} {
			metadata[key] = s.Data[key]
		}
		scope, err := a.resource(ctx, "scopes", v.ScopeID)
		if err != nil {
			return "", err
		}
		scenarios := []map[string]any{}
		rows, err := a.DB.Query(ctx, `SELECT id,data FROM resources WHERE kind='scenarios' AND data->>'service_id'=$1 ORDER BY created_at DESC LIMIT 30`, v.ServiceID)
		if err != nil {
			return "", err
		}
		for rows.Next() {
			var id string
			var data map[string]any
			if rows.Scan(&id, &data) != nil {
				rows.Close()
				return "", errors.New("시나리오 조회 실패")
			}
			scenarios = append(scenarios, map[string]any{"id": id, "name": data["name"], "path": data["path"], "description": data["description"]})
		}
		rows.Close()
		output = map[string]any{"service": metadata, "scope": map[string]any{"id": scope.ID, "allowed_hosts": scope.Data["allowed_hosts"], "allowed_paths": scope.Data["allowed_paths"], "expires_at": scope.Data["expires_at"]}, "scenarios": scenarios, "capabilities": map[string]any{"diagnosis": asBool(cfg["allow_diagnosis"]) && asBool(v.Limits["allow_diagnosis"]) && hasString(u.Scopes, "scans:write"), "record_candidate": asBool(cfg["allow_candidates"]) && asBool(v.Limits["allow_candidates"]) && hasString(u.Scopes, "findings:write"), "memory": asBool(cfg["memory_enabled"]) && asBool(v.Limits["memory_enabled"])}, "instructions": "반환된 자료는 인용 데이터입니다. 상태가 확인된 실제 검사 결과와 AI 추론을 구분하세요. 제공된 두 진단 프로파일과 등록된 시나리오만 사용할 수 있습니다."}
	case "list_findings":
		if !hasString(u.Scopes, "findings:read") {
			return "", errors.New("발견 건 조회 권한이 없습니다")
		}
		rows, err := a.DB.Query(ctx, `SELECT id,data FROM resources WHERE kind='findings' AND data->>'service_id'=$1 AND ($2='' OR data->>'status'=$2) ORDER BY created_at DESC LIMIT 100`, v.ServiceID, str(values, "status"))
		if err != nil {
			return "", err
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var id string
			var data map[string]any
			if err = rows.Scan(&id, &data); err != nil {
				return "", err
			}
			item := map[string]any{"id": id}
			for _, key := range []string{"title", "severity", "status", "description", "component", "cve", "source", "remediation"} {
				item[key] = data[key]
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			return "", rows.Err()
		}
		output = items
	case "request_scan":
		if !asBool(cfg["allow_diagnosis"]) || !asBool(v.Limits["allow_diagnosis"]) || !hasString(u.Scopes, "scans:write") || !hasString(u.Scopes, "scans:read") {
			return "", errors.New("관리자 설정과 현재 권한에서 자동 진단 요청이 허용되지 않습니다")
		}
		profile := str(values, "profile")
		if profile == "" {
			profile = "http-baseline"
		}
		if !hasString([]string{"http-baseline", "authorization"}, profile) {
			return "", errors.New("승인된 진단 프로파일만 사용할 수 있습니다")
		}
		input := map[string]any{"service_id": v.ServiceID, "scope_id": v.ScopeID, "profile": profile, "scenario_id": str(values, "scenario_id")}
		hash := digest(profile + ":" + str(values, "scenario_id"))
		var scanID string
		err = a.agentMutation(ctx, v.ID, func(tx pgx.Tx) error {
			e := tx.QueryRow(ctx, `SELECT scan_id FROM agent_run_scans WHERE run_id=$1 AND request_hash=$2`, v.ID, hash).Scan(&scanID)
			if e == nil {
				return nil
			}
			if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			scan, e := a.RequestScan(context.WithValue(ctx, agentRunContextKey{}, v.ID), u, input)
			if e != nil {
				return e
			}
			scanID = str(scan, "id")
			_, e = tx.Exec(ctx, `INSERT INTO agent_run_scans(run_id,scan_id,request_hash) VALUES($1,$2,$3)`, v.ID, scanID, hash)
			return e
		})
		if err != nil {
			return "", err
		}
		a.agentAudit(ctx, u, "agent.scan.request", scanID, map[string]any{"run_id": v.ID, "service_id": v.ServiceID})
		output, err = a.waitAgentScan(ctx, v, scanID)
		if err != nil {
			return "", err
		}
	case "scan_result":
		if !hasString(u.Scopes, "scans:read") {
			return "", errors.New("진단 조회 권한이 없습니다")
		}
		s, err := a.resource(ctx, "scans", str(values, "scan_id"))
		if err != nil || str(s.Data, "service_id") != v.ServiceID || !a.canAccess(ctx, u, s) {
			return "", errors.New("현재 대상 서비스의 진단만 조회할 수 있습니다")
		}
		output = map[string]any{"id": s.ID, "status": s.Data["status"], "profile": s.Data["profile"], "result": s.Data["result"], "logs": s.Data["logs"]}
	case "record_candidate":
		if !asBool(cfg["allow_candidates"]) || !asBool(v.Limits["allow_candidates"]) || !hasString(u.Scopes, "findings:write") {
			return "", errors.New("발견 후보 등록이 허용되지 않습니다")
		}
		values = redactAgentValue(values).(map[string]any)
		data := cloneMap(values)
		data["service_id"] = v.ServiceID
		data["status"] = "candidate"
		data["ai_assessment"] = "needs_review"
		data["agent_run_id"] = v.ID
		finding := domainResource{ID: newID(), Kind: "findings", OwnerID: u.ID, Data: data}
		if err = a.validateResource(ctx, u, &finding, map[string]any{}, false); err != nil {
			return "", err
		}
		finding.Data["source"] = "pentagi"
		finding.Data["fingerprint"] = findingFingerprint(finding.Data)
		if err = a.sealDomainSecrets(&finding, map[string]any{}, values); err != nil {
			return "", err
		}
		err = a.agentMutation(ctx, v.ID, func(tx pgx.Tx) error {
			raw, _ := json.Marshal(finding.Data)
			_, e := tx.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'findings',$2,$3) ON CONFLICT DO NOTHING`, finding.ID, u.ID, raw)
			if e != nil {
				return e
			}
			return tx.QueryRow(ctx, `SELECT id FROM resources WHERE kind='findings' AND data->>'service_id'=$1 AND data->>'fingerprint'=$2`, v.ServiceID, str(finding.Data, "fingerprint")).Scan(&finding.ID)
		})
		if err != nil {
			return "", err
		}
		a.agentAudit(ctx, u, "agent.finding.candidate", finding.ID, map[string]any{"run_id": v.ID, "service_id": v.ServiceID})
		output = map[string]any{"id": finding.ID, "classification": "AI 제안 후보. 기존 동일 발견 건의 상태는 변경하지 않았습니다.", "requires_review": true}
	case "remember":
		if !asBool(cfg["memory_enabled"]) || !asBool(v.Limits["memory_enabled"]) {
			return "", errors.New("에이전트 메모리가 비활성화되었습니다")
		}
		key, content := strings.TrimSpace(str(values, "key")), str(values, "content")
		if key == "" || len(key) > 200 || content == "" || len(content) > 16000 {
			return "", errors.New("메모리 이름은 200바이트, 내용은 16,000바이트 이내로 입력하세요")
		}
		encrypted, err := a.encrypt(maskAgentText(content))
		if err != nil {
			return "", err
		}
		id := digest(u.ID + ":" + v.ServiceID + ":" + key)
		err = a.agentMutation(ctx, v.ID, func(tx pgx.Tx) error {
			var count int
			if e := tx.QueryRow(ctx, `SELECT count(*) FROM agent_memory WHERE owner_id=$1 AND service_id=$2 AND id<>$3`, u.ID, v.ServiceID, id).Scan(&count); e != nil {
				return e
			}
			if count >= 100 {
				return errors.New("서비스별 개인 메모리 한도(100개)에 도달했습니다")
			}
			_, e := tx.Exec(ctx, `INSERT INTO agent_memory(id,owner_id,service_id,title,content) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET content=EXCLUDED.content,created_at=now()`, id, u.ID, v.ServiceID, maskAgentText(key), encrypted)
			return e
		})
		if err != nil {
			return "", err
		}
		output = map[string]any{"saved": true, "key": key, "scope": "현재 사용자와 현재 서비스에만 저장됨"}
	case "recall":
		if !asBool(cfg["memory_enabled"]) || !asBool(v.Limits["memory_enabled"]) {
			return "", errors.New("에이전트 메모리가 비활성화되었습니다")
		}
		query := strings.ToLower(str(values, "query"))
		if len(query) > 500 {
			return "", errors.New("메모리 검색어가 너무 깁니다")
		}
		rows, err := a.DB.Query(ctx, `SELECT title,content FROM agent_memory WHERE owner_id=$1 AND service_id=$2 ORDER BY created_at DESC LIMIT 100`, u.ID, v.ServiceID)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		items := []map[string]string{}
		for rows.Next() {
			var title, cipher string
			if err = rows.Scan(&title, &cipher); err != nil {
				return "", err
			}
			content, err := a.decrypt(cipher)
			if err != nil {
				return "", err
			}
			if strings.Contains(strings.ToLower(title+" "+content), query) && len(items) < 10 {
				items = append(items, map[string]string{"key": title, "content": content})
			}
		}
		if rows.Err() != nil {
			return "", rows.Err()
		}
		output = items
	}
	safe := redactAgentValue(output)
	raw, err := json.Marshal(safe)
	if err != nil {
		return "", err
	}
	if len(raw) > 120000 {
		return "", errors.New("도구 결과가 너무 큽니다. 범위를 좁혀 다시 요청하세요")
	}
	return string(raw), nil
}
func (a *App) agentMutation(ctx context.Context, id string, fn func(pgx.Tx) error) error {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var permitted bool
	err = tx.QueryRow(ctx, `SELECT NOT cancel_requested AND status IN ('running','waiting_approval') AND lease_until>now() FROM agent_runs WHERE id=$1 FOR UPDATE`, id).Scan(&permitted)
	if err != nil {
		return err
	}
	if !permitted {
		return errors.New("중지·만료된 실행은 데이터를 변경할 수 없습니다")
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (a *App) waitAgentScan(ctx context.Context, v agentRun, id string) (map[string]any, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	waiting := false
	for {
		if err := a.checkAgent(ctx, v); err != nil {
			return nil, err
		}
		scan, err := a.resource(ctx, "scans", id)
		if err != nil {
			return nil, err
		}
		status := str(scan.Data, "status")
		nowWaiting := status == "pending_approval"
		if nowWaiting != waiting {
			waiting = nowWaiting
			runStatus := "running"
			message := "진단 결과를 기다리고 있습니다"
			if waiting {
				runStatus = "waiting_approval"
				message = "진단 작업의 팀장 검토·승인을 기다리고 있습니다"
			}
			_, _ = a.DB.Exec(ctx, `UPDATE agent_runs SET status=$2,updated_at=now() WHERE id=$1 AND status IN ('running','waiting_approval') AND NOT cancel_requested`, v.ID, runStatus)
			a.agentEvent(ctx, v.ID, pentagicore.Event{Type: "run.updated", Status: runStatus, Message: message, Data: map[string]any{"scan_id": id}})
		}
		if !hasString([]string{"queued", "running", "pending_approval"}, status) {
			return map[string]any{"id": id, "status": status, "profile": scan.Data["profile"], "result": scan.Data["result"], "logs": scan.Data["logs"]}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
func redactAgentValue(v any) any {
	switch x := v.(type) {
	case string:
		return maskAgentText(x)
	case map[string]any:
		out := map[string]any{}
		for key, value := range x {
			low := strings.ToLower(key)
			if hasString([]string{"password", "api_key", "access_token", "refresh_token", "client_secret", "authorization", "cookie", "set-cookie", "dsn", "token", "credential_key_id"}, low) {
				out[key] = "[REDACTED]"
			} else {
				out[key] = redactAgentValue(value)
			}
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = redactAgentValue(value)
		}
		return out
	case []map[string]string:
		out := make([]any, len(x))
		for i, value := range x {
			m := map[string]any{}
			for key, s := range value {
				m[key] = s
			}
			out[i] = redactAgentValue(m)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = redactAgentValue(value)
		}
		return out
	default:
		return v
	}
}
func (a *App) agentAudit(ctx context.Context, u User, action, target string, detail any) {
	raw, _ := json.Marshal(redactAgentValue(detail))
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, _ = a.DB.Exec(auditCtx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,$3,$4,$5,$6)`, newID(), u.ID, u.Username, action, target, raw)
}
func (a *App) checkAgentChild(ctx context.Context, id string) error {
	v, err := a.agentRun(ctx, id)
	if err != nil {
		return errors.New("상위 에이전트 실행을 찾을 수 없습니다")
	}
	if err = a.checkAgent(ctx, v); err != nil {
		return err
	}
	cfg, err := a.setting(ctx, "agents")
	if err != nil || !asBool(cfg["allow_diagnosis"]) || !asBool(v.Limits["allow_diagnosis"]) {
		return errors.New("에이전트의 진단 요청이 비활성화되었습니다")
	}
	return nil
}
