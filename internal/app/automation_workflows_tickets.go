package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type workflowSyncRequest struct {
	RemediationID    string `json:"remediation_id"`
	Expected         string `json:"expected_updated_at"`
	AcceptExternal   bool   `json:"accept_external"`
	ExpectedFinding  string `json:"expected_finding_updated_at"`
	ExpectedExternal string `json:"expected_external_updated_at"`
}
type workflowTicket struct {
	ID                  string    `json:"id"`
	Status              string    `json:"status"`
	UpdatedAt           time.Time `json:"updated_at"`
	Assignee            *string   `json:"assignee,omitempty"`
	DueDate             *string   `json:"due_date,omitempty"`
	DeploymentReference string    `json:"deployment_reference"`
	DeploymentConfirmed bool      `json:"deployment_confirmed"`
}

func workflowTicketMap(payload map[string]any, f workflowTicketFields) (workflowTicket, error) {
	var t workflowTicket
	t.ID = asString(fieldPath(payload, f.ExternalID))
	t.Status = asString(fieldPath(payload, f.Status))
	stamp, ok := fieldPath(payload, f.UpdatedAt).(string)
	var e error
	if !ok {
		return t, errors.New("외부 수정 시각은 RFC3339 문자열이어야 합니다")
	}
	t.UpdatedAt, e = time.Parse(time.RFC3339Nano, stamp)
	if e != nil || t.UpdatedAt.After(time.Now().Add(5*time.Minute)) {
		return t, errors.New("외부 수정 시각은 미래가 아닌 RFC3339 형식이어야 합니다")
	}
	if t.ID == "" || !workflowText(t.ID, 200) || t.Status == "" || !workflowText(t.Status, 100) {
		return t, errors.New("외부 ID·상태 값이 올바르지 않습니다")
	}
	for key, p := range map[string]string{"assignee": f.Assignee, "due_date": f.DueDate} {
		if p == "" {
			continue
		}
		value := fieldPath(payload, p)
		if value == nil {
			continue
		}
		s, ok := value.(string)
		if !ok || !workflowText(s, 200) {
			return t, errors.New("외부 담당자·기한은 200바이트 이하 문자열이어야 합니다")
		}
		s = strings.TrimSpace(s)
		if key == "assignee" {
			t.Assignee = &s
		} else {
			if e = validateFindingOpsResource(map[string]any{"due_date": s}); e != nil {
				return t, e
			}
			t.DueDate = &s
		}
	}
	if f.DeploymentReference != "" {
		t.DeploymentReference = asString(fieldPath(payload, f.DeploymentReference))
		if !workflowText(t.DeploymentReference, 200) {
			return t, errors.New("배포 식별자는 200바이트 이하여야 합니다")
		}
	}
	if f.DeploymentConfirmed != "" {
		v := fieldPath(payload, f.DeploymentConfirmed)
		if v != nil {
			var ok bool
			t.DeploymentConfirmed, ok = v.(bool)
			if !ok {
				return t, errors.New("배포 확인 필드는 JSON boolean이어야 합니다")
			}
		}
	}
	return t, nil
}
func (a *App) workflowReadTicket(ctx context.Context, rule workflowTicketRule, integration domainResource, externalID string) (map[string]any, error) {
	endpoint, e := workflowTicketURL(rule.ReadURLTemplate, externalID)
	if e != nil {
		return nil, e
	}
	source, e := parseTarget(str(integration.Data, "endpoint"))
	if e != nil {
		return nil, errors.New("REST 연동 주소를 확인하세요")
	}
	target, _ := url.Parse(endpoint)
	if source.Scheme != target.Scheme || !strings.EqualFold(source.Host, target.Host) {
		return nil, errors.New("조회 주소는 인증 정보가 등록된 REST 연동과 같은 출처여야 합니다")
	}
	client, e := a.outboundClient(ctx, 10*time.Second)
	if e != nil {
		return nil, errors.New("사내 인증서 설정을 확인하세요")
	}
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("ITSM 조회 리다이렉트는 허용하지 않습니다")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept", "application/json")
	if cipher := str(integration.Data, "secret"); cipher != "" {
		plain, err := a.decrypt(cipher)
		if err != nil {
			return nil, errors.New("연동 인증 정보를 읽을 수 없습니다")
		}
		req.Header.Set("Authorization", "Bearer "+plain)
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, errors.New("ITSM 읽기 연결에 실패했습니다. 주소·인증·인증서를 확인하세요")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ITSM 조회 HTTP %d", resp.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		return nil, errors.New("ITSM 응답은 1 MiB 이하여야 합니다")
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil || payload == nil {
		return nil, errors.New("ITSM JSON 객체 응답이 필요합니다")
	}
	return payload, nil
}
func (a *App) workflowTicketContext(ctx context.Context, u User, c workflowConfig, id string) (domainResource, domainResource, domainResource, workflowTicketRule, error) {
	var rule workflowTicketRule
	rem, e := a.resource(ctx, "remediations", id)
	var f, integration domainResource
	if e != nil || !a.canAccess(ctx, u, rem) {
		return rem, f, integration, rule, errors.New("접근 가능한 개선 요청이 없습니다")
	}
	if e = workflowScopes(u, "findings:read", "findings:write"); e != nil {
		return rem, f, integration, rule, e
	}
	f, e = a.resource(ctx, "findings", str(rem.Data, "finding_id"))
	if e != nil || !a.canAccess(ctx, u, f) || str(rem.Data, "service_id") != str(f.Data, "service_id") {
		return rem, f, integration, rule, errors.New("같은 서비스의 현재 발견 건이 필요합니다")
	}
	sid := str(f.Data, "service_id")
	iid := str(rem.Data, "integration_id")
	if e = a.workflowAccess(ctx, u, iid, sid); e != nil {
		return rem, f, integration, rule, e
	}
	if str(rem.Data, "external_id") == "" || str(rem.Data, "dispatch_state") != "sent" {
		return rem, f, integration, rule, errors.New("외부 티켓 ID가 확인된 발신 완료 개선 요청만 동기화할 수 있습니다")
	}
	integration, e = a.resource(ctx, "integrations", iid)
	if e != nil || str(integration.Data, "type") != "rest" {
		return rem, f, integration, rule, errors.New("REST 연동이 필요합니다")
	}
	for _, v := range c.TicketRules {
		if v.Enabled && v.IntegrationID == iid && v.ServiceID == sid {
			return rem, f, integration, v, nil
		}
	}
	return rem, f, integration, rule, errors.New("활성화된 ITSM 동기화 규칙이 없습니다")
}
func (a *App) workflowFailure(ctx context.Context, u User, rem domainResource, reason string) (workflowRun, error) {
	v := workflowRun{ID: newID(), Kind: "ticket_sync", IntegrationID: str(rem.Data, "integration_id"), ServiceID: str(rem.Data, "service_id"), Reference: rem.ID + "/failure/" + newID(), Hash: digest(reason), Status: "blocked", Result: map[string]any{"remediation_id": rem.ID, "reason": reason, "scan_ids": []string{}}}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return v, e
	}
	defer tx.Rollback(ctx)
	if e = a.workflowInsert(ctx, tx, &v); e != nil {
		return v, e
	}
	if e = workflowAuditTx(ctx, tx, u, "workflow.ticket_sync", v.ID, map[string]any{"status": "blocked", "remediation_id": rem.ID}); e != nil {
		return v, e
	}
	return v, tx.Commit(ctx)
}
func (a *App) syncWorkflowTicket(ctx context.Context, u User, c workflowConfig, input workflowSyncRequest, payload map[string]any) (workflowRun, error) {
	var zero workflowRun
	if !c.Enabled {
		return zero, errors.New("ITSM 자동화가 비활성화되어 있습니다")
	}
	rem, f, integration, rule, e := a.workflowTicketContext(ctx, u, c, input.RemediationID)
	if e != nil {
		return zero, e
	}
	if input.Expected != "" {
		rev, err := time.Parse(time.RFC3339Nano, input.Expected)
		if err != nil || !rev.Equal(rem.UpdatedAt) {
			return zero, errWorkflowConflict
		}
	}
	if input.AcceptExternal {
		rev, err := time.Parse(time.RFC3339Nano, input.ExpectedFinding)
		if err != nil || !rev.Equal(f.UpdatedAt) {
			return zero, errWorkflowConflict
		}
	}
	if payload == nil {
		payload, e = a.workflowReadTicket(ctx, rule, integration, str(rem.Data, "external_id"))
		if e != nil {
			return a.workflowFailure(ctx, u, rem, e.Error())
		}
	}
	ticket, e := workflowTicketMap(payload, rule.FieldMap)
	if e != nil {
		return a.workflowFailure(ctx, u, rem, e.Error())
	}
	if ticket.ID != str(rem.Data, "external_id") {
		return a.workflowFailure(ctx, u, rem, "응답 외부 티켓 ID가 개선 요청과 다릅니다")
	}
	raw, _ := json.Marshal(ticket)
	hash := digest(string(raw))
	ref := rem.ID + "@" + ticket.UpdatedAt.UTC().Format(time.RFC3339Nano)
	if input.AcceptExternal {
		rev, err := time.Parse(time.RFC3339Nano, input.ExpectedExternal)
		if err != nil || !rev.Equal(ticket.UpdatedAt) {
			return zero, errWorkflowConflict
		}
		// Bind an override to the exact external values returned by the original
		// synchronization, including providers that reuse a modification timestamp.
		reviewed, err := a.workflowExisting(ctx, "ticket_sync", integration.ID, str(f.Data, "service_id"), ref)
		if err != nil || reviewed.Hash != hash {
			return zero, errWorkflowConflict
		}
		ref += "/override/" + input.ExpectedFinding
	}
	if old, err := a.workflowExisting(ctx, "ticket_sync", integration.ID, str(f.Data, "service_id"), ref); err == nil {
		if old.Hash != hash {
			return old, errWorkflowConflict
		}
		return old, nil
	}
	var prepared *preparedScan
	scanReason := ""
	if rule.RetestOnDeploy && hasString(rule.CompleteStatuses, ticket.Status) && ticket.DeploymentConfirmed && ticket.DeploymentReference != "" {
		if e = workflowScopes(u, "scans:read", "scans:write"); e != nil {
			scanReason = e.Error()
		} else {
			prepared, e = a.prepareScan(ctx, u, map[string]any{"service_id": str(f.Data, "service_id"), "profile": "http-baseline", "scope_id": rule.ScopeID, "finding_id": f.ID}, "", "")
			if e != nil {
				scanReason = e.Error()
			}
		}
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return zero, e
	}
	defer tx.Rollback(ctx)
	if e = workflowConfigRevision(ctx, tx, c); e != nil {
		return zero, e
	}
	if e = workflowAccessTx(ctx, tx, u, integration.ID, str(f.Data, "service_id")); e != nil {
		return zero, e
	}
	lockedRem, e := scanResource(tx.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind='remediations' AND id=$1 FOR UPDATE`, rem.ID))
	if e != nil {
		return zero, errWorkflowConflict
	}
	lockedFinding, e := scanResource(tx.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind='findings' AND id=$1 FOR UPDATE`, f.ID))
	if e != nil {
		return zero, errWorkflowConflict
	}
	// A second callback may have been waiting on the same remediation lock.
	var existing string
	err := tx.QueryRow(ctx, `SELECT id FROM workflow_automation_runs WHERE kind='ticket_sync' AND integration_id=$1 AND service_id=$2 AND reference=$3`, integration.ID, str(f.Data, "service_id"), ref).Scan(&existing)
	if err == nil {
		tx.Rollback(ctx)
		old, e := a.workflowExisting(ctx, "ticket_sync", integration.ID, str(f.Data, "service_id"), ref)
		if old.Hash != hash {
			return old, errWorkflowConflict
		}
		return old, e
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return zero, err
	}
	if !lockedRem.UpdatedAt.Equal(rem.UpdatedAt) || !lockedFinding.UpdatedAt.Equal(f.UpdatedAt) {
		return zero, errWorkflowConflict
	}
	if _, e = tx.Exec(ctx, `INSERT INTO workflow_ticket_state(remediation_id) VALUES($1) ON CONFLICT DO NOTHING`, rem.ID); e != nil {
		return zero, e
	}
	var baselineCipher string
	var lastAt *time.Time
	if e = tx.QueryRow(ctx, `SELECT baseline_encrypted,last_external_at FROM workflow_ticket_state WHERE remediation_id=$1 FOR UPDATE`, rem.ID).Scan(&baselineCipher, &lastAt); e != nil {
		return zero, e
	}
	baseline := map[string]any{}
	if baselineCipher != "" {
		plain, err := a.decrypt(baselineCipher)
		if err != nil {
			return zero, err
		}
		if e = json.Unmarshal([]byte(plain), &baseline); e != nil {
			return zero, e
		}
	}
	v := workflowRun{ID: newID(), Kind: "ticket_sync", IntegrationID: integration.ID, ServiceID: str(f.Data, "service_id"), Reference: ref, Hash: hash, Status: "completed"}
	patch := map[string]any{}
	if ticket.Assignee != nil {
		patch["assignee"] = *ticket.Assignee
	}
	if ticket.DueDate != nil {
		patch["due_date"] = *ticket.DueDate
	}
	reason := ""
	conflicts := []string{}
	if lastAt != nil && ticket.UpdatedAt.Before(*lastAt) {
		v.Status = "unchanged"
		reason = "현재 반영한 외부 자료보다 오래된 수정 시각입니다"
	}
	for k, value := range patch {
		current := str(lockedFinding.Data, k)
		remote := value.(string)
		old, known := baseline[k].(string)
		if remote != current && (!known && current != "" || known && current != old) && !input.AcceptExternal {
			conflicts = append(conflicts, k)
		}
	}
	if len(conflicts) > 0 && v.Status != "unchanged" {
		v.Status = "conflict"
		reason = "로컬 담당자·기한이 변경되어 자동으로 덮어쓰지 않았습니다"
	}
	scanIDs := []string{}
	if v.Status == "completed" {
		updatedFinding := cloneMap(lockedFinding.Data)
		for k, value := range patch {
			updatedFinding[k] = value
		}
		patchRaw, _ := json.Marshal(updatedFinding)
		if _, e = tx.Exec(ctx, `UPDATE resources SET data=$2,updated_at=now() WHERE id=$1`, f.ID, patchRaw); e != nil {
			return zero, e
		}
		if _, e = tx.Exec(ctx, `UPDATE resources SET data=data||jsonb_build_object('external_status',$2::text,'external_updated_at',$3::text,'last_synced_at',now()),updated_at=now() WHERE id=$1`, rem.ID, ticket.Status, ticket.UpdatedAt.UTC().Format(time.RFC3339Nano)); e != nil {
			return zero, e
		}
		nextBaseline := map[string]any{"assignee": str(updatedFinding, "assignee"), "due_date": str(updatedFinding, "due_date")}
		cipher, e := workflowCipher(a, nextBaseline)
		if e != nil {
			return zero, e
		}
		if _, e = tx.Exec(ctx, `UPDATE workflow_ticket_state SET baseline_encrypted=$2,last_external_at=$3 WHERE remediation_id=$1`, rem.ID, cipher, ticket.UpdatedAt); e != nil {
			return zero, e
		}
		if prepared != nil {
			var previousScan string
			err := tx.QueryRow(ctx, `SELECT scan_id FROM workflow_deploy_retests WHERE remediation_id=$1 AND deployment_reference=$2`, rem.ID, ticket.DeploymentReference).Scan(&previousScan)
			if errors.Is(err, pgx.ErrNoRows) {
				prepared.Data["automation_run_id"] = v.ID
				prepared.Data["deployment_reference"] = ticket.DeploymentReference
				if _, e = a.insertPreparedScan(ctx, tx, u, prepared); e != nil {
					return zero, e
				}
				if _, e = tx.Exec(ctx, `INSERT INTO workflow_deploy_retests(remediation_id,deployment_reference,scan_id) VALUES($1,$2,$3)`, rem.ID, ticket.DeploymentReference, prepared.ID); e != nil {
					return zero, e
				}
				scanIDs = append(scanIDs, prepared.ID)
			} else if err != nil {
				return zero, err
			} else {
				scanReason = "같은 배포 확인으로 이미 재검증을 요청했습니다"
			}
		}
	}
	v.Result = map[string]any{"remediation_id": rem.ID, "finding_id": f.ID, "external_status": ticket.Status, "external_updated_at": ticket.UpdatedAt, "changes": patch, "reason": reason, "conflicts": conflicts, "scan_ids": scanIDs, "retest_reason": scanReason, "finding_status_changed": false}
	if e = a.workflowInsert(ctx, tx, &v); e != nil {
		return zero, e
	}
	if e = workflowAuditTx(ctx, tx, u, "workflow.ticket_sync", v.ID, map[string]any{"remediation_id": rem.ID, "status": v.Status, "scan_count": len(scanIDs)}); e != nil {
		return zero, e
	}
	return v, tx.Commit(ctx)
}
func (a *App) manualWorkflowSync(w http.ResponseWriter, r *http.Request) {
	var input workflowSyncRequest
	if decode(r, &input) != nil || input.Expected == "" {
		fail(w, 400, "개선 요청 ID와 조회한 expected_updated_at이 필요합니다")
		return
	}
	c, e := a.workflowConfig(r.Context())
	if e != nil {
		fail(w, 500, "자동화 설정 조회 실패")
		return
	}
	v, e := a.syncWorkflowTicket(r.Context(), currentUser(r), c, input, nil)
	if e != nil {
		code := 400
		if errors.Is(e, errWorkflowConflict) {
			code = 409
		} else if errors.Is(e, errWorkflowForbidden) {
			code = 403
		}
		fail(w, code, e.Error())
		return
	}
	jsonResponse(w, 200, v)
}
func (a *App) workflowTicketCallback(w http.ResponseWriter, r *http.Request) {
	c, e := a.workflowConfig(r.Context())
	if e != nil || !c.Enabled {
		fail(w, 400, "자동화가 비활성화되어 있습니다")
		return
	}
	raw, e := a.workflowSignedBody(r, c)
	if e != nil {
		fail(w, 401, e.Error())
		return
	}
	var input struct {
		RemediationID string         `json:"remediation_id"`
		Ticket        map[string]any `json:"ticket"`
	}
	if json.Unmarshal(raw, &input) != nil || input.Ticket == nil {
		fail(w, 400, "remediation_id와 ticket JSON이 필요합니다")
		return
	}
	rem, e := a.resource(r.Context(), "remediations", input.RemediationID)
	if e != nil || str(rem.Data, "integration_id") != r.PathValue("id") {
		fail(w, 404, "이 연동의 개선 요청을 찾을 수 없습니다")
		return
	}
	v, e := a.syncWorkflowTicket(r.Context(), currentUser(r), c, workflowSyncRequest{RemediationID: input.RemediationID}, input.Ticket)
	if e != nil {
		code := 400
		if errors.Is(e, errWorkflowConflict) {
			code = 409
		} else if errors.Is(e, errWorkflowForbidden) {
			code = 403
		}
		fail(w, code, e.Error())
		return
	}
	jsonResponse(w, 200, v)
}

// WorkflowAutomationTick is called only by the controller. A row lease keeps
// multiple controllers from polling the same ticket concurrently; GET is replay safe.
func (a *App) WorkflowAutomationTick(ctx context.Context) error {
	c, e := a.workflowConfig(ctx)
	if e != nil || !c.Enabled {
		return e
	}
	u, e := a.workflowPrincipal(ctx, c)
	if e != nil {
		return e
	}
	pairs := []map[string]string{}
	for _, rule := range c.TicketRules {
		if rule.Enabled {
			pairs = append(pairs, map[string]string{"integration_id": rule.IntegrationID, "service_id": rule.ServiceID})
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	pairJSON, _ := json.Marshal(pairs)
	rows, e := a.DB.Query(ctx, `SELECT r.id,r.data FROM resources r LEFT JOIN workflow_ticket_poll p ON p.remediation_id=r.id WHERE r.kind='remediations' AND r.data->>'dispatch_state'='sent' AND coalesce(r.data->>'external_id','')<>'' AND (p.next_poll_at IS NULL OR p.next_poll_at<=now()) AND (p.lease_until IS NULL OR p.lease_until<now()) AND EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) x(integration_id text,service_id text) WHERE x.integration_id=r.data->>'integration_id' AND x.service_id=r.data->>'service_id') ORDER BY coalesce(p.next_poll_at,'-infinity'::timestamptz),r.id LIMIT 100`, pairJSON)
	if e != nil {
		return e
	}
	type candidate struct {
		id   string
		data map[string]any
	}
	candidates := []candidate{}
	for rows.Next() {
		var v candidate
		if e = rows.Scan(&v.id, &v.data); e != nil {
			break
		}
		candidates = append(candidates, v)
	}
	rows.Close()
	if e != nil {
		return e
	}
	processed := 0
	for _, item := range candidates {
		interval := 0
		for _, rule := range c.TicketRules {
			if rule.Enabled && rule.IntegrationID == str(item.data, "integration_id") && rule.ServiceID == str(item.data, "service_id") {
				interval = rule.PollIntervalMinutes
				break
			}
		}
		if interval == 0 {
			continue
		}
		_, e = a.DB.Exec(ctx, `INSERT INTO workflow_ticket_poll(remediation_id) VALUES($1) ON CONFLICT DO NOTHING`, item.id)
		if e != nil {
			return e
		}
		var id string
		e = a.DB.QueryRow(ctx, `UPDATE workflow_ticket_poll SET lease_until=now()+interval '1 minute',next_poll_at=now()+$2*interval '1 minute' WHERE remediation_id=$1 AND next_poll_at<=now() AND (lease_until IS NULL OR lease_until<now()) RETURNING remediation_id`, item.id, interval).Scan(&id)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return e
		}
		_, runErr := a.syncWorkflowTicket(ctx, u, c, workflowSyncRequest{RemediationID: id}, nil)
		_, _ = a.DB.Exec(ctx, `UPDATE workflow_ticket_poll SET lease_until=NULL WHERE remediation_id=$1`, id)
		processed++
		if runErr != nil {
			return runErr
		}
		if processed >= 10 {
			break
		}
	}
	return nil
}
