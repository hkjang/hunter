package app

import (
	"context"
	"encoding/base64"
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

func (a *App) RequestScan(ctx context.Context, u User, input map[string]any) (map[string]any, error) {
	return a.requestScan(ctx, u, input, "", "")
}

func (a *App) requestScan(ctx context.Context, u User, input map[string]any, scheduleID, occurrence string) (map[string]any, error) {
	s, err := a.resource(ctx, "services", str(input, "service_id"))
	if err != nil || !a.canAccess(ctx, u, s) {
		return nil, errors.New("접근 가능한 서비스가 필요합니다")
	}
	profile := str(input, "profile")
	if profile == "" {
		profile = "http-baseline"
	}
	if !hasString([]string{"http-baseline", "import-only", "authorization"}, profile) {
		return nil, errors.New("지원하지 않는 진단 프로파일입니다")
	}
	var emergency bool
	if err = a.DB.QueryRow(ctx, `SELECT emergency FROM domain_runtime WHERE id=1`).Scan(&emergency); err != nil {
		return nil, err
	}
	if emergency {
		return nil, errors.New("긴급 중지가 활성화되어 있습니다")
	}
	scopeID := ""
	if profile != "import-only" {
		_, scope, _, err := a.scanPolicy(ctx, input)
		if err != nil {
			return nil, err
		}
		scopeID = scope.ID
	}
	if profile == "authorization" {
		scenario, err := a.resource(ctx, "scenarios", str(input, "scenario_id"))
		if err != nil || str(scenario.Data, "service_id") != s.ID || !a.canAccess(ctx, u, scenario) {
			return nil, errors.New("서비스에 연결된 권한 검증 시나리오가 필요합니다")
		}
		if str(s.Data, "environment") == "production" {
			return nil, errors.New("권한 시나리오는 검증계 또는 개발계에서만 실행할 수 있습니다")
		}
	}
	if fid := str(input, "finding_id"); fid != "" {
		f, err := a.resource(ctx, "findings", fid)
		if err != nil || str(f.Data, "service_id") != s.ID || !a.canAccess(ctx, u, f) {
			return nil, errors.New("동일 서비스의 발견 건이 필요합니다")
		}
		if profile != "http-baseline" || str(f.Data, "source") != "http-baseline" {
			return nil, errors.New("자동 해결 검증은 HTTP 기준 검사로 발견한 보안 헤더 항목만 지원합니다. 다른 도구 결과는 관찰 기록으로 수입하세요")
		}
	}
	status := "queued"
	jobStatus := "ready"
	cfg, err := a.setting(ctx, "workflow")
	if err != nil {
		return nil, errors.New("워크플로 설정을 불러올 수 없습니다")
	}
	if boolean(cfg, "approval_enabled") {
		status = "pending_approval"
		jobStatus = "blocked"
	}
	if profile == "import-only" {
		status = "awaiting_import"
	}
	id := newID()
	m := map[string]any{"name": str(s.Data, "name") + " 진단", "service_id": s.ID, "service_name": str(s.Data, "name"), "profile": profile, "scope_id": scopeID, "scenario_id": str(input, "scenario_id"), "finding_id": str(input, "finding_id"), "status": status, "logs": []string{}, "result": map[string]any{}, "requested_by": u.ID}
	if scheduleID != "" {
		m["schedule_id"] = scheduleID
		m["schedule_occurrence"] = occurrence
	}
	m["credential_key_id"] = u.KeyID
	if runID, ok := ctx.Value(agentRunContextKey{}).(string); ok && runID != "" {
		m["agent_run_id"] = runID
	}
	if profile == "import-only" {
		m["logs"] = []string{"스캐너가 내보낸 JSON 결과를 /api/imports에서 수입하세요. 외부 엔진은 실행되지 않았습니다."}
	}
	raw, _ := json.Marshal(m)
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var created, updated time.Time
	if err = tx.QueryRow(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'scans',$2,$3) RETURNING created_at,updated_at`, id, u.ID, raw).Scan(&created, &updated); err != nil {
		return nil, err
	}
	if profile != "import-only" {
		if _, err = tx.Exec(ctx, `INSERT INTO scan_jobs(scan_id,status) VALUES($1,$2)`, id, jobStatus); err != nil {
			return nil, err
		}
		if status == "pending_approval" {
			approval, _ := json.Marshal(map[string]any{"name": str(s.Data, "name") + " 진단 검토", "scan_id": id, "service_id": s.ID, "status": "pending", "requested_by": u.ID})
			if _, err = tx.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'approvals',$2,$3)`, newID(), u.ID, approval); err != nil {
				return nil, err
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	m["id"] = id
	m["owner_id"] = u.ID
	m["created_at"] = created
	m["updated_at"] = updated
	delete(m, "credential_key_id")
	return m, nil
}

func (a *App) cancelScan(w http.ResponseWriter, r *http.Request) {
	s, err := a.resource(r.Context(), "scans", r.PathValue("id"))
	if err != nil || !a.canAccess(r.Context(), currentUser(r), s) {
		fail(w, 404, "진단을 찾을 수 없습니다")
		return
	}
	if !hasString([]string{"queued", "running", "pending_approval", "awaiting_import"}, str(s.Data, "status")) {
		fail(w, 409, "종료된 진단은 취소할 수 없습니다")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "취소할 수 없습니다")
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `UPDATE scan_jobs SET status='cancelled',lease_until=NULL WHERE scan_id=$1 AND status IN ('ready','leased','blocked')`, s.ID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE resources SET data=data||jsonb_build_object('status','cancelled','finished_at',now()),updated_at=now() WHERE id=$1 AND data->>'status' IN ('queued','running','pending_approval','awaiting_import')`, s.ID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE resources SET data=data||' {"status":"cancelled"}'::jsonb,updated_at=now() WHERE kind='approvals' AND data->>'scan_id'=$1 AND data->>'status'='pending'`, s.ID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "취소할 수 없습니다")
		return
	}
	a.audit(r, "scan.cancel", s.ID, nil)
	jsonResponse(w, 200, map[string]any{"status": "cancelled"})
}

func (a *App) approveScan(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.setting(r.Context(), "workflow")
	if err != nil || !boolean(cfg, "approval_enabled") {
		fail(w, 409, "검토·승인 프로세스가 활성화되어 있지 않습니다")
		return
	}
	m := map[string]any{}
	if decode(r, &m) != nil || !hasString([]string{"approved", "rejected"}, str(m, "decision")) {
		fail(w, 400, "approved 또는 rejected 결정을 입력하세요")
		return
	}
	if strings.TrimSpace(str(m, "reason")) == "" {
		fail(w, 400, "결정 사유를 입력하세요")
		return
	}
	s, err := a.resource(r.Context(), "scans", r.PathValue("id"))
	if err != nil || !a.canAccess(r.Context(), currentUser(r), s) {
		fail(w, 404, "진단을 찾을 수 없습니다")
		return
	}
	if s.OwnerID == currentUser(r).ID && currentUser(r).Role != "admin" {
		fail(w, 403, "본인이 요청한 진단은 다른 팀장 또는 관리자가 검토해야 합니다")
		return
	}
	status, jobStatus := "queued", "ready"
	if str(m, "decision") == "rejected" {
		status, jobStatus = "rejected", "rejected"
	} else {
		if _, _, _, err := a.scanPolicy(r.Context(), s.Data); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "검토 결과를 저장하지 못했습니다")
		return
	}
	defer tx.Rollback(r.Context())
	ct, err := tx.Exec(r.Context(), `UPDATE scan_jobs SET status=$2,available_at=now() WHERE scan_id=$1 AND status='blocked'`, s.ID, jobStatus)
	if err != nil || ct.RowsAffected() != 1 {
		fail(w, 409, "검토 대기 상태의 진단이 아닙니다")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE resources SET data=data||jsonb_build_object('status',$2::text,'reviewed_by',$3::text,'review_reason',$4::text),updated_at=now() WHERE id=$1`, s.ID, status, currentUser(r).ID, str(m, "reason"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE resources SET data=data||jsonb_build_object('status',$2::text,'reviewed_by',$3::text,'reason',$4::text,'reviewed_at',now()),updated_at=now() WHERE kind='approvals' AND data->>'scan_id'=$1`, s.ID, str(m, "decision"), currentUser(r).ID, str(m, "reason"))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "검토 결과를 저장하지 못했습니다")
		return
	}
	a.audit(r, "scan."+str(m, "decision"), s.ID, map[string]any{"reason": str(m, "reason")})
	jsonResponse(w, 200, map[string]any{"status": status})
}

func (a *App) emergencyStop(w http.ResponseWriter, r *http.Request) {
	m := map[string]any{}
	if decode(r, &m) != nil {
		fail(w, 400, "올바른 요청이 필요합니다")
		return
	}
	enabled, ok := m["enabled"].(bool)
	if !ok {
		fail(w, 400, "enabled는 true 또는 false 여야 합니다")
		return
	}
	if strings.TrimSpace(str(m, "reason")) == "" {
		fail(w, 400, "긴급 중지 변경 사유를 입력하세요")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "긴급 중지 변경 실패")
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `UPDATE domain_runtime SET emergency=$1,reason=$2,updated_at=now() WHERE id=1`, enabled, str(m, "reason"))
	if err == nil && enabled {
		_, err = tx.Exec(r.Context(), `UPDATE resources SET data=data||jsonb_build_object('status','cancelled','finished_at',now(),'stop_reason',$1::text),updated_at=now() WHERE kind='scans' AND data->>'status' IN ('queued','running','pending_approval','awaiting_import')`, str(m, "reason"))
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE scan_jobs SET status='cancelled',lease_until=NULL WHERE status IN ('ready','leased','blocked'); UPDATE resources SET data=data||'{"status":"cancelled"}'::jsonb,updated_at=now() WHERE kind='approvals' AND data->>'status'='pending'`)
		}
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "긴급 중지 변경 실패")
		return
	}
	a.audit(r, "emergency-stop", "global", m)
	jsonResponse(w, 200, map[string]any{"enabled": enabled})
}

func (a *App) StartWorkers(ctx context.Context) {
	workerID := a.WorkerID
	if workerID == "" {
		workerID = "builtin"
	}
	go a.workerLoop(ctx, workerID)
}

func (a *App) workerLoop(ctx context.Context, workerID string) {
	heartbeat := func() {
		_ = a.registerWorker(ctx, workerID)
	}
	heartbeat()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	lastHeartbeat := time.Now()
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = a.DB.Exec(c, `UPDATE resources SET data=data||'{"status":"offline"}'::jsonb,updated_at=now() WHERE id=$1`, workerID)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if time.Since(lastHeartbeat) > 15*time.Second {
			heartbeat()
			lastHeartbeat = time.Now()
		}
		a.releaseDisabledApprovals(ctx)
		id, err := a.claimScan(ctx, workerID)
		if err != nil || id == "" {
			continue
		}
		a.executeScan(ctx, workerID, id)
	}
}

func (a *App) releaseDisabledApprovals(ctx context.Context) {
	cfg, err := a.setting(ctx, "workflow")
	if err != nil || boolean(cfg, "approval_enabled") {
		return
	}
	_, _ = a.DB.Exec(ctx, `WITH released AS (UPDATE scan_jobs SET status='ready' WHERE status='blocked' RETURNING scan_id) UPDATE resources SET data=data||'{"status":"queued","review_reason":"관리자가 검토 프로세스를 비활성화했습니다"}'::jsonb,updated_at=now() WHERE id IN(SELECT scan_id FROM released)`)
	_, _ = a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"status":"bypassed","reason":"검토 프로세스 비활성화"}'::jsonb,updated_at=now() WHERE kind='approvals' AND data->>'status'='pending'`)
}

func (a *App) claimScan(ctx context.Context, workerID string) (string, error) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var workerEnabled bool
	var workerNetwork string
	if err = tx.QueryRow(ctx, `SELECT COALESCE((data->>'enabled')::boolean,false),COALESCE(data->>'network','') FROM resources WHERE kind='workers' AND id=$1`, workerID).Scan(&workerEnabled, &workerNetwork); errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	} else if err != nil || !workerEnabled {
		return "", err
	}
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(716284991)`).Scan(&locked); err != nil || !locked {
		return "", err
	}
	var stop, leased bool
	if err = tx.QueryRow(ctx, `SELECT emergency FROM domain_runtime WHERE id=1`).Scan(&stop); err != nil || stop {
		return "", err
	}
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scan_jobs WHERE status='leased' AND lease_until>now())`).Scan(&leased); err != nil || leased {
		return "", err
	}
	// Expired leases become inconclusive after two attempts, never resolved.
	_, err = tx.Exec(ctx, `WITH exhausted AS (UPDATE scan_jobs SET status='failed' WHERE status='leased' AND lease_until<=now() AND attempts>=2 RETURNING scan_id) UPDATE resources SET data=data||jsonb_build_object('status','inconclusive','finished_at',now(),'logs','["워커 임대 만료: 재시도 한도에 도달했습니다"]'::jsonb),updated_at=now() WHERE id IN(SELECT scan_id FROM exhausted)`)
	if err != nil {
		return "", err
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT j.scan_id FROM scan_jobs j JOIN resources r ON r.id=j.scan_id JOIN resources s ON s.kind='services' AND s.id=r.data->>'service_id' WHERE ((j.status='ready' AND j.available_at<=now()) OR (j.status='leased' AND j.lease_until<=now() AND j.attempts<2)) AND COALESCE(s.data->>'network','')=$1 ORDER BY j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1`, workerNetwork).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", tx.Commit(ctx)
	}
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `UPDATE scan_jobs SET status='leased',worker_id=$2,attempts=attempts+1,lease_until=now()+interval '15 seconds' WHERE scan_id=$1`, id, workerID)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE resources SET data=data||jsonb_build_object('status','running','worker_id',$2::text,'started_at',now()),updated_at=now() WHERE id=$1`, id, workerID)
	}
	if err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

func (a *App) executeScan(parent context.Context, workerID, id string) {
	scan, err := a.resource(parent, "scans", id)
	if err != nil {
		return
	}
	s, scope, p, err := a.scanPolicy(parent, scan.Data)
	if err != nil {
		a.finishScan(parent, workerID, id, "inconclusive", map[string]any{}, []string{err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.Timeout)*time.Second)
	defer cancel()
	check := func() error {
		var stop, live, userEnabled bool
		err := a.DB.QueryRow(ctx, `SELECT d.emergency,EXISTS(SELECT 1 FROM scan_jobs WHERE scan_id=$1 AND worker_id=$2 AND status='leased' AND lease_until>now()),EXISTS(SELECT 1 FROM users WHERE id=$3 AND NOT disabled) FROM domain_runtime d WHERE id=1`, id, workerID, scan.OwnerID).Scan(&stop, &live, &userEnabled)
		if err != nil {
			return err
		}
		if stop || !live || !userEnabled {
			return errors.New("진단이 중지되었거나 요청자 계정이 비활성화되었습니다")
		}
		if runID := str(scan.Data, "agent_run_id"); runID != "" {
			if err := a.checkAgentChild(ctx, runID); err != nil {
				return err
			}
		}
		owner, err := a.scheduleOwner(ctx, scan)
		if err != nil {
			return err
		}
		worker, err := a.resource(ctx, "workers", workerID)
		if err != nil || !boolean(worker.Data, "enabled") {
			return errors.New("워커가 관리자에 의해 비활성화되었습니다")
		}
		current, err := a.resource(ctx, "scopes", scope.ID)
		if err != nil || !boolean(current.Data, "approved") {
			return errors.New("범위 승인이 취소되었습니다")
		}
		service, err := a.resource(ctx, "services", s.ID)
		if err != nil || !boolean(service.Data, "approved") || str(service.Data, "url") != str(s.Data, "url") {
			return errors.New("대상 서비스 승인이 변경되었습니다")
		}
		if !a.canAccess(ctx, owner, service) {
			return errors.New("요청자의 서비스 접근 권한이 변경되었습니다")
		}
		if str(worker.Data, "network") != str(service.Data, "network") {
			return errors.New("워커와 서비스의 승인된 망이 다릅니다")
		}
		_, _, latest, err := a.scanPolicy(ctx, scan.Data)
		if err != nil {
			return err
		}
		if latest.Fingerprint != p.Fingerprint {
			return errors.New("대상·범위·정책 설정이 변경되어 진행 중인 진단을 중지합니다")
		}
		if err = latest.validateURL(p.Target); err != nil {
			return err
		}
		return nil
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := check(); err != nil {
					cancel()
					return
				}
				ct, err := a.DB.Exec(ctx, `UPDATE scan_jobs SET lease_until=now()+interval '15 seconds' WHERE scan_id=$1 AND worker_id=$2 AND status='leased'`, id, workerID)
				if err != nil || ct.RowsAffected() != 1 {
					cancel()
					return
				}
				_, _ = a.DB.Exec(ctx, `UPDATE resources SET data=data||jsonb_build_object('last_seen',now()),updated_at=now() WHERE id=$1`, workerID)
			}
		}
	}()
	client, closeClient := p.client(ctx, check)
	defer closeClient()
	var findings []map[string]any
	result := map[string]any{}
	logs := []string{"승인 대상·범위·DNS·경로·요청 제한 확인"}
	if str(scan.Data, "profile") == "authorization" {
		findings, result, err = a.runAuthorization(ctx, client, s, scan.Data)
	} else {
		findings, result, err = runHTTPBaseline(ctx, client, s, p.Target)
	}
	if err != nil {
		logs = append(logs, safeProbeError(err))
		a.finishScan(parent, workerID, id, "inconclusive", result, logs)
		return
	}
	if err = check(); err != nil {
		a.finishScan(parent, workerID, id, "inconclusive", result, append(logs, "실행 상태가 변경되어 결과 확정을 중지했습니다"))
		return
	}
	inserted, updated, err := a.ingestFindings(ctx, User{ID: scan.OwnerID}, s.ID, findings, id)
	if err != nil {
		a.finishScan(parent, workerID, id, "inconclusive", result, append(logs, "관찰 결과 저장 실패"))
		return
	}
	result["new_findings"] = inserted
	result["updated_findings"] = updated
	if fid := str(scan.Data, "finding_id"); fid != "" {
		if err := a.resolveBaselineFinding(ctx, fid, id, workerID, result); err != nil {
			logs = append(logs, err.Error())
		}
	}
	logs = append(logs, "정의된 제한 진단이 완료되었습니다. 결과가 없는 항목은 취약점 부재를 보장하지 않습니다.")
	a.finishScan(parent, workerID, id, "completed", result, logs)
}

func (a *App) finishScan(ctx context.Context, workerID, id, status string, result map[string]any, logs []string) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	ct, err := tx.Exec(ctx, `UPDATE scan_jobs SET status='finished',lease_until=NULL WHERE scan_id=$1 AND worker_id=$2 AND status='leased'`, id, workerID)
	if err != nil || ct.RowsAffected() != 1 {
		return
	}
	patch, _ := json.Marshal(map[string]any{"status": status, "result": result, "logs": logs, "finished_at": time.Now().UTC()})
	_, err = tx.Exec(ctx, `UPDATE resources SET data=data||$2::jsonb,updated_at=now() WHERE id=$1`, id, patch)
	if err == nil {
		_ = tx.Commit(ctx)
	}
}

func safeProbeError(err error) string {
	// URL queries can carry credentials; do not serialize net/http errors.
	var ue *url.Error
	if errors.As(err, &ue) {
		return "진단 통신 실패: " + safeProbeError(ue.Err)
	}
	msg := err.Error()
	if strings.Contains(msg, "http://") || strings.Contains(msg, "https://") {
		return "진단 통신 오류: 대상과 인증 프로파일을 확인하세요"
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

var baselineHeaders = []struct{ key, title, severity, remediation string }{
	{"x-content-type-options", "MIME 유형 추측 방지 헤더 누락", "low", "X-Content-Type-Options: nosniff 응답 헤더를 설정하세요."},
	{"content-security-policy", "콘텐츠 보안 정책 헤더 누락", "low", "서비스 리소스 출처에 맞는 Content-Security-Policy를 설정하고 검증하세요."},
	{"x-frame-options", "클릭재킹 방지 정책 확인 필요", "low", "Content-Security-Policy의 frame-ancestors 또는 X-Frame-Options를 설정하세요."},
	{"strict-transport-security", "HTTPS 강제 정책 헤더 누락", "medium", "HTTPS 서비스를 확인한 뒤 Strict-Transport-Security를 설정하세요."},
}

func runHTTPBaseline(ctx context.Context, client *http.Client, service domainResource, target *url.URL) ([]map[string]any, map[string]any, error) {
	result := map[string]any{"engine": "hunter-http-baseline", "engine_version": "1", "tested_controls": []string{}}
	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return nil, result, err
	}
	req.Header.Set("User-Agent", "Hunter-Security-Validation/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, result, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, result, err
	}
	result["http_status"] = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, result, errors.New("정상 업무 응답에 도달하지 못해 보안 헤더 판정을 보류합니다")
	}
	findings := []map[string]any{}
	controls := map[string]bool{}
	for _, test := range baselineHeaders {
		if test.key == "strict-transport-security" && target.Scheme != "https" {
			continue
		}
		present := strings.TrimSpace(resp.Header.Get(test.key)) != ""
		if test.key == "x-frame-options" && strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
			present = true
		}
		controls[test.key] = present
		if !present {
			findings = append(findings, map[string]any{"title": test.title, "severity": test.severity, "source": "http-baseline", "status": "candidate", "rule_id": test.key, "location": target.EscapedPath(), "description": "등록된 경로의 실제 응답에서 권장 보안 헤더를 확인할 수 없습니다. 업무 맥락과 대체 통제를 검토하세요.", "evidence": fmt.Sprintf("GET %s → HTTP %d; %s 헤더 없음", target.EscapedPath(), resp.StatusCode, test.key), "remediation": test.remediation})
		}
	}
	result["tested_controls"] = controls
	result["path"] = target.EscapedPath()
	result["response_received"] = true
	return findings, result, nil
}

func (a *App) resolveBaselineFinding(ctx context.Context, fid, scanID, workerID string, result map[string]any) error {
	f, err := a.resource(ctx, "findings", fid)
	if err != nil {
		return err
	}
	controls, ok := result["tested_controls"].(map[string]bool)
	if !ok {
		return errors.New("재검증 통제 결과가 없습니다")
	}
	present, tested := controls[str(f.Data, "rule_id")]
	if !tested || str(f.Data, "location") != str(result, "path") {
		return errors.New("기존 발견과 동일한 경로·통제에 도달하지 못해 해결 처리하지 않았습니다")
	}
	if !present {
		return errors.New("기존 문제가 재현되어 미해결 상태를 유지합니다")
	}
	patch, _ := json.Marshal(map[string]any{"status": "resolved", "resolved_at": time.Now().UTC(), "verification": map[string]any{"scan_id": scanID, "control": str(f.Data, "rule_id"), "result": "control_present", "http_status": result["http_status"], "verified_at": time.Now().UTC()}})
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var emergency bool
	if err = tx.QueryRow(ctx, `SELECT emergency FROM domain_runtime WHERE id=1 FOR SHARE`).Scan(&emergency); err != nil {
		return err
	}
	if emergency {
		return errors.New("긴급 중지되어 해결 상태를 확정하지 않았습니다")
	}
	var jobStatus string
	err = tx.QueryRow(ctx, `SELECT j.status FROM scan_jobs j JOIN resources s ON s.id=j.scan_id WHERE j.scan_id=$1 AND j.worker_id=$2 AND j.status='leased' AND j.lease_until>now() AND s.data->>'status'='running' AND s.data->>'finding_id'=$3 FOR UPDATE OF j`, scanID, workerID, fid).Scan(&jobStatus)
	if err != nil {
		return errors.New("활성 재검증 임대가 없어 해결 상태를 확정하지 않았습니다")
	}
	_, err = tx.Exec(ctx, `UPDATE resources SET data=data||$2::jsonb,updated_at=now() WHERE id=$1 AND kind='findings'`, fid, patch)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a *App) runAuthorization(ctx context.Context, client *http.Client, service domainResource, input map[string]any) ([]map[string]any, map[string]any, error) {
	result := map[string]any{"engine": "hunter-authorization", "engine_version": "1"}
	scenario, err := a.resource(ctx, "scenarios", str(input, "scenario_id"))
	if err != nil {
		return nil, result, err
	}
	if str(scenario.Data, "service_id") != service.ID {
		return nil, result, errors.New("시나리오 대상이 다릅니다")
	}
	base, err := url.Parse(str(service.Data, "url"))
	if err != nil {
		return nil, result, err
	}
	relative, err := url.Parse(str(scenario.Data, "path"))
	if err != nil || relative.IsAbs() || relative.Host != "" {
		return nil, result, errors.New("검증 경로가 올바르지 않습니다")
	}
	target := base.ResolveReference(relative)
	marker := str(scenario.Data, "marker")
	if marker == "" {
		return nil, result, errors.New("합성 데이터 식별 문자열이 필요합니다")
	}
	probe := func(profileID string, probeURL *url.URL, expectedMarker string) (int, bool, error) {
		profile, err := a.resource(ctx, "auth-profiles", profileID)
		if err != nil || str(profile.Data, "service_id") != service.ID {
			return 0, false, errors.New("서비스에 연결된 인증 프로파일이 필요합니다")
		}
		req, err := http.NewRequestWithContext(ctx, "GET", probeURL.String(), nil)
		if err != nil {
			return 0, false, err
		}
		req.Header.Set("User-Agent", "Hunter-Authorization-Validation/1.0")
		if err = a.applyAuthProfile(req, profile.Data); err != nil {
			return 0, false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, false, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
		if err != nil {
			return 0, false, err
		}
		if len(body) > 2<<20 {
			return 0, false, errors.New("검증 응답 크기가 제한을 초과했습니다")
		}
		return resp.StatusCode, strings.Contains(string(body), expectedMarker), nil
	}
	authorized, found, err := probe(str(scenario.Data, "authorized_profile_id"), target, marker)
	if err != nil {
		return nil, result, err
	}
	result["authorized_status"] = authorized
	if authorized < 200 || authorized >= 300 || !found {
		return nil, result, errors.New("정상 사용자 기준 검증 실패: 인증 상태·합성 데이터 접근을 확인하세요")
	}
	controlPath, controlMarker := str(scenario.Data, "unauthorized_control_path"), str(scenario.Data, "unauthorized_control_marker")
	if !validScopePath(controlPath) || controlMarker == "" {
		return nil, result, errors.New("비교 계정의 정상 인증 확인 경로·합성 식별 문자열이 필요합니다")
	}
	controlRelative, err := url.Parse(controlPath)
	if err != nil {
		return nil, result, errors.New("비교 계정 기준 경로가 올바르지 않습니다")
	}
	controlStatus, controlFound, err := probe(str(scenario.Data, "unauthorized_profile_id"), base.ResolveReference(controlRelative), controlMarker)
	if err != nil {
		return nil, result, err
	}
	result["comparison_control_status"] = controlStatus
	if controlStatus < 200 || controlStatus >= 300 || !controlFound {
		return nil, result, errors.New("비교 계정의 정상 인증 기준 검증 실패: 세션 만료를 권한 차단으로 판단하지 않습니다")
	}
	unauthorized, leaked, err := probe(str(scenario.Data, "unauthorized_profile_id"), target, marker)
	if err != nil {
		return nil, result, err
	}
	result["unauthorized_status"] = unauthorized
	result["synthetic_marker_exposed"] = leaked
	if unauthorized == 401 {
		return nil, result, errors.New("권한 없는 사용자 프로파일의 인증 실패: 인가 차단과 구분할 수 없습니다")
	}
	if leaked {
		return []map[string]any{{"title": "권한이 없는 역할에 합성 테스트 데이터 노출", "severity": "high", "status": "confirmed", "source": "authorization", "rule_id": scenario.ID, "location": str(scenario.Data, "path"), "description": "정상 사용자 기준 검사 성공 후 다른 역할의 응답에서도 같은 합성 데이터 식별 문자열이 확인되었습니다.", "evidence": fmt.Sprintf("정상 역할 HTTP %d / 비교 역할 HTTP %d / 합성 데이터 일치=true (응답 및 비밀값 미저장)", authorized, unauthorized), "remediation": "데이터 소유자·조직·역할에 대한 서버 측 인가 검사를 적용하세요."}}, result, nil
	}
	if unauthorized != 403 && unauthorized != 404 && (unauthorized < 200 || unauthorized >= 300) {
		return nil, result, errors.New("비교 역할 응답이 정의된 차단 또는 정상 응답이 아니므로 판단 불가입니다")
	}
	result["outcome"] = "no_synthetic_data_exposure"
	return []map[string]any{}, result, nil
}

func (a *App) applyAuthProfile(req *http.Request, m map[string]any) error {
	secret := func(key string) (string, error) {
		s := str(m, key)
		if s == "" {
			return "", errors.New("인증 프로파일의 비밀 값이 설정되지 않았습니다")
		}
		return a.decrypt(s)
	}
	switch str(m, "type") {
	case "bearer":
		token, err := secret("token")
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	case "basic":
		password, err := secret("password")
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(str(m, "username")+":"+password)))
	case "headers":
		raw, err := secret("headers")
		if err != nil {
			return err
		}
		headers := map[string]string{}
		if json.Unmarshal([]byte(raw), &headers) != nil {
			return errors.New("인증 헤더 JSON이 올바르지 않습니다")
		}
		for key, value := range headers {
			if hasString([]string{"host", "content-length", "connection", "transfer-encoding", "proxy-authorization"}, strings.ToLower(key)) {
				return errors.New("인증 프로파일에 허용되지 않는 헤더입니다")
			}
			req.Header.Set(key, value)
		}
	default:
		return errors.New("지원하지 않는 인증 방식입니다")
	}
	return nil
}
