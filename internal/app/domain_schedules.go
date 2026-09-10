package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func validateSchedule(m map[string]any) error {
	if str(m, "service_id") == "" {
		return errors.New("예약의 대상 서비스가 필요합니다")
	}
	interval := number(m, "interval_minutes", 60)
	if interval < 5 || interval > 10080 {
		return errors.New("예약 간격은 5~10080분입니다")
	}
	m["interval_minutes"] = interval
	if str(m, "profile") == "" {
		m["profile"] = "http-baseline"
	}
	if !hasString([]string{"http-baseline", "authorization", "import-only"}, str(m, "profile")) {
		return errors.New("지원하지 않는 예약 진단 프로파일입니다")
	}
	if str(m, "profile") == "authorization" && str(m, "scenario_id") == "" {
		return errors.New("권한 검증 예약에는 시나리오가 필요합니다")
	}
	if str(m, "next_run_at") == "" {
		m["next_run_at"] = time.Now().UTC().Add(time.Duration(interval) * time.Minute).Format(time.RFC3339)
	}
	if _, err := time.Parse(time.RFC3339, str(m, "next_run_at")); err != nil {
		return errors.New("다음 실행 시각은 RFC3339 형식입니다")
	}
	if _, ok := m["enabled"]; !ok {
		m["enabled"] = true
	}
	return nil
}

// StartScheduler is only called by the control plane. Workers run the same
// image but do not need to expose an HTTP listener or run this timer.
func (a *App) StartScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			a.runDueSchedules(ctx, time.Now().UTC())
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (a *App) runDueSchedules(ctx context.Context, now time.Time) {
	rows, err := a.DB.Query(ctx, `SELECT id FROM resources WHERE kind='schedules' AND data->>'enabled'='true' AND (data->>'next_run_at')::timestamptz<=$1 ORDER BY (data->>'next_run_at')::timestamptz LIMIT 100`, now)
	if err != nil {
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		_ = a.runSchedule(ctx, id, now)
	}
}

func (a *App) scheduleOwner(ctx context.Context, schedule domainResource) (User, error) {
	var u User
	err := a.DB.QueryRow(ctx, `SELECT id,username,name,role,team FROM users WHERE id=$1 AND NOT disabled`, schedule.OwnerID).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	if err != nil {
		return u, errors.New("예약 소유자 계정이 비활성화되었거나 삭제되었습니다")
	}
	u.Scopes = a.roleScopes(ctx, u.Role)
	if !hasString(u.Scopes, "scans:write") {
		return u, errors.New("예약 소유자에게 현재 진단 실행 권한이 없습니다")
	}
	if keyID := str(schedule.Data, "credential_key_id"); keyID != "" {
		u.KeyID = keyID
		var scopes []string
		if err = a.DB.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, keyID, u.ID).Scan(&scopes); err != nil || !hasString(scopes, "scans:write") {
			return u, errors.New("예약 생성 API 키가 만료·폐기되었거나 실행 권한이 변경되었습니다")
		}
		effective := []string{}
		for _, scope := range u.Scopes {
			if hasString(scopes, scope) {
				effective = append(effective, scope)
			}
		}
		u.Scopes = effective
	}
	return u, nil
}

func (a *App) runSchedule(ctx context.Context, id string, now time.Time) error {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	schedule, err := scanResource(tx.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind='schedules' AND id=$1 FOR UPDATE SKIP LOCKED`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	due, err := time.Parse(time.RFC3339, str(schedule.Data, "next_run_at"))
	if err != nil || !boolean(schedule.Data, "enabled") || due.After(now) {
		return nil
	}
	interval := number(schedule.Data, "interval_minutes", 60)
	if interval < 5 || interval > 10080 {
		return errors.New("유효하지 않은 예약 간격")
	}
	patch := map[string]any{"last_run_at": now.Format(time.RFC3339), "next_run_at": now.Add(time.Duration(interval) * time.Minute).Format(time.RFC3339), "last_result": "blocked", "last_error": ""}
	var pending bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resources WHERE kind='scans' AND data->>'schedule_id'=$1 AND data->>'status' IN ('queued','running','pending_approval','awaiting_import'))`, id).Scan(&pending)
	if err != nil {
		return err
	}
	if pending {
		patch["last_result"] = "skipped_pending"
		patch["last_error"] = "이 예약의 이전 진단이 대기·실행 중이므로 중복 실행하지 않았습니다"
	} else {
		owner, ownerErr := a.scheduleOwner(ctx, schedule)
		if ownerErr != nil {
			patch["last_error"] = ownerErr.Error()
		} else {
			occurrence := due.UTC().Format(time.RFC3339Nano)
			var previousID string
			priorErr := tx.QueryRow(ctx, `SELECT id FROM resources WHERE kind='scans' AND data->>'schedule_id'=$1 AND data->>'schedule_occurrence'=$2`, id, occurrence).Scan(&previousID)
			if priorErr == nil {
				patch["last_result"] = "already_scheduled"
				patch["last_scan_id"] = previousID
			} else if !errors.Is(priorErr, pgx.ErrNoRows) {
				return priorErr
			} else {
				result, scanErr := a.requestScan(ctx, owner, schedule.Data, id, occurrence)
				if scanErr != nil {
					patch["last_error"] = scanErr.Error()
				} else {
					patch["last_result"] = "scan_requested"
					patch["last_scan_id"] = str(result, "id")
				}
			}
		}
	}
	encoded, _ := json.Marshal(patch)
	if _, err = tx.Exec(ctx, `UPDATE resources SET data=data||$2::jsonb,updated_at=now() WHERE id=$1`, id, encoded); err != nil {
		return err
	}
	auditData, _ := json.Marshal(map[string]any{"last_result": patch["last_result"], "scan_id": patch["last_scan_id"]})
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,'scheduler','schedule.tick',$3,$4)`, newID(), schedule.OwnerID, id, auditData)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a *App) registerWorker(ctx context.Context, id string) error {
	name := "망별 진단 워커"
	enabled := false
	if id == "builtin" {
		name = "내장 제한 진단 워커"
		enabled = true
	}
	initial := map[string]any{"name": name, "enabled": enabled, "network": "", "status": "online", "last_seen": time.Now().UTC(), "profiles": []string{"http-baseline", "authorization"}, "version": a.Version, "isolation": "전용 HTTP transport · 비특권 컨테이너 프로세스", "max_concurrency": 1}
	data, _ := json.Marshal(initial)
	heartbeat, _ := json.Marshal(map[string]any{"status": "online", "last_seen": time.Now().UTC(), "version": a.Version, "profiles": []string{"http-baseline", "authorization"}})
	_, err := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'workers','system',$2) ON CONFLICT(id) DO UPDATE SET data=resources.data||$3::jsonb,updated_at=now() WHERE resources.kind='workers'`, id, data, heartbeat)
	return err
}

func (a *App) updateWorker(w http.ResponseWriter, r *http.Request) {
	m := map[string]any{}
	if decode(r, &m) != nil {
		fail(w, 400, "올바른 워커 설정이 필요합니다")
		return
	}
	patch := map[string]any{}
	for key, value := range m {
		switch key {
		case "name", "network":
			text, ok := value.(string)
			if !ok || len(text) > 200 || strings.ContainsAny(text, "\r\n\x00") {
				fail(w, 400, "워커 이름·망 이름은 200자 이내 문자열입니다")
				return
			}
			if key == "name" && strings.TrimSpace(text) == "" {
				fail(w, 400, "워커 이름을 입력하세요")
				return
			}
			patch[key] = text
		case "enabled":
			enabled, ok := value.(bool)
			if !ok {
				fail(w, 400, "enabled는 true 또는 false 입니다")
				return
			}
			patch[key] = enabled
		default:
			continue
		}
	}
	encoded, _ := json.Marshal(patch)
	ct, err := a.DB.Exec(r.Context(), `UPDATE resources SET data=data||$2::jsonb,updated_at=now() WHERE kind='workers' AND id=$1`, r.PathValue("id"), encoded)
	if err != nil {
		fail(w, 500, "워커 설정 저장 실패")
		return
	}
	if ct.RowsAffected() != 1 {
		fail(w, 404, "워커를 찾을 수 없습니다")
		return
	}
	v, err := a.resource(r.Context(), "workers", r.PathValue("id"))
	if err != nil {
		fail(w, 500, "워커 설정 조회 실패")
		return
	}
	a.audit(r, "worker.configure", v.ID, patch)
	jsonResponse(w, 200, a.resourceOutput(v))
}

func (a *App) recordPolicyVersion(ctx context.Context, v domainResource, actor string) {
	data, _ := json.Marshal(v.Data)
	_, _ = a.DB.Exec(ctx, `INSERT INTO policy_versions(policy_id,changed_by,data) VALUES($1,$2,$3)`, v.ID, actor, data)
}
func (a *App) policyHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(r.Context(), `SELECT row_number() OVER(ORDER BY id),changed_by,data,created_at FROM policy_versions WHERE policy_id=$1 ORDER BY id DESC LIMIT 100`, r.PathValue("id"))
	if err != nil {
		fail(w, 500, "정책 이력 조회 실패")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var version int
		var actor string
		var data map[string]any
		var created time.Time
		if rows.Scan(&version, &actor, &data, &created) != nil {
			fail(w, 500, "정책 이력 조회 실패")
			return
		}
		out = append(out, map[string]any{"version": version, "changed_by": actor, "data": data, "created_at": created})
	}
	jsonResponse(w, 200, out)
}
func (a *App) exportPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := a.ListResources(r.Context(), "policies", currentUser(r))
	if err != nil {
		fail(w, 500, "정책 내보내기 실패")
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=hunter-policies.json")
	a.audit(r, "policies.export", "all", map[string]any{"count": len(policies)})
	jsonResponse(w, 200, map[string]any{"schema_version": "1", "generated_at": time.Now().UTC(), "policies": policies})
}
