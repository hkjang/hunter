package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hkjang/hunter/internal/pentagicore"
	"github.com/jackc/pgx/v5"
)

var errAgentPaused = errors.New("사용자가 요청한 안전 경계에서 일시 중지했습니다")

func (a *App) initAgentControl(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS agent_run_control(run_id text PRIMARY KEY REFERENCES agent_runs(id) ON DELETE CASCADE,pause_requested boolean NOT NULL DEFAULT false,resume_count integer NOT NULL DEFAULT 0,active_ms bigint NOT NULL DEFAULT 0,resumed_at timestamptz,wait_input_after bigint NOT NULL DEFAULT 0,control_updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
 ALTER TABLE agent_run_control ADD COLUMN IF NOT EXISTS control_updated_at timestamptz NOT NULL DEFAULT clock_timestamp();
 CREATE TABLE IF NOT EXISTS agent_inputs(id bigserial PRIMARY KEY,run_id text NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,author_id text NOT NULL REFERENCES users(id),content_encrypted text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
 CREATE INDEX IF NOT EXISTS agent_inputs_run ON agent_inputs(run_id,id);
 CREATE TABLE IF NOT EXISTS agent_tool_receipts(run_id text NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,call_id text NOT NULL,name text NOT NULL,arguments_hash text NOT NULL,status text NOT NULL,result_encrypted text NOT NULL DEFAULT '',error_text text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(run_id,call_id));`)
	return err
}
func (a *App) registerAgentControl(m *http.ServeMux) {
	for _, action := range []string{"pause", "resume", "input"} {
		m.HandleFunc("POST /api/agent-runs/{id}/"+action, a.protect("agents:write", func(w http.ResponseWriter, r *http.Request) { a.changeAgentControl(w, r, action) }))
	}
}
func agentControlAccessTx(ctx context.Context, tx pgx.Tx, u User, serviceID string) error {
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT NOT disabled AND role=$2 AND team=$3 FROM users WHERE id=$1 FOR SHARE`, u.ID, u.Role, u.Team).Scan(&enabled); err != nil || !enabled {
		return errors.New("현재 사용자 권한을 확인해 주세요")
	}
	if u.Role != "admin" {
		var roles map[string]any
		if err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key='roles' FOR SHARE`).Scan(&roles); err != nil {
			return errors.New("현재 역할 권한을 확인할 수 없습니다")
		}
		for _, s := range u.Scopes {
			if !hasString(stringList(roles[u.Role]), s) {
				return errors.New("역할 권한이 변경되었습니다")
			}
		}
	}
	if u.KeyID != "" {
		var scopes []string
		if err := tx.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() FOR SHARE`, u.KeyID, u.ID).Scan(&scopes); err != nil {
			return errors.New("API 키가 만료·회전·폐기되었습니다")
		}
		for _, s := range u.Scopes {
			if !hasString(scopes, s) {
				return errors.New("API 키 권한이 변경되었습니다")
			}
		}
	}
	var id string
	if err := tx.QueryRow(ctx, `SELECT id FROM resources WHERE id=$1 AND kind='services' AND ($2 OR owner_id=$3 OR ($4<>'' AND data->>'team'=$4)) FOR SHARE`, serviceID, elevated(u), u.ID, leadTeam(u)).Scan(&id); err != nil {
		return errors.New("현재 서비스 접근 권한이 없습니다")
	}
	return nil
}
func (a *App) changeAgentControl(w http.ResponseWriter, r *http.Request, action string) {
	var in struct {
		Expected string `json:"expected_updated_at"`
		Message  string `json:"message"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "요청 내용을 확인하세요")
		return
	}
	expected, err := time.Parse(time.RFC3339Nano, in.Expected)
	if err != nil {
		fail(w, 400, "조회한 실행의 expected_updated_at이 필요합니다")
		return
	}
	if action == "input" && (strings.TrimSpace(in.Message) == "" || len(in.Message) > 16000 || !utf8.ValidString(in.Message) || strings.ContainsRune(in.Message, 0)) {
		fail(w, 400, "추가 입력은 1~16,000바이트의 올바른 문자열이어야 합니다")
		return
	}
	ctx, u := r.Context(), currentUser(r)
	if !hasAgentReadScopes(u) || !hasString(u.Scopes, "ai:use") {
		fail(w, 403, "에이전트·AI·대상 자료 권한이 필요합니다")
		return
	}
	v, err := a.agentRun(ctx, r.PathValue("id"))
	if err != nil || !a.canReadAgent(ctx, u, v) {
		fail(w, 404, "접근 가능한 실행을 찾을 수 없습니다")
		return
	}
	// The original principal remains authoritative on resume. A different caller
	// cannot revive a run created by a now-revoked key.
	owner, err := a.agentPrincipal(ctx, v)
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	if action == "resume" {
		_, _, policy, e := a.scanPolicy(ctx, map[string]any{"service_id": v.ServiceID, "scope_id": v.ScopeID})
		if e != nil || policy.Fingerprint != v.PolicyHash {
			fail(w, 409, "대상·범위·정책이 변경되었거나 만료되었습니다. 현재 조건으로 새 실행을 시작하세요")
			return
		}
		cfg, e := a.setting(ctx, "agents")
		if e != nil || !boolean(cfg, "enabled") {
			fail(w, 409, "관리자가 에이전트 진단을 비활성화했습니다")
			return
		}
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		fail(w, 503, "실행 상태 저장소를 사용할 수 없습니다")
		return
	}
	defer tx.Rollback(ctx)
	v, err = scanAgent(tx.QueryRow(ctx, `SELECT `+agentColumns+` FROM agent_runs WHERE id=$1 FOR UPDATE`, v.ID))
	if err != nil {
		fail(w, 404, "실행을 찾을 수 없습니다")
		return
	}
	var controlUpdated time.Time
	if _, err = tx.Exec(ctx, `INSERT INTO agent_run_control(run_id,control_updated_at) VALUES($1,$2) ON CONFLICT DO NOTHING`, v.ID, v.UpdatedAt); err != nil {
		fail(w, 503, "실행 제어 기준을 준비할 수 없습니다")
		return
	}
	if err = tx.QueryRow(ctx, `SELECT control_updated_at FROM agent_run_control WHERE run_id=$1 FOR UPDATE`, v.ID).Scan(&controlUpdated); err != nil {
		fail(w, 503, "실행 제어 기준을 읽을 수 없습니다")
		return
	}
	if (!controlUpdated.Equal(expected) && !v.UpdatedAt.Equal(expected)) || agentTerminal(v.Status) || v.CancelRequested {
		fail(w, 409, "실행 상태가 변경되었습니다. 입력을 보존한 채 최신 상태를 확인하세요")
		return
	}
	if err = agentControlAccessTx(ctx, tx, u, v.ServiceID); err == nil {
		err = agentControlAccessTx(ctx, tx, owner, v.ServiceID)
	}
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_run_control(run_id) VALUES($1) ON CONFLICT DO NOTHING`, v.ID)
	if err != nil {
		fail(w, 503, "실행 제어를 준비할 수 없습니다")
		return
	}
	next, message := v.Status, ""
	switch action {
	case "pause":
		if !hasString([]string{"queued", "running", "waiting_approval"}, v.Status) {
			fail(w, 409, "실행 중이거나 대기열에 있는 작업만 일시 중지할 수 있습니다")
			return
		}
		if v.Status == "queued" {
			next = "paused"
		}
		_, err = tx.Exec(ctx, `UPDATE agent_run_control SET pause_requested=true WHERE run_id=$1`, v.ID)
		message = "일시 중지를 요청했습니다. 진행 중인 도구가 반환한 안전 경계에서 멈춥니다"
	case "resume":
		if !hasString([]string{"paused", "waiting_provider", "waiting_input"}, v.Status) {
			fail(w, 409, "일시 중지·입력 대기·모델 연결 대기 상태만 재개할 수 있습니다")
			return
		}
		var age int64
		var after, last int64
		err = tx.QueryRow(ctx, `SELECT active_ms,wait_input_after,(SELECT coalesce(max(id),0) FROM agent_inputs WHERE run_id=$1) FROM agent_run_control WHERE run_id=$1`, v.ID).Scan(&age, &after, &last)
		if err == nil && age >= int64(asInt(v.Limits["timeout_minutes"]))*60000 {
			fail(w, 409, "누적 실행 시간 한도에 도달했습니다")
			return
		}
		if err == nil && v.Status == "waiting_input" && last <= after {
			fail(w, 409, "질문에 대한 추가 입력을 저장한 뒤 재개하세요")
			return
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE agent_run_control SET pause_requested=false,resume_count=resume_count+1 WHERE run_id=$1`, v.ID)
		}
		next = "queued"
		message = "저장된 같은 실행을 재개 대기열에 등록했습니다"
	case "input":
		var count, size int
		err = tx.QueryRow(ctx, `SELECT count(*),coalesce(sum(octet_length(content_encrypted)),0) FROM agent_inputs WHERE run_id=$1`, v.ID).Scan(&count, &size)
		if err == nil && (count >= 20 || size >= 96000) {
			fail(w, 409, "실행별 추가 입력 한도(20건·저장 96KB)에 도달했습니다")
			return
		}
		cipher, e := a.encrypt(maskAgentText(strings.TrimSpace(in.Message)))
		if e != nil {
			err = e
		} else if err == nil && size+len(cipher) > 96000 {
			fail(w, 409, "실행별 추가 입력 저장 한도(96KB)에 도달했습니다")
			return
		} else if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO agent_inputs(run_id,author_id,content_encrypted) VALUES($1,$2,$3)`, v.ID, u.ID, cipher)
		}
		message = "추가 지시를 저장했습니다. 실행 중이면 다음 모델 호출에 반영되고, 대기 중이면 재개 버튼으로 계속할 수 있습니다"
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE agent_run_control SET control_updated_at=clock_timestamp() WHERE run_id=$1`, v.ID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE agent_runs SET status=$2,error=CASE WHEN $3='resume' THEN '' ELSE error END,finished_at=NULL,updated_at=clock_timestamp() WHERE id=$1`, v.ID, next, action)
	}
	if err == nil {
		err = a.agentEventTx(ctx, tx, v.ID, pentagicore.Event{Type: "run.updated", Status: next, Message: message})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		fail(w, 503, "실행 제어 요청을 저장하지 못했습니다")
		return
	}
	a.audit(r, "agent."+action, v.ID, map[string]any{"service_id": v.ServiceID})
	v, err = a.agentRun(ctx, v.ID)
	if err != nil {
		fail(w, 503, "저장된 실행을 다시 조회하세요")
		return
	}
	jsonResponse(w, 200, a.agentOutput(ctx, v, true, u))
}
func (a *App) agentInputs(ctx context.Context, id string) ([]pentagicore.RunInput, error) {
	rows, err := a.DB.Query(ctx, `SELECT id,content_encrypted FROM agent_inputs WHERE run_id=$1 ORDER BY id LIMIT 20`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []pentagicore.RunInput{}
	for rows.Next() {
		var in pentagicore.RunInput
		var encrypted string
		if err = rows.Scan(&in.ID, &encrypted); err != nil {
			return nil, err
		}
		in.Text, err = a.decrypt(encrypted)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}
func (a *App) agentBoundary(ctx context.Context, v agentRun) error {
	if err := a.checkAgent(ctx, v); err != nil {
		return err
	}
	var paused bool
	err := a.DB.QueryRow(ctx, `SELECT coalesce((SELECT pause_requested FROM agent_run_control WHERE run_id=$1),false)`, v.ID).Scan(&paused)
	if err != nil {
		return err
	}
	if paused {
		return errAgentPaused
	}
	return nil
}
func (a *App) suspendAgent(v agentRun, status, reason string, inputAfter int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var live bool
	err = tx.QueryRow(ctx, `SELECT NOT cancel_requested AND status IN ('running','waiting_approval') AND lease_until>now() FROM agent_runs WHERE id=$1 FOR UPDATE`, v.ID).Scan(&live)
	if err != nil {
		return err
	}
	if !live {
		return errors.New("실행 제어권을 잃었습니다")
	}
	_, err = tx.Exec(ctx, `UPDATE agent_run_control SET active_ms=active_ms+coalesce(greatest(0,extract(epoch FROM (now()-resumed_at))*1000)::bigint,0),resumed_at=NULL,wait_input_after=CASE WHEN $2='waiting_input' THEN $3 ELSE wait_input_after END WHERE run_id=$1`, v.ID, status, inputAfter)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE agent_runs SET status=$2,error=$3,lease_until=NULL,updated_at=clock_timestamp() WHERE id=$1`, v.ID, status, reason)
	}
	if err == nil {
		err = a.agentEventTx(ctx, tx, v.ID, pentagicore.Event{Type: "run.updated", Status: status, Message: reason})
	}
	if err == nil && status == "waiting_input" {
		a.mailAgentRun(ctx, tx, v, "agent_waiting", status, reason)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (a *App) agentToolCall(ctx context.Context, v agentRun, callID, name string, args json.RawMessage) (string, error) {
	if err := a.checkAgent(ctx, v); err != nil {
		return "", err
	}
	if callID == "" || len(callID) > 300 {
		return "", errors.New("도구 호출 식별자가 올바르지 않습니다")
	}
	hash := digest(name + ":" + string(args))
	tag, err := a.DB.Exec(ctx, `INSERT INTO agent_tool_receipts(run_id,call_id,name,arguments_hash,status) VALUES($1,$2,$3,$4,'started') ON CONFLICT DO NOTHING`, v.ID, callID, name, hash)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		var storedName, storedHash, status, result, reason string
		if err = a.DB.QueryRow(ctx, `SELECT name,arguments_hash,status,result_encrypted,error_text FROM agent_tool_receipts WHERE run_id=$1 AND call_id=$2`, v.ID, callID).Scan(&storedName, &storedHash, &status, &result, &reason); err != nil {
			return "", err
		}
		if storedName != name || storedHash != hash {
			return "", errors.New("같은 도구 호출 ID의 인수가 변경되었습니다")
		}
		if status == "started" {
			return `{"status":"unknown","replayed":false,"detail":"이전 도구 처리 결과를 확정할 수 없어 재실행하지 않았습니다. 기존 진단 상태를 조회하세요."}`, nil
		}
		if reason != "" {
			return "", errors.New(reason)
		}
		return a.decrypt(result)
	}
	out, callErr := a.agentTool(ctx, v, name, args)
	cipher, e := a.encrypt(out)
	if e != nil {
		return "", e
	}
	reason := ""
	status := "completed"
	if callErr != nil {
		reason = maskAgentText(callErr.Error())
		status = "failed"
	}
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, e = a.DB.Exec(persist, `UPDATE agent_tool_receipts SET status=$3,result_encrypted=$4,error_text=$5,updated_at=now() WHERE run_id=$1 AND call_id=$2 AND status='started'`, v.ID, callID, status, cipher, reason)
	if e != nil {
		return "", errors.New("도구 처리 결과 저장을 확인할 수 없습니다. 같은 작업을 재실행하지 마세요")
	}
	return out, callErr
}
