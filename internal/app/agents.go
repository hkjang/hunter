package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hkjang/hunter/internal/pentagicore"
	"github.com/jackc/pgx/v5"
)

type agentRun struct {
	ID              string           `json:"id"`
	OwnerID         string           `json:"owner_id"`
	KeyID           string           `json:"-"`
	ServiceID       string           `json:"service_id"`
	ServiceName     string           `json:"service_name"`
	ScopeID         string           `json:"scope_id"`
	Title           string           `json:"title"`
	Status          string           `json:"status"`
	Prompt          string           `json:"prompt,omitempty"`
	Result          string           `json:"result,omitempty"`
	Error           string           `json:"error,omitempty"`
	PolicyHash      string           `json:"-"`
	Limits          map[string]any   `json:"limits"`
	Tasks           []map[string]any `json:"tasks"`
	ModelCalls      int              `json:"model_calls"`
	ToolCalls       int              `json:"tool_calls"`
	InputTokens     int64            `json:"input_tokens"`
	OutputTokens    int64            `json:"output_tokens"`
	CancelRequested bool             `json:"cancel_requested"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	FinishedAt      *time.Time       `json:"finished_at,omitempty"`
}
type agentRunContextKey struct{}

func (a *App) initAgents(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `
 CREATE TABLE IF NOT EXISTS agent_runs (
 id text PRIMARY KEY,owner_id text NOT NULL REFERENCES users(id),credential_key_id text NOT NULL DEFAULT '',
 service_id text NOT NULL REFERENCES resources(id),service_name text NOT NULL,scope_id text NOT NULL,title text NOT NULL,
 status text NOT NULL DEFAULT 'queued',prompt text NOT NULL,result text NOT NULL DEFAULT '',error text NOT NULL DEFAULT '',
 policy_hash text NOT NULL,limits jsonb NOT NULL,tasks jsonb NOT NULL DEFAULT '[]',
 model_calls integer NOT NULL DEFAULT 0,tool_calls integer NOT NULL DEFAULT 0,input_tokens bigint NOT NULL DEFAULT 0,output_tokens bigint NOT NULL DEFAULT 0,
 cancel_requested boolean NOT NULL DEFAULT false,lease_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),finished_at timestamptz);
 CREATE INDEX IF NOT EXISTS agent_runs_service_created ON agent_runs(service_id,created_at DESC);
 CREATE INDEX IF NOT EXISTS agent_runs_status ON agent_runs(status,created_at);
 CREATE TABLE IF NOT EXISTS agent_events (
 id bigserial PRIMARY KEY,run_id text NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,payload text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
 CREATE INDEX IF NOT EXISTS agent_events_run_id ON agent_events(run_id,id);
 CREATE TABLE IF NOT EXISTS agent_run_scans (
 run_id text NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,scan_id text NOT NULL REFERENCES resources(id) ON DELETE CASCADE,request_hash text NOT NULL,
 PRIMARY KEY(run_id,request_hash),UNIQUE(scan_id));
 CREATE TABLE IF NOT EXISTS agent_memory (
 id text PRIMARY KEY,owner_id text NOT NULL REFERENCES users(id),service_id text NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
 title text NOT NULL,content text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
 CREATE INDEX IF NOT EXISTS agent_memory_owner_service ON agent_memory(owner_id,service_id,created_at DESC);
 `)
	return err
}

const agentColumns = `id,owner_id,credential_key_id,service_id,service_name,scope_id,title,status,prompt,result,error,policy_hash,limits,tasks,model_calls,tool_calls,input_tokens,output_tokens,cancel_requested,created_at,updated_at,finished_at`

func scanAgent(row pgx.Row) (agentRun, error) {
	var v agentRun
	err := row.Scan(&v.ID, &v.OwnerID, &v.KeyID, &v.ServiceID, &v.ServiceName, &v.ScopeID, &v.Title, &v.Status, &v.Prompt, &v.Result, &v.Error, &v.PolicyHash, &v.Limits, &v.Tasks, &v.ModelCalls, &v.ToolCalls, &v.InputTokens, &v.OutputTokens, &v.CancelRequested, &v.CreatedAt, &v.UpdatedAt, &v.FinishedAt)
	return v, err
}
func (a *App) agentRun(ctx context.Context, id string) (agentRun, error) {
	return scanAgent(a.DB.QueryRow(ctx, `SELECT `+agentColumns+` FROM agent_runs WHERE id=$1`, id))
}
func agentTerminal(status string) bool {
	return hasString([]string{"completed", "failed", "cancelled", "inconclusive"}, status)
}
func hasAgentReadScopes(u User) bool {
	for _, scope := range []string{"agents:read", "services:read", "findings:read", "scans:read"} {
		if !hasString(u.Scopes, scope) {
			return false
		}
	}
	return true
}
func (a *App) canReadAgent(ctx context.Context, u User, v agentRun) bool {
	s, err := a.resource(ctx, "services", v.ServiceID)
	return err == nil && hasAgentReadScopes(u) && a.canAccess(ctx, u, s)
}
func (a *App) agentOutput(ctx context.Context, v agentRun, detail bool, u User) map[string]any {
	if detail {
		v.Prompt, _ = a.decrypt(v.Prompt)
		if v.Result != "" {
			v.Result, _ = a.decrypt(v.Result)
		}
	} else {
		v.Prompt = ""
		v.Result = ""
		v.Tasks = nil
	}
	raw, _ := json.Marshal(v)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["engine"] = "pentagi"
	out["upstream_commit"] = pentagicore.UpstreamCommit
	actions := []string{}
	if hasString(u.Scopes, "agents:write") {
		if agentTerminal(v.Status) {
			actions = append(actions, "retry")
		} else if !v.CancelRequested {
			actions = append(actions, "stop")
		}
	}
	var pauseRequested bool
	var resumeCount int
	var activeMS int64
	controlUpdated := v.UpdatedAt
	_ = a.DB.QueryRow(ctx, `SELECT pause_requested,resume_count,active_ms,control_updated_at FROM agent_run_control WHERE run_id=$1`, v.ID).Scan(&pauseRequested, &resumeCount, &activeMS, &controlUpdated)
	if hasString(u.Scopes, "agents:write") && hasString(u.Scopes, "ai:use") && hasAgentReadScopes(u) && !agentTerminal(v.Status) && !v.CancelRequested {
		actions = append(actions, "input")
		if hasString([]string{"queued", "running", "waiting_approval"}, v.Status) && !pauseRequested {
			actions = append(actions, "pause")
		}
		if hasString([]string{"paused", "waiting_provider", "waiting_input"}, v.Status) {
			actions = append(actions, "resume")
		}
	}
	out["control_updated_at"] = controlUpdated
	out["pause_requested"] = pauseRequested
	out["resume_count"] = resumeCount
	out["active_ms"] = activeMS
	out["allowed_actions"] = actions
	if detail {
		var last int64
		_ = a.DB.QueryRow(ctx, `SELECT coalesce(max(id),0) FROM agent_events WHERE run_id=$1`, v.ID).Scan(&last)
		out["last_event_id"] = last
		inputs := []map[string]any{}
		rows, e := a.DB.Query(ctx, `SELECT id,author_id,content_encrypted,created_at FROM agent_inputs WHERE run_id=$1 ORDER BY id LIMIT 20`, v.ID)
		if e == nil {
			for rows.Next() {
				var id int64
				var author, cipher string
				var created time.Time
				if rows.Scan(&id, &author, &cipher, &created) == nil {
					if text, e := a.decrypt(cipher); e == nil {
						inputs = append(inputs, map[string]any{"id": id, "author_id": author, "message": text, "created_at": created})
					}
				}
			}
			rows.Close()
		}
		out["inputs"] = inputs
		out["additional_input_count"] = len(inputs)

		scans := []map[string]any{}
		if hasString(u.Scopes, "scans:read") {
			rows, err := a.DB.Query(ctx, `SELECT r.id,r.kind,r.owner_id,r.data,r.created_at,r.updated_at FROM resources r JOIN agent_run_scans s ON s.scan_id=r.id WHERE s.run_id=$1 ORDER BY r.created_at`, v.ID)
			if err == nil {
				for rows.Next() {
					r, e := scanResource(rows)
					if e == nil && a.canAccess(ctx, u, r) {
						scans = append(scans, a.resourceOutput(r))
					}
				}
				rows.Close()
			}
		}
		out["scans"] = scans
		if out["tasks"] == nil {
			out["tasks"] = []any{}
		}
	}
	return out
}
func (a *App) registerAgents(m *http.ServeMux) {
	m.HandleFunc("GET /api/agent-runs", a.protect("agents:read", a.listAgentRuns))
	m.HandleFunc("POST /api/agent-runs", a.protect("agents:write", a.createAgentRun))
	m.HandleFunc("GET /api/agent-runs/{id}", a.protect("agents:read", a.getAgentRun))
	m.HandleFunc("GET /api/agent-runs/{id}/events", a.protect("agents:read", a.streamAgentEvents))
	m.HandleFunc("POST /api/agent-runs/{id}/stop", a.protect("agents:write", a.stopAgentRun))
}
func (a *App) listAgentRuns(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if !hasAgentReadScopes(u) {
		fail(w, 403, "에이전트·서비스·발견 건·진단 조회 권한이 필요합니다")
		return
	}
	rows, err := a.DB.Query(r.Context(), `SELECT `+strings.Join(prefixColumns(agentColumns, "a."), ",")+` FROM agent_runs a JOIN resources s ON s.id=a.service_id AND s.kind='services' WHERE ($1 OR s.owner_id=$2 OR ($3<>'' AND s.data->>'team'=$3)) ORDER BY a.created_at DESC LIMIT 1000`, elevated(u), u.ID, leadTeam(u))
	if err != nil {
		fail(w, 500, "에이전트 실행 목록을 읽을 수 없습니다")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		v, e := scanAgent(rows)
		if e != nil {
			fail(w, 500, "실행 목록 해석 실패")
			return
		}
		out = append(out, a.agentOutput(r.Context(), v, false, u))
	}
	if rows.Err() != nil {
		fail(w, 500, "실행 목록 조회 실패")
		return
	}
	jsonResponse(w, 200, out)
}
func prefixColumns(s, prefix string) []string {
	out := strings.Split(s, ",")
	for i := range out {
		out[i] = prefix + out[i]
	}
	return out
}
func (a *App) createAgentRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ServiceID string `json:"service_id"`
		ScopeID   string `json:"scope_id"`
		Prompt    string `json:"prompt"`
	}
	if decode(r, &in) != nil || strings.TrimSpace(in.Prompt) == "" || len(in.Prompt) > 32000 {
		fail(w, 400, "진단 목표를 32,000바이트 이내로 입력하세요")
		return
	}
	u := currentUser(r)
	for _, s := range []string{"agents:read", "ai:use", "services:read", "findings:read", "scans:read"} {
		if !hasString(u.Scopes, s) {
			fail(w, 403, "에이전트·AI·서비스 권한을 확인하세요")
			return
		}
	}
	cfg, err := a.setting(r.Context(), "agents")
	if err != nil || !asBool(cfg["enabled"]) {
		fail(w, 409, "관리자 설정에서 에이전트 진단을 활성화하세요")
		return
	}
	ai, err := a.setting(r.Context(), "ai")
	if err != nil {
		fail(w, 503, "AI 설정을 읽을 수 없습니다")
		return
	}
	platformEnabled, err := a.platformModelsEnabled(r.Context())
	if err != nil {
		fail(w, 503, "모델 연결 설정을 읽을 수 없습니다")
		return
	}
	service, err := a.resource(r.Context(), "services", in.ServiceID)
	if err != nil || !a.canAccess(r.Context(), u, service) {
		fail(w, 404, "접근 가능한 서비스가 필요합니다")
		return
	}
	_, scope, policy, err := a.scanPolicy(r.Context(), map[string]any{"service_id": in.ServiceID, "scope_id": in.ScopeID})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var emergency bool
	if a.DB.QueryRow(r.Context(), `SELECT emergency FROM domain_runtime WHERE id=1`).Scan(&emergency) != nil || emergency {
		fail(w, 409, "긴급 중지 상태에서는 실행할 수 없습니다")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "실행을 준비할 수 없습니다")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,42))`, u.ID); err != nil {
		fail(w, 500, "실행 잠금을 준비할 수 없습니다")
		return
	}
	var active int
	err = tx.QueryRow(r.Context(), `SELECT count(*) FROM agent_runs WHERE owner_id=$1 AND status IN ('queued','running','waiting_approval','stopping','paused','waiting_provider','waiting_input')`, u.ID).Scan(&active)
	if err != nil {
		fail(w, 500, "진행 중인 실행을 확인할 수 없습니다")
		return
	}
	if active >= 3 {
		fail(w, 429, "사용자당 진행 중인 에이전트 실행은 최대 3개입니다")
		return
	}
	id := newID()
	prompt, err := a.encrypt(maskAgentText(strings.TrimSpace(in.Prompt)))
	if err != nil {
		fail(w, 500, "진단 목표를 보호할 수 없습니다")
		return
	}
	limits := cloneMap(cfg)
	limits["max_tokens"] = ai["max_tokens"]
	limits["context_window"] = ai["context_window"]
	limits["model"] = ai["model"]
	if platformEnabled {
		limits["max_tokens"] = 262144
		limits["context_window"] = 262144
		limits["model"] = "role-routed"
	}
	raw, _ := json.Marshal(limits)
	title := str(service.Data, "name") + " 에이전트 진단"
	_, err = tx.Exec(r.Context(), `INSERT INTO agent_runs(id,owner_id,credential_key_id,service_id,service_name,scope_id,title,prompt,policy_hash,limits) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, u.ID, u.KeyID, service.ID, str(service.Data, "name"), scope.ID, title, prompt, policy.Fingerprint, raw)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO agent_run_control(run_id,control_updated_at) SELECT id,updated_at FROM agent_runs WHERE id=$1`, id)
	}
	if err == nil {
		err = a.agentEventTx(r.Context(), tx, id, pentagicore.Event{Type: "run.updated", Status: "queued", Message: "에이전트 진단을 대기열에 등록했습니다"})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "에이전트 실행을 저장하지 못했습니다")
		return
	}
	a.audit(r, "agent.request", id, map[string]any{"service_id": service.ID, "engine": "pentagi", "upstream_commit": pentagicore.UpstreamCommit})
	run, err := a.agentRun(r.Context(), id)
	if err != nil {
		fail(w, 500, "실행을 읽지 못했습니다")
		return
	}
	jsonResponse(w, 201, a.agentOutput(r.Context(), run, true, u))
}
func (a *App) getAgentRun(w http.ResponseWriter, r *http.Request) {
	v, err := a.agentRun(r.Context(), r.PathValue("id"))
	if err != nil || !a.canReadAgent(r.Context(), currentUser(r), v) {
		fail(w, 404, "에이전트 실행을 찾을 수 없습니다")
		return
	}
	jsonResponse(w, 200, a.agentOutput(r.Context(), v, true, currentUser(r)))
}
func (a *App) stopAgentRun(w http.ResponseWriter, r *http.Request) {
	v, err := a.agentRun(r.Context(), r.PathValue("id"))
	if err != nil || !a.canReadAgent(r.Context(), currentUser(r), v) {
		fail(w, 404, "에이전트 실행을 찾을 수 없습니다")
		return
	}
	if agentTerminal(v.Status) {
		fail(w, 409, "이미 종료된 실행입니다")
		return
	}
	if err = a.cancelAgent(r.Context(), v.ID, "사용자가 실행을 중지했습니다"); err != nil {
		fail(w, 500, "실행을 중지하지 못했습니다")
		return
	}
	a.audit(r, "agent.stop", v.ID, nil)
	v, _ = a.agentRun(r.Context(), v.ID)
	jsonResponse(w, 202, a.agentOutput(r.Context(), v, true, currentUser(r)))
}
func (a *App) cancelAgent(ctx context.Context, id, reason string) error {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var status string
	if err = tx.QueryRow(ctx, `SELECT status FROM agent_runs WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		return err
	}
	if agentTerminal(status) {
		return nil
	}
	next := "stopping"
	if hasString([]string{"queued", "paused", "waiting_provider", "waiting_input"}, status) {
		next = "cancelled"
	}
	_, err = tx.Exec(ctx, `UPDATE agent_runs SET cancel_requested=true,status=$2,error=$3,updated_at=now(),finished_at=CASE WHEN $2='cancelled' THEN now() ELSE finished_at END WHERE id=$1`, id, next, reason)
	if err == nil {
		err = cancelAgentScans(ctx, tx, id)
	}
	if err != nil {
		return err
	}
	if err = a.agentEventTx(ctx, tx, id, pentagicore.Event{Type: "run.updated", Status: next, Message: reason}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func cancelAgentScans(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE scan_jobs SET status='cancelled',lease_until=NULL WHERE scan_id IN (SELECT id FROM resources WHERE kind='scans' AND data->>'agent_run_id'=$1 UNION SELECT scan_id FROM agent_run_scans WHERE run_id=$1) AND status IN ('ready','leased','blocked')`, id)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE resources SET data=data||jsonb_build_object('status','cancelled','finished_at',now()),updated_at=now() WHERE id IN (SELECT id FROM resources WHERE kind='scans' AND data->>'agent_run_id'=$1 UNION SELECT scan_id FROM agent_run_scans WHERE run_id=$1) AND data->>'status' IN ('queued','running','pending_approval')`, id)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE resources SET data=data||'{"status":"cancelled"}'::jsonb,updated_at=now() WHERE kind='approvals' AND data->>'scan_id' IN (SELECT id FROM resources WHERE kind='scans' AND data->>'agent_run_id'=$1 UNION SELECT scan_id FROM agent_run_scans WHERE run_id=$1) AND data->>'status'='pending'`, id)
	}
	return err
}
func (a *App) agentEvent(ctx context.Context, id string, event pentagicore.Event) {
	// Log data is bounded, redacted and encrypted independently of its queryable sequence.
	event.Message = maskAgentText(event.Message)
	if len(event.Message) > 64000 {
		event.Message = event.Message[:64000] + "…"
	}
	if event.Data != nil {
		if safe, ok := redactAgentValue(event.Data).(map[string]any); ok {
			event.Data = safe
		}
	}
	raw, err := json.Marshal(event)
	if err != nil || len(raw) > 200000 {
		return
	}
	cipher, err := a.encrypt(string(raw))
	if err != nil {
		return
	}
	_, _ = a.DB.Exec(ctx, `INSERT INTO agent_events(run_id,payload) VALUES($1,$2)`, id, cipher)
}
func (a *App) streamAgentEvents(w http.ResponseWriter, r *http.Request) {
	v, err := a.agentRun(r.Context(), r.PathValue("id"))
	if err != nil || !a.canReadAgent(r.Context(), currentUser(r), v) {
		fail(w, 404, "실행을 찾을 수 없습니다")
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if h := r.Header.Get("Last-Event-ID"); h != "" {
		if n, e := strconv.ParseInt(h, 10, 64); e == nil && n > after {
			after = n
		}
	}
	if after < 0 {
		after = 0
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	flush, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, "스트리밍을 지원하지 않습니다")
		return
	}
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flush.Flush()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	lastBeat := time.Now()
	for {
		u, e := a.authenticate(r)
		if e != nil || !a.canReadAgent(r.Context(), u, v) {
			return
		}
		rows, e := a.DB.Query(r.Context(), `SELECT id,payload,created_at FROM agent_events WHERE run_id=$1 AND id>$2 ORDER BY id LIMIT 200`, v.ID, after)
		if e != nil {
			return
		}
		count := 0
		for rows.Next() {
			var seq int64
			var cipher string
			var created time.Time
			if rows.Scan(&seq, &cipher, &created) != nil {
				rows.Close()
				return
			}
			plain, e := a.decrypt(cipher)
			if e != nil {
				rows.Close()
				return
			}
			data := map[string]any{}
			if json.Unmarshal([]byte(plain), &data) != nil {
				rows.Close()
				return
			}
			data["id"] = seq
			data["run_id"] = v.ID
			data["created_at"] = created
			raw, _ := json.Marshal(data)
			if _, e = fmt.Fprintf(w, "id: %d\nevent: agent.event\ndata: %s\n\n", seq, raw); e != nil {
				rows.Close()
				return
			}
			after = seq
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return
		}
		flush.Flush()
		if count == 200 {
			continue
		}
		current, e := a.agentRun(r.Context(), v.ID)
		if e != nil {
			return
		}
		if agentTerminal(current.Status) {
			var newest int64
			_ = a.DB.QueryRow(r.Context(), `SELECT coalesce(max(id),0) FROM agent_events WHERE run_id=$1`, v.ID).Scan(&newest)
			if newest <= after {
				_, _ = fmt.Fprint(w, "event: done\ndata: {}\n\n")
				flush.Flush()
				return
			}
		}
		if time.Since(lastBeat) > 10*time.Second {
			_, _ = fmt.Fprint(w, ": heartbeat\n\n")
			flush.Flush()
			lastBeat = time.Now()
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
func (a *App) agentPrincipal(ctx context.Context, v agentRun) (User, error) {
	var u User
	err := a.DB.QueryRow(ctx, `SELECT id,username,name,role,team FROM users WHERE id=$1 AND NOT disabled`, v.OwnerID).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	if err != nil {
		return u, errors.New("실행 소유자 계정을 사용할 수 없습니다")
	}
	u.Scopes = a.roleScopes(ctx, u.Role)
	u.KeyID = v.KeyID
	if v.KeyID != "" {
		var scopes []string
		if a.DB.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, v.KeyID, u.ID).Scan(&scopes) != nil {
			return u, errors.New("실행 API 키가 만료·회전·폐기되었습니다")
		}
		filtered := []string{}
		for _, scope := range u.Scopes {
			if hasString(scopes, scope) {
				filtered = append(filtered, scope)
			}
		}
		u.Scopes = filtered
	}
	for _, scope := range []string{"agents:read", "agents:write", "ai:use", "services:read", "findings:read", "scans:read"} {
		if !hasString(u.Scopes, scope) {
			return u, errors.New("실행에 필요한 현재 권한이 없습니다")
		}
	}
	s, err := a.resource(ctx, "services", v.ServiceID)
	if err != nil || !a.canAccess(ctx, u, s) {
		return u, errors.New("서비스 접근 권한이 변경되었습니다")
	}
	return u, nil
}
