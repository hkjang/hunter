package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/hunter/internal/pentagicore"
	"github.com/jackc/pgx/v5"
)

// StartAgents runs one durable queue consumer per control server. Browser SSE
// connections are observers; disconnecting a browser never restarts a run.
func (a *App) StartAgents(ctx context.Context) {
	go func() {
		var engine *pentagicore.Engine
		defer func() {
			if engine != nil {
				_ = engine.Close()
			}
		}()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			a.reapAgents(ctx)
			v, err := a.claimAgent(ctx)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				slog.Error("agent queue claim failed", "error", err)
				continue
			}
			if engine == nil {
				engine, err = pentagicore.New(ctx, a.DB)
				if err != nil {
					a.finishAgent(v, "failed", "", "에이전트 코어를 초기화할 수 없습니다: "+err.Error())
					continue
				}
			}
			a.executeAgent(ctx, engine, v)
		}
	}()
}
func (a *App) claimAgent(ctx context.Context) (agentRun, error) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return agentRun{}, err
	}
	defer tx.Rollback(ctx)
	v, err := scanAgent(tx.QueryRow(ctx, `SELECT `+agentColumns+` FROM agent_runs WHERE status='queued' AND NOT cancel_requested ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`))
	if err != nil {
		return v, err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_runs SET status='running',lease_until=now()+interval '20 seconds',updated_at=now() WHERE id=$1`, v.ID)
	if err != nil {
		return v, err
	}
	if err = tx.Commit(ctx); err != nil {
		return v, err
	}
	v.Status = "running"
	return v, nil
}
func (a *App) reapAgents(ctx context.Context) {
	rows, err := a.DB.Query(ctx, `SELECT id FROM agent_runs WHERE status IN ('running','waiting_approval','stopping') AND lease_until<now()`)
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
		tx, e := a.DB.Begin(ctx)
		if e != nil {
			continue
		}
		var status string
		e = tx.QueryRow(ctx, `UPDATE agent_runs SET status=CASE WHEN cancel_requested THEN 'cancelled' ELSE 'inconclusive' END,error='실행 프로세스 연결이 끊어졌습니다. 내용을 확인한 뒤 새 실행을 시작하세요',lease_until=NULL,finished_at=now(),updated_at=now() WHERE id=$1 AND status IN ('running','waiting_approval','stopping') AND lease_until<now() RETURNING status`, id).Scan(&status)
		if e == nil {
			e = cancelAgentScans(ctx, tx, id)
		}
		if e == nil {
			e = a.agentEventTx(ctx, tx, id, pentagicore.Event{Type: "run.updated", Status: status, Message: "작업 임대가 만료되었습니다. 자동으로 재실행하지 않습니다"})
		}
		if e != nil {
			_ = tx.Rollback(ctx)
			continue
		}
		_ = tx.Commit(ctx)
	}
}
func (a *App) executeAgent(parent context.Context, engine *pentagicore.Engine, v agentRun) {
	timeout := time.Duration(asInt(v.Limits["timeout_minutes"])) * time.Minute
	if timeout <= 0 || timeout > time.Hour {
		timeout = 15 * time.Minute
	}
	deadline, stop := context.WithTimeout(parent, timeout)
	defer stop()
	ctx, cancel := context.WithCancelCause(deadline)
	defer cancel(nil)
	done := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.checkAgent(ctx, v); err != nil {
					cancel(err)
					return
				}
				tag, err := a.DB.Exec(ctx, `UPDATE agent_runs SET lease_until=now()+interval '20 seconds' WHERE id=$1 AND NOT cancel_requested AND status IN ('running','waiting_approval') AND lease_until>now()`, v.ID)
				if err != nil || tag.RowsAffected() != 1 {
					cancel(errors.New("에이전트 임대를 갱신하지 못했습니다"))
					return
				}
			}
		}
	}()
	defer func() { close(done); watcher.Wait() }()
	if err := a.checkAgent(ctx, v); err != nil {
		a.finishAgent(v, "inconclusive", "", err.Error())
		return
	}
	prompt, err := a.decrypt(v.Prompt)
	if err != nil {
		a.finishAgent(v, "failed", "", "진단 목표를 복호화하지 못했습니다")
		return
	}
	a.agentEvent(ctx, v.ID, pentagicore.Event{Type: "run.updated", Status: "running", Message: "고정된 PentAGI 코어로 에이전트 진단을 시작합니다"})
	var taskMu sync.Mutex
	tasks := []map[string]any{}
	hooks := pentagicore.Hooks{
		Check: func(c context.Context) error { return a.checkAgent(c, v) },
		Complete: func(c context.Context, in pentagicore.CompletionRequest) (pentagicore.CompletionResult, error) {
			if e := a.checkAgent(c, v); e != nil {
				return pentagicore.CompletionResult{}, e
			}
			return a.agentCompletion(c, v, in)
		},
		ExecuteTool: func(c context.Context, name string, args json.RawMessage) (string, error) {
			return a.agentTool(c, v, name, args)
		},
		Emit: func(event pentagicore.Event) {
			switch event.Type {
			case "phase":
				event.Type = "log"
			case "delta":
				event.Type = "message.delta"
			case "model":
				if event.Status == "finished" {
					event.Type = "usage"
				} else {
					event.Type = "log"
				}
			case "subtask":
				event.Type = "subtask.updated"
			}
			if event.Type == "task.updated" || event.Type == "subtask.updated" {
				taskMu.Lock()
				tasks = mergeAgentTask(tasks, event)
				raw, _ := json.Marshal(redactAgentValue(tasks))
				_, _ = a.DB.Exec(ctx, `UPDATE agent_runs SET tasks=$2,updated_at=now() WHERE id=$1 AND NOT cancel_requested AND status IN ('running','waiting_approval')`, v.ID, raw)
				taskMu.Unlock()
			}
			a.agentEvent(ctx, v.ID, event)
		},
	}
	request := pentagicore.Request{RunID: v.ID, ServiceID: v.ServiceID, Prompt: prompt, MaxIterations: asInt(v.Limits["max_iterations"]), MaxModelCalls: asInt(v.Limits["max_model_calls"]), MaxTokens: asInt(v.Limits["max_tokens"]), ContextWindow: asInt(v.Limits["context_window"])}
	result, err := engine.Run(ctx, request, hooks)
	status := "completed"
	reason := ""
	if result.Status == "waiting" {
		status = "inconclusive"
		reason = "추가 정보가 필요합니다. 결과를 확인하고 목표를 보완해 새 실행을 시작하세요"
	} else if result.Status != "finished" {
		status = "failed"
	}
	if err != nil {
		status = "failed"
		reason = err.Error()
	}
	if cause := context.Cause(ctx); cause != nil {
		status = "inconclusive"
		reason = cause.Error()
		if errors.Is(cause, context.DeadlineExceeded) {
			reason = "설정된 최대 실행 시간을 초과했습니다"
		}
	}
	a.finishAgent(v, status, maskAgentText(result.Summary), maskAgentText(reason))
}
func mergeAgentTask(tasks []map[string]any, event pentagicore.Event) []map[string]any {
	data := map[string]any{}
	raw, _ := json.Marshal(event.Data)
	_ = json.Unmarshal(raw, &data)
	taskID := data["task_id"]
	if taskID == nil {
		taskID = data["id"]
	}
	if taskID == nil {
		return tasks
	}
	index := -1
	for i, t := range tasks {
		if fmt.Sprint(t["id"]) == fmt.Sprint(taskID) {
			index = i
			break
		}
	}
	if index < 0 {
		tasks = append(tasks, map[string]any{"id": taskID, "title": "에이전트 진단", "status": "running", "subtasks": []any{}})
		index = len(tasks) - 1
	}
	if event.Type == "task.updated" {
		for key, value := range data {
			if key != "task_id" {
				tasks[index][key] = value
			}
		}
		if event.Status != "" {
			tasks[index]["status"] = event.Status
		}
		return tasks
	}
	sid := data["subtask_id"]
	if sid == nil {
		return tasks
	}
	subtasks, _ := tasks[index]["subtasks"].([]any)
	found := false
	for i, item := range subtasks {
		child, ok := item.(map[string]any)
		if ok && fmt.Sprint(child["id"]) == fmt.Sprint(sid) {
			for key, value := range data {
				if key != "task_id" && key != "subtask_id" {
					child[key] = value
				}
			}
			child["status"] = event.Status
			subtasks[i] = child
			found = true
			break
		}
	}
	if !found {
		data["id"] = sid
		data["status"] = event.Status
		delete(data, "task_id")
		delete(data, "subtask_id")
		subtasks = append(subtasks, data)
	}
	tasks[index]["subtasks"] = subtasks
	return tasks
}
func (a *App) finishAgent(v agentRun, status, result, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	var current string
	var stopped, live bool
	if err = tx.QueryRow(ctx, `SELECT status,cancel_requested,coalesce(lease_until>now(),false) FROM agent_runs WHERE id=$1 FOR UPDATE`, v.ID).Scan(&current, &stopped, &live); err != nil {
		return
	}
	if agentTerminal(current) {
		return
	}
	if stopped {
		status = "cancelled"
		reason = "사용자 요청으로 실행이 중지되었습니다"
	} else if !live {
		status = "inconclusive"
		reason = "에이전트 작업 임대가 만료되었습니다. 새 실행으로 다시 확인하세요"
	}
	if len(reason) > 2000 {
		reason = reason[:2000]
	}
	reason = strings.TrimSpace(reason)
	encrypted := ""
	if result != "" {
		encrypted, err = a.encrypt(result)
		if err != nil {
			return
		}
	}
	_, err = tx.Exec(ctx, `UPDATE agent_runs SET status=$2,result=$3,error=$4,lease_until=NULL,finished_at=now(),updated_at=now() WHERE id=$1`, v.ID, status, encrypted, reason)
	if err == nil {
		err = cancelAgentScans(ctx, tx, v.ID)
	}
	if err == nil {
		err = a.agentEventTx(ctx, tx, v.ID, pentagicore.Event{Type: "run.updated", Status: status, Message: reason})
	}
	if err != nil || tx.Commit(ctx) != nil {
		return
	}
	user, _ := a.agentPrincipal(ctx, v)
	if user.ID != "" {
		a.agentAudit(ctx, user, "agent.finished", v.ID, map[string]any{"status": status, "service_id": v.ServiceID})
	}
}
func (a *App) agentEventTx(ctx context.Context, tx pgx.Tx, id string, event pentagicore.Event) error {
	event.Message = maskAgentText(event.Message)
	if event.Data != nil {
		event.Data = redactAgentValue(event.Data).(map[string]any)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	cipher, err := a.encrypt(string(raw))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_events(run_id,payload) VALUES($1,$2)`, id, cipher)
	return err
}
