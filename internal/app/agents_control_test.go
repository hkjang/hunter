package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hkjang/hunter/internal/pentagicore"
)

func TestAgentControlRevisionInputsPauseResumeAndReceipt(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	run := mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "합성 자료 확인"}, admin, 201)
	id := str(run, "id")
	path := "/api/agent-runs/" + id
	paused := mustRequest(t, s, "POST", path+"/pause", map[string]any{"expected_updated_at": run["updated_at"]}, admin, 200)
	if str(paused, "status") != "paused" {
		t.Fatalf("queued pause %+v", paused)
	}
	mustRequest(t, s, "POST", path+"/input", map[string]any{"expected_updated_at": run["updated_at"], "message": "보존해야 할 입력"}, admin, 409)
	updated := mustRequest(t, s, "POST", path+"/input", map[string]any{"expected_updated_at": paused["updated_at"], "message": "현재 승인된 근거만 확인하세요"}, admin, 200)
	if str(updated, "status") != "paused" || asInt(updated["additional_input_count"]) != 1 {
		t.Fatalf("input resumed implicitly %+v", updated)
	}
	var cipher string
	if err := a.DB.QueryRow(context.Background(), `SELECT content_encrypted FROM agent_inputs WHERE run_id=$1`, id).Scan(&cipher); err != nil || strings.Contains(cipher, "현재 승인") {
		t.Fatal("input not encrypted", err)
	}
	resumed := mustRequest(t, s, "POST", path+"/resume", map[string]any{"expected_updated_at": updated["updated_at"]}, admin, 200)
	if str(resumed, "status") != "queued" || asInt(resumed["resume_count"]) != 1 {
		t.Fatalf("resume %+v", resumed)
	}
	v, err := a.claimAgent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.agentToolCall(context.Background(), v, "durable-tool-1", "remember", json.RawMessage(`{"key":"영구 기록","content":"합성 보존 자료"}`))
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.agentToolCall(context.Background(), v, "durable-tool-1", "remember", json.RawMessage(`{"key":"영구 기록","content":"합성 보존 자료"}`))
	if err != nil || first != again {
		t.Fatal("completed receipt did not replay result", err)
	}
	after, _ := a.agentRun(context.Background(), id)
	if after.ToolCalls != 1 {
		t.Fatal("tool effect repeated")
	}
	if _, err = a.agentToolCall(context.Background(), v, "durable-tool-1", "remember", json.RawMessage(`{"key":"다른 인수","content":"거부"}`)); err == nil {
		t.Fatal("changed duplicate accepted")
	}
	_, err = a.DB.Exec(context.Background(), `INSERT INTO agent_tool_receipts(run_id,call_id,name,arguments_hash,status) VALUES($1,'unknown-1','remember',$2,'started')`, id, digest(`remember:{"key":"미확정","content":"보류"}`))
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := a.agentToolCall(context.Background(), v, "unknown-1", "remember", json.RawMessage(`{"key":"미확정","content":"보류"}`))
	if err != nil || !strings.Contains(unknown, "unknown") {
		t.Fatal("unknown repeated", err)
	}
	for range 4 {
		large, e := a.encrypt(strings.Repeat("x", 16000))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = a.DB.Exec(context.Background(), `INSERT INTO agent_inputs(run_id,author_id,content_encrypted) VALUES($1,$2,$3)`, id, v.OwnerID, large); e != nil {
			t.Fatal(e)
		}
	}
	state := mustRequest(t, s, "GET", path, nil, admin, 200)
	mustRequest(t, s, "POST", path+"/input", map[string]any{"expected_updated_at": state["updated_at"], "message": strings.Repeat("x", 16000)}, admin, 409)
	var inputCount int
	if e := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM agent_inputs WHERE run_id=$1`, id).Scan(&inputCount); e != nil || inputCount != 5 {
		t.Fatal("input ciphertext bound exceeded", e)
	}

	pending := mustRequest(t, s, "POST", path+"/pause", map[string]any{"expected_updated_at": state["updated_at"]}, admin, 200)
	if str(pending, "status") != "running" || !asBool(pending["pause_requested"]) {
		t.Fatal("active pause must be boundary pending")
	}
	if a.checkAgent(context.Background(), v) != nil {
		t.Fatal("watchdog interrupted in-flight tool")
	}
	if !errors.Is(a.agentBoundary(context.Background(), v), errAgentPaused) {
		t.Fatal("safe boundary ignored pause")
	}
	if err = a.suspendAgent(v, "paused", errAgentPaused.Error(), 0); err != nil {
		t.Fatal(err)
	}
	stopped := mustRequest(t, s, "POST", path+"/stop", nil, admin, 202)
	if str(stopped, "status") != "cancelled" {
		t.Fatal("paused run stop did not finish")
	}
}
func TestAgentNoProviderRetainsDurableRun(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	mustRequest(t, s, "PUT", "/api/settings/ai", map[string]any{"enabled": false}, admin, 200)
	created := mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "연결 없어도 자료 보존"}, admin, 201)
	v, err := a.claimAgent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e, err := pentagicore.New(context.Background(), a.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	a.executeAgent(context.Background(), e, v)
	state := mustRequest(t, s, "GET", "/api/agent-runs/"+str(created, "id"), nil, admin, 200)
	if str(state, "status") != "waiting_provider" || !strings.Contains(str(state, "error"), "재개") {
		t.Fatalf("missing provider terminated run %+v", state)
	}
	mustRequest(t, s, "GET", "/api/services", nil, admin, 200)
	mustRequest(t, s, "GET", "/api/health", nil, admin, 200)
}
func TestAgentPlatformCircuitOneRecoveryAndStaleRevision(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	var cfg map[string]any
	rev, err := a.loadPlatformConfig(ctx, "search", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	policy := platformResilience{FailureThreshold: 1, CooldownSeconds: 30}
	ok, err := a.platformPermit(ctx, "search", "mock", rev, policy, time.Second)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if err = a.platformOutcome(ctx, "search", "mock", rev, false, "timeout", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if ok, _ = a.platformPermit(ctx, "search", "mock", rev, policy, time.Second); ok {
		t.Fatal("open circuit admitted call")
	}
	if _, err = a.DB.Exec(ctx, `UPDATE agent_platform_health SET open_until=now()-interval '1 second' WHERE group_name='search'`); err != nil {
		t.Fatal(err)
	}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := a.platformPermit(ctx, "search", "mock", rev, policy, 10*time.Second)
			if e != nil {
				t.Error(e)
			}
			if ok {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatal("multiple half-open requests", admitted.Load())
	}
	next, err := a.mutatePlatformConfig(ctx, "search", rev.Format(time.RFC3339Nano), func(json.RawMessage) (any, error) { return map[string]any{"secret": "synthetic-secret"}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = a.platformOutcome(ctx, "search", "mock", rev, false, "timeout", time.Second); err != nil {
		t.Fatal(err)
	}
	statuses, err := a.platformStatus(ctx, "search")
	if err != nil || len(statuses) != 0 {
		t.Fatal("stale outcome poisoned new configuration")
	}
	if ok, _ = a.platformPermit(ctx, "search", "mock", rev, policy, time.Second); ok {
		t.Fatal("stale revision admitted")
	}
	if _, err = a.mutatePlatformConfig(ctx, "search", rev.Format(time.RFC3339Nano), func(json.RawMessage) (any, error) { return nil, nil }); err == nil {
		t.Fatal("stale config overwrote")
	}
	var raw string
	if err = a.DB.QueryRow(ctx, `SELECT config_encrypted FROM agent_platform_config WHERE group_name='search'`).Scan(&raw); err != nil || strings.Contains(raw, "synthetic-secret") || next.Equal(rev) {
		t.Fatal("configuration encryption/revision", err)
	}
}

func TestAgentResumeKeepsOriginalKeyAndPolicyBoundary(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "재개 키", "expires_days": 1, "scopes": []string{"agents:read", "agents:write", "ai:use", "services:read", "findings:read", "scans:read"}}, admin, 201)
	run := mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "키 경계 확인"}, str(key, "token"), 201)
	path := "/api/agent-runs/" + str(run, "id")
	paused := mustRequest(t, s, "POST", path+"/pause", map[string]any{"expected_updated_at": run["updated_at"]}, admin, 200)
	mustRequest(t, s, "POST", "/api/keys/"+str(key["key"].(map[string]any), "id")+"/rotate", nil, admin, 200)
	mustRequest(t, s, "POST", path+"/resume", map[string]any{"expected_updated_at": paused["updated_at"]}, admin, 403)
	mustRequest(t, s, "POST", path+"/stop", nil, admin, 202)
	run = mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "범위 경계 확인"}, admin, 201)
	path = "/api/agent-runs/" + str(run, "id")
	paused = mustRequest(t, s, "POST", path+"/pause", map[string]any{"expected_updated_at": run["updated_at"]}, admin, 200)
	if _, err := a.DB.Exec(context.Background(), `UPDATE resources SET data=data||'{"approved":false}' WHERE kind='scopes' AND data->>'service_id'=$1`, sid); err != nil {
		t.Fatal(err)
	}
	mustRequest(t, s, "POST", path+"/resume", map[string]any{"expected_updated_at": paused["updated_at"]}, admin, 409)
}

func TestAgentControlVersionSurvivesAutomaticProgress(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	run := mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "진행 중에도 사용자 제어"}, admin, 201)
	path := "/api/agent-runs/" + str(run, "id")
	version := run["control_updated_at"]
	v, err := a.claimAgent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.DB.Exec(context.Background(), `UPDATE agent_runs SET model_calls=model_calls+1,updated_at=clock_timestamp() WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	input := mustRequest(t, s, "POST", path+"/input", map[string]any{"expected_updated_at": version, "message": "자동 갱신 중 작성한 입력"}, admin, 200)
	if input["control_updated_at"] == version {
		t.Fatal("manual control did not advance its version")
	}
	mustRequest(t, s, "POST", path+"/input", map[string]any{"expected_updated_at": version, "message": "다른 탭의 오래된 입력"}, admin, 409)
	if _, err = a.DB.Exec(context.Background(), `UPDATE agent_runs SET updated_at=clock_timestamp() WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	paused := mustRequest(t, s, "POST", path+"/pause", map[string]any{"expected_updated_at": input["control_updated_at"]}, admin, 200)
	if !asBool(paused["pause_requested"]) {
		t.Fatal("automatic progress blocked pause")
	}
}

func TestAgentPlatformModelsEnablePublicCapabilityWithoutLegacyAI(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	mustRequest(t, s, "PUT", "/api/settings/ai", map[string]any{"enabled": false}, admin, 200)
	public := mustRequest(t, s, "GET", "/api/settings/public", nil, admin, 200)
	if asBool(public["ai_enabled"]) {
		t.Fatal("unconfigured AI advertised enabled")
	}
	doc := mustRequest(t, s, "GET", "/api/agent-platform/models", nil, admin, 200)
	mustRequest(t, s, "PUT", "/api/agent-platform/models", map[string]any{"expected_updated_at": doc["updated_at"], "config": map[string]any{"enabled": true, "providers": []any{}, "role_providers": map[string]any{}}}, admin, 200)
	public = mustRequest(t, s, "GET", "/api/settings/public", nil, admin, 200)
	if !asBool(public["ai_enabled"]) {
		t.Fatal("native-only AI unavailable in UI")
	}
	run := mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "역할별 모델 토큰 상한 확인"}, admin, 201)
	limits := run["limits"].(map[string]any)
	if asInt(limits["max_tokens"]) != 262144 || asInt(limits["context_window"]) != 262144 {
		t.Fatal("native models inherited legacy token limits")
	}
}

func TestAgentOptionalExecutionUnavailableDoesNotAbortAnalysis(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	mustRequest(t, s, "PUT", "/api/settings/agents", map[string]any{"allow_diagnosis": true}, admin, 200)
	mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "미연동은 기존 자료로 계속"}, admin, 201)
	v, err := a.claimAgent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.agentToolCall(context.Background(), v, "optional-disabled", "request_scan", json.RawMessage(`{"profile":"isolated","execution_profile_id":"missing"}`))
	if err != nil || !strings.Contains(result, "execution_disabled") || !strings.Contains(result, `"degraded":true`) {
		t.Fatalf("optional setup aborted analysis %s %v", result, err)
	}
	if _, err = a.agentToolCall(context.Background(), v, "after-degraded", "service_context", json.RawMessage(`{}`)); err != nil {
		t.Fatal("local analysis could not continue", err)
	}
	var scans int
	if err = a.DB.QueryRow(context.Background(), `SELECT count(*) FROM resources WHERE kind='scans' AND data->>'service_id'=$1`, sid).Scan(&scans); err != nil || scans != 0 {
		t.Fatal("unavailable setup created scan", err)
	}
}
