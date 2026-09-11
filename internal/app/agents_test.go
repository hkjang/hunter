package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hkjang/hunter/internal/pentagicore"
	"github.com/jackc/pgx/v5"
)

func agentFixture(t *testing.T, a *App, s *httptest.Server, admin string) string {
	t.Helper()
	svc := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "승인된 합성 서비스", "url": "https://agent-test.internal/api", "environment": "staging", "approved": true}, admin, 200)
	id := str(svc, "id")
	mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "명시적 합성 범위", "service_id": id, "approved": true, "allowed_hosts": []string{"agent-test.internal"}, "allowed_paths": []string{"/api"}, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)}, admin, 200)
	mustRequest(t, s, "PUT", "/api/settings/agents", map[string]any{"enabled": true}, admin, 200)
	mustRequest(t, s, "PUT", "/api/settings/ai", map[string]any{"enabled": true, "base_url": "http://127.0.0.1:1/v1", "model": "synthetic-model", "max_tokens": 512}, admin, 200)
	return id
}

func TestAgentStreamingToolCallsAndTruncatedResponses(t *testing.T) {
	packets := []any{
		map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": "검토 ", "tool_calls": []any{map[string]any{"index": 0, "id": "call_1", "type": "function", "function": map[string]any{"name": "recall", "arguments": "{\"query\":"}}}}}}},
		map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": 0, "function": map[string]any{"arguments": "\"허용\"}"}}}}, "finish_reason": "tool_calls"}}, "usage": map[string]any{"prompt_tokens": 25, "completion_tokens": 8}},
	}
	var stream strings.Builder
	for _, packet := range packets {
		raw, _ := json.Marshal(packet)
		fmt.Fprintf(&stream, "data: %s\r\n\r\n", raw)
	}
	stream.WriteString("data: [DONE]\n\n")
	var text strings.Builder
	out, err := readAgentCompletion(strings.NewReader(stream.String()), func(s string) { text.WriteString(s) })
	if err != nil || out.InputTokens != 25 || len(out.ToolCalls) != 1 || out.ToolCalls[0].Arguments != `{"query":"허용"}` || text.String() != "검토 " {
		t.Fatalf("stream reassembly failed: %+v %v", out, err)
	}
	for _, broken := range []string{`data: {"choices":[{"delta":{"content":"incomplete"}}]}` + "\n\n", "data: invalid\n\n", `data: {"error":{"message":"private provider error"}}` + "\n\n"} {
		if _, err := readAgentCompletion(strings.NewReader(broken), nil); err == nil {
			t.Fatal("incomplete or error stream accepted")
		}
	}
}

func TestAgentLongStreamingContentKeepsEveryUTF8Character(t *testing.T) {
	content := strings.Repeat("한글 응답 ", 10000)
	packet, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": content}, "finish_reason": "stop"}}})
	if err != nil {
		t.Fatal(err)
	}
	var actual strings.Builder
	chunks := 0
	result, err := readAgentCompletion(strings.NewReader("data: "+string(packet)+"\n\ndata: [DONE]\n\n"), func(chunk string) {
		if len(chunk) > 8192 || !utf8.ValidString(chunk) {
			t.Errorf("invalid persistence chunk: %d bytes", len(chunk))
		}
		chunks++
		actual.WriteString(chunk)
	})
	if err != nil || chunks < 2 || actual.String() != content || result.Content != content {
		t.Fatalf("long stream lost content: chunks=%d error=%v", chunks, err)
	}
}

func TestAgentAuthorizationRevocationAndSafeTools(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "Scoped agent key", "expires_days": 1, "scopes": []string{"agents:read", "agents:write", "ai:use", "services:read", "findings:read", "findings:write", "scans:read", "scans:write"}}, admin, 201)
	input := map[string]any{"service_id": sid, "prompt": "승인된 자료를 검토하세요"}
	created := mustRequest(t, s, "POST", "/api/agent-runs", input, str(key, "token"), 201)
	ctx := context.Background()
	v, err := a.claimAgent(ctx)
	if err != nil || v.ID != str(created, "id") {
		t.Fatalf("claim: %v", err)
	}
	if err = a.checkAgent(ctx, v); err != nil {
		t.Fatal(err)
	}
	if _, err = a.agentTool(ctx, v, "terminal", json.RawMessage(`{"command":"anything"}`)); err == nil {
		t.Fatal("original shell tool allowed")
	}
	if _, err = a.agentTool(ctx, v, "service_context", json.RawMessage(`{"service_id":"another-service"}`)); err == nil {
		t.Fatal("model overrode fixed service")
	}
	if _, err = a.agentTool(ctx, v, "request_scan", json.RawMessage(`{}`)); err == nil {
		t.Fatal("diagnosis enabled despite admin default")
	}
	candidate, err := a.agentTool(ctx, v, "record_candidate", json.RawMessage(`{"title":"AI 후보","description":"합성 근거","severity":"medium","evidence":"private-test-evidence\nAuthorization: Bearer example-sensitive-value"}`))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	_ = json.Unmarshal([]byte(candidate), &result)
	finding, err := a.resource(ctx, "findings", str(result, "id"))
	if err != nil || str(finding.Data, "status") != "candidate" || str(finding.Data, "source") != "pentagi" {
		t.Fatalf("candidate incorrectly confirmed %+v %v", finding, err)
	}
	raw, _ := json.Marshal(finding.Data)
	if bytes.Contains(raw, []byte("private-test-evidence")) || bytes.Contains(raw, []byte("example-sensitive-value")) {
		t.Fatal("plaintext evidence stored")
	}
	if _, err = a.agentTool(ctx, v, "remember", json.RawMessage(`{"key":"owner-policy","content":"합성 문서는 소유자만 조회합니다"}`)); err != nil {
		t.Fatal(err)
	}
	memory, err := a.agentTool(ctx, v, "recall", json.RawMessage(`{"query":"소유자"}`))
	if err != nil || !strings.Contains(memory, "소유자") {
		t.Fatalf("memory: %s %v", memory, err)
	}
	a.agentEvent(ctx, v.ID, pentagicore.Event{Type: "usage", Message: "password: example-secret", Data: map[string]any{"input_tokens": 12, "result": "Authorization: Bearer other-secret"}})
	var cipher string
	if err = a.DB.QueryRow(ctx, `SELECT payload FROM agent_events WHERE run_id=$1 ORDER BY id DESC LIMIT 1`, v.ID).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	plain, err := a.decrypt(cipher)
	if err != nil || !json.Valid([]byte(plain)) || strings.Contains(plain, "example-secret") || strings.Contains(plain, "other-secret") || !strings.Contains(plain, `"input_tokens":12`) {
		t.Fatalf("event redaction/encoding: %s %v", plain, err)
	}
	mustRequest(t, s, "POST", "/api/keys/"+str(key["key"].(map[string]any), "id")+"/rotate", nil, admin, 200)
	if err = a.checkAgent(ctx, v); err == nil {
		t.Fatal("rotated credential remained authorized")
	}
	if _, err = a.agentTool(ctx, v, "remember", json.RawMessage(`{"key":"revoked","content":"must not persist"}`)); err == nil {
		t.Fatal("revoked key changed memory")
	}
	mustRequest(t, s, "POST", "/api/agent-runs/"+v.ID+"/stop", nil, admin, 202)
	if err = a.agentMutation(ctx, v.ID, func(pgx.Tx) error { t.Fatal("cancelled run entered mutation"); return nil }); err == nil {
		t.Fatal("cancelled mutation accepted")
	}
}

func TestAgentReadScopesAndTerminalTransitions(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	ctx := context.Background()
	create := func() agentRun {
		t.Helper()
		mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "합성 권한 검증"}, admin, 201)
		v, err := a.claimAgent(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	v := create()
	mustRequest(t, s, "DELETE", "/api/scopes/"+v.ScopeID, nil, admin, 409)
	for _, missing := range []string{"findings:read", "scans:read"} {
		scopes := []string{"agents:read", "agents:write", "services:read", "ai:use"}
		for _, scope := range []string{"findings:read", "scans:read"} {
			if scope != missing {
				scopes = append(scopes, scope)
			}
		}
		key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "Restricted transcript", "expires_days": 1, "scopes": scopes}, admin, 201)
		token := str(key, "token")
		mustRequest(t, s, "GET", "/api/agent-runs", nil, token, 403)
		mustRequest(t, s, "GET", "/api/agent-runs/"+v.ID, nil, token, 404)
		mustRequest(t, s, "GET", "/api/agent-runs/"+v.ID+"/events", nil, token, 404)
		mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "denied"}, token, 403)
	}
	assertFinal := func(id, expected string) {
		t.Helper()
		state, err := a.agentRun(ctx, id)
		if err != nil || state.Status != expected {
			t.Fatalf("terminal state: %s %v", state.Status, err)
		}
		var cipher string
		if err = a.DB.QueryRow(ctx, `SELECT payload FROM agent_events WHERE run_id=$1 ORDER BY id DESC LIMIT 1`, id).Scan(&cipher); err != nil {
			t.Fatal(err)
		}
		plain, err := a.decrypt(cipher)
		var event pentagicore.Event
		if err != nil || json.Unmarshal([]byte(plain), &event) != nil || event.Status != expected {
			t.Fatalf("terminal event disagrees with committed state: %s %v", plain, err)
		}
	}
	if err := a.cancelAgent(ctx, v.ID, "test cancellation"); err != nil {
		t.Fatal(err)
	}
	a.finishAgent(v, "completed", "late result", "")
	assertFinal(v.ID, "cancelled")
	a.finishAgent(v, "completed", "second late result", "")
	assertFinal(v.ID, "cancelled")

	v = create()
	if _, err := a.DB.Exec(ctx, `UPDATE agent_runs SET lease_until=now()-interval '1 second' WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	a.finishAgent(v, "completed", "expired result", "")
	assertFinal(v.ID, "inconclusive")
	v = create()
	if _, err := a.DB.Exec(ctx, `UPDATE agent_runs SET lease_until=now()-interval '1 second' WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	a.reapAgents(ctx)
	assertFinal(v.ID, "inconclusive")

	v = create()
	mustRequest(t, s, "PUT", "/api/settings/agents", map[string]any{"max_iterations": 6}, admin, 200)
	if err := a.checkAgent(ctx, v); err == nil {
		t.Fatal("lowered iteration limit did not invalidate active run")
	}
}

func TestAgentCancellationCoversUnlinkedApprovalScan(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	mustRequest(t, s, "PUT", "/api/settings/agents", map[string]any{"allow_diagnosis": true}, admin, 200)
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]any{"approval_enabled": true}, admin, 200)
	mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "합성 승인 대기 취소"}, admin, 201)
	ctx := context.Background()
	v, err := a.claimAgent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.agentPrincipal(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a process failure after RequestScan committed but before the link
	// transaction committed. The intrinsic parent ID must still stop this scan.
	scan, err := a.RequestScan(context.WithValue(ctx, agentRunContextKey{}, v.ID), u, map[string]any{"service_id": sid, "scope_id": v.ScopeID, "profile": "http-baseline"})
	if err != nil || str(scan, "status") != "pending_approval" {
		t.Fatalf("pending scan: %+v %v", scan, err)
	}
	if err = a.cancelAgent(ctx, v.ID, "중지"); err != nil {
		t.Fatal(err)
	}
	child, err := a.resource(ctx, "scans", str(scan, "id"))
	if err != nil || str(child.Data, "status") != "cancelled" {
		t.Fatalf("orphan scan survived: %+v %v", child, err)
	}
	var pending int
	if err = a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='approvals' AND data->>'scan_id'=$1 AND data->>'status'='pending'`, child.ID).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("approval survived cancellation: %d %v", pending, err)
	}
	if err = a.checkAgentChild(ctx, v.ID); err == nil {
		t.Fatal("cancelled parent allowed scan network access")
	}
}

func TestAgentOriginalCoreThroughStreamingHTTPAndSSE(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	sid := agentFixture(t, a, s, admin)
	var sequence, primary atomic.Int64
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input map[string]any
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			http.Error(w, "bad body", 400)
			return
		}
		if input["stream"] != true || input["model"] != "synthetic-model" {
			http.Error(w, "stream/model required", 400)
			return
		}
		available := map[string]bool{}
		if defs, ok := input["tools"].([]any); ok {
			for _, def := range defs {
				function := def.(map[string]any)["function"].(map[string]any)
				available[str(function, "name")] = true
			}
		}
		for _, name := range []string{"terminal", "file", "browser", "web_search"} {
			if available[name] {
				t.Errorf("unsafe original tool exposed: %s", name)
			}
		}
		name, args := "", ""
		switch {
		case available["subtask_list"]:
			name = "subtask_list"
			args = `{"subtasks":[{"title":"서비스 검토","description":"승인된 서비스 근거를 확인합니다."}],"message":"계획"}`
		case available["subtask_patch"]:
			name = "subtask_patch"
			args = `{"operations":[],"message":"추가 작업 없음"}`
		case available["report_result"]:
			name = "report_result"
			args = `{"success":true,"result":"승인된 근거 검토를 완료했습니다. 실제 취약점 확정은 하지 않았습니다.","message":"완료"}`
		case available["done"]:
			if primary.Add(1) == 1 {
				name = "service_context"
				args = `{}`
			} else {
				name = "done"
				args = `{"success":true,"result":"서비스 자료 검토 완료","message":"완료"}`
			}
		default:
		}
		w.Header().Set("Content-Type", "text/event-stream")
		delta := map[string]any{"content": "자료를 확인합니다. "}
		finish := "stop"
		if name != "" {
			finish = "tool_calls"
			delta["tool_calls"] = []any{map[string]any{"index": 0, "id": fmt.Sprintf("call_%d", sequence.Add(1)), "type": "function", "function": map[string]string{"name": name, "arguments": args}}}
		}
		packet := map[string]any{"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10}}
		raw, _ := json.Marshal(packet)
		fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", raw)
	}))
	defer mock.Close()
	mustRequest(t, s, "PUT", "/api/settings/ai", map[string]any{"base_url": mock.URL + "/v1"}, admin, 200)
	created := mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "승인된 서비스 자료를 검토하세요"}, admin, 201)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	core, err := pentagicore.New(ctx, a.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = core.Close()
		cfg := a.DB.Config().ConnConfig
		base := cfg.RuntimeParams["search_path"]
		sum := sha256.Sum256([]byte(base))
		_, _ = a.DB.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+pgx.Identifier{fmt.Sprintf("hunter_pentagi_%x", sum[:6])}.Sanitize()+" CASCADE")
	}()
	v, err := a.claimAgent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan struct{})
	go func() { defer close(completed); a.executeAgent(ctx, core, v) }()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL+"/api/agent-runs/"+v.ID+"/events", nil)
	req.Header.Set("Cookie", admin)
	response, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	<-completed
	state := mustRequest(t, s, "GET", "/api/agent-runs/"+str(created, "id"), nil, admin, 200)
	if state["status"] != "completed" || !strings.Contains(str(state, "result"), "검토") || asInt(state["model_calls"]) < 4 || asInt(state["tool_calls"]) != 1 {
		t.Fatalf("actual original engine run failed: %+v", state)
	}
	for _, fragment := range []string{"event: agent.event", "task.updated", "tool.completed", "message.delta", "event: done"} {
		if !bytes.Contains(body, []byte(fragment)) {
			t.Errorf("missing SSE event %s", fragment)
		}
	}
	if len(state["tasks"].([]any)) == 0 {
		t.Fatal("task snapshot missing")
	}
	var raw string
	_ = a.DB.QueryRow(ctx, `SELECT result FROM agent_runs WHERE id=$1`, v.ID).Scan(&raw)
	if strings.Contains(raw, "승인된 근거") {
		t.Fatal("run output not encrypted")
	}
}
