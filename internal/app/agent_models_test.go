package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hkjang/hunter/internal/pentagicore"
)

type byteModelReader struct{ r io.Reader }

func (r byteModelReader) Read(p []byte) (int, error) { return r.r.Read(p[:min(1, len(p))]) }
func modelSSE(parts ...string) string                { return "data: " + strings.Join(parts, "\n\ndata: ") + "\n\n" }
func modelGoodSSE(text string) string {
	b, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": text}, "finish_reason": "stop"}}, "usage": map[string]any{"prompt_tokens": 4, "completion_tokens": 2}})
	return modelSSE(string(b), "[DONE]")
}
func modelFixture(kind string) string {
	switch kind {
	case "anthropic":
		return modelSSE(`{"type":"message_start","message":{"usage":{"input_tokens":9,"output_tokens":0}}}`, `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"한글"}}`, `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"native-call","name":"lookup","input":{}}}`, `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"q\":"}}`, `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"서울\"}"}}`, `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}`, `{"type":"message_stop"}`)
	case "gemini":
		return modelSSE(`{"candidates":[{"index":0,"content":{"parts":[{"text":"한글"},{"functionCall":{"id":"native-call","name":"lookup","args":{"q":"서울"}},"thoughtSignature":"cHJpdmF0ZS1zaWduYXR1cmU="}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":7}}`)
	case "ollama":
		return `{"message":{"content":"한글","thinking":"내부"},"done":false}` + "\n" + `{"message":{"tool_calls":[{"id":"native-call","function":{"name":"lookup","arguments":{"q":"서울"}}}]},"done":true,"done_reason":"stop","prompt_eval_count":9,"eval_count":7}` + "\n"
	default:
		return modelSSE(`{"choices":[{"index":0,"delta":{"content":"한글","tool_calls":[{"index":0,"id":"native-call","type":"function","function":{"name":"lookup","arguments":"{\"q\":"}}]}}]}`, `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"서울\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":9,"completion_tokens":7}}`, "[DONE]")
	}
}
func TestAgentModelsNativeStreams(t *testing.T) {
	for _, kind := range []string{"openai", "anthropic", "gemini", "ollama"} {
		t.Run(kind, func(t *testing.T) {
			ct := "text/event-stream"
			if kind == "ollama" {
				ct = "application/x-ndjson"
			}
			out, metadata, e := readModelWire(byteModelReader{strings.NewReader(modelFixture(kind))}, kind, ct)
			if e != nil {
				t.Fatal(e)
			}
			if out.Content != "한글" || out.InputTokens != 9 || out.OutputTokens != 7 || out.FinishReason != "tool_calls" || len(out.ToolCalls) != 1 {
				t.Fatalf("native conversion: %+v", out)
			}
			if out.ToolCalls[0].Arguments != `{"q":"서울"}` {
				t.Fatal("tool fragments changed")
			}
			if kind == "gemini" && !bytes.Contains(metadata["native-call"], []byte("thoughtSignature")) {
				t.Fatal("signature lost")
			}
			if _, _, e = readModelWire(strings.NewReader(strings.Split(modelFixture(kind), "\n")[0]), kind, ct); kind != "gemini" && e == nil {
				t.Fatal("truncated response accepted")
			}
		})
	}
	for _, input := range []string{modelSSE(`{"type":"error","error":{"message":"secret-upstream"}}`), modelSSE(`{"type":"message_stop"}`)} {
		if _, _, e := readModelWire(strings.NewReader(input), "anthropic", "text/event-stream"); e == nil {
			t.Fatal("empty/error accepted")
		}
	}
}
func modelTestApp(t *testing.T) (*App, *httptest.Server) {
	t.Helper()
	a, original := testApp(t)
	_ = original
	ctx := context.Background()
	if e := a.initAgentPlatform(ctx); e != nil {
		t.Fatal(e)
	}
	if e := a.initAgentProviders(ctx); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	a.registerAuth(mux)
	a.registerKeys(mux)
	a.registerAI(mux)
	a.registerAgentProviders(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return a, s
}
func modelProvider(id, kind, base string) agentModelProvider {
	return agentModelProvider{ID: id, Name: "합성 모델", Type: kind, Enabled: true, BaseURL: base, Model: "synthetic-model", APIKey: "synthetic-model-secret", ContextWindow: 32768, MaxTokens: 4096, Priority: 10, TimeoutSeconds: 5, platformResilience: platformResilience{FailureThreshold: 3, CooldownSeconds: 5}}
}
func saveModelTestConfig(t *testing.T, a *App, c agentModelsConfig) time.Time {
	t.Helper()
	ctx := context.Background()
	old := defaultAgentModels()
	rev, e := a.loadPlatformConfig(ctx, "models", &old)
	if e != nil {
		t.Fatal(e)
	}
	next, e := a.mutatePlatformConfig(ctx, "models", rev.Format(time.RFC3339Nano), func(json.RawMessage) (any, error) { return c, normalizeModelConfig(&c, old) })
	if e != nil {
		t.Fatal(e)
	}
	return next
}
func TestAgentModelsNativeRequestsAndMetadata(t *testing.T) {
	a, _ := modelTestApp(t)
	ctx := withModelCallContext(context.Background(), modelCallContext{RunID: "synthetic-run"})
	for _, kind := range []string{"openai", "anthropic", "gemini", "ollama"} {
		t.Run(kind, func(t *testing.T) {
			var captured map[string]any
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewDecoder(r.Body).Decode(&captured)
				if kind == "gemini" && r.Header.Get("x-goog-api-key") != "synthetic-model-secret" {
					t.Error("Gemini auth")
				}
				if kind == "anthropic" && r.Header.Get("anthropic-version") != "2023-06-01" {
					t.Error("Messages version")
				}
				ct := "text/event-stream"
				if kind == "ollama" {
					ct = "application/x-ndjson"
				}
				w.Header().Set("Content-Type", ct)
				io.WriteString(w, modelFixture(kind))
			}))
			defer mock.Close()
			p := modelProvider("native-"+kind, kind, mock.URL)
			rev := saveModelTestConfig(t, a, agentModelsConfig{Enabled: true, Providers: []agentModelProvider{p}})
			in := pentagicore.CompletionRequest{Role: "assistant", MaxTokens: 4096, ContextWindow: 32768, Messages: []pentagicore.Message{{Role: "system", Content: "규칙"}, {Role: "user", Content: "질문"}}, Tools: []pentagicore.ToolDefinition{{Name: "lookup", Description: "조회", Parameters: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`)}}}
			out, e := a.attemptPlatformModel(ctx, p, rev, in, nil)
			if e != nil {
				t.Fatal(e)
			}
			if out.FinishReason != "tool_calls" {
				t.Fatal("tool calls not normalized")
			}
			if captured == nil {
				t.Fatal("request not sent")
			}
			in.Messages = append(in.Messages, pentagicore.Message{Role: "assistant", Content: out.Content, ToolCalls: out.ToolCalls}, pentagicore.Message{Role: "tool", ToolCallID: "native-call", Content: "허용 결과"})
			body, endpoint, e := a.modelWireRequest(ctx, p, in)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "gemini" {
				if !strings.Contains(endpoint, ":streamGenerateContent?alt=sse") || !bytes.Contains(body, []byte("thoughtSignature")) {
					t.Fatal("Gemini native signature roundtrip")
				}
				other := withModelCallContext(context.Background(), modelCallContext{RunID: "different-run"})
				raw, e := a.loadModelMetadata(other, p, "native-call")
				if e != nil || len(raw) != 0 {
					t.Fatal("cross-run metadata leak")
				}
				p.Model = "other-model"
				raw, e = a.loadModelMetadata(ctx, p, "native-call")
				if e != nil || len(raw) != 0 {
					t.Fatal("cross-provider metadata leak")
				}
			}
		})
	}
	var cipher string
	if e := a.DB.QueryRow(context.Background(), `SELECT metadata_encrypted FROM agent_model_tool_metadata LIMIT 1`).Scan(&cipher); e != nil || strings.Contains(cipher, "cHJpdmF0") {
		t.Fatal("metadata plaintext")
	}
}
func TestAgentModelsFailoverCommitAndConfiguration(t *testing.T) {
	a, s := modelTestApp(t)
	ctx := context.Background()
	var first, second atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, modelSSE(`{"choices":[{"index":0,"delta":{"content":"DO-NOT-COMMIT","tool_calls":[{"index":0,"id":"bad","function":{"name":"request_scan","arguments":"{"}}]}}]}`))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, modelGoodSSE("정상 응답"))
	}))
	defer good.Close()
	p1, p2 := modelProvider("bad", "openai", bad.URL), modelProvider("good", "openai", good.URL)
	saveModelTestConfig(t, a, agentModelsConfig{Enabled: true, Providers: []agentModelProvider{p1, p2}, RoleProviders: map[string][]string{"assistant": {"bad", "good"}}})
	var emitted strings.Builder
	in := pentagicore.CompletionRequest{Role: "assistant", MaxTokens: 256, ContextWindow: 32768, Messages: []pentagicore.Message{{Role: "user", Content: "합성 질문"}}, OnDelta: func(s string) { emitted.WriteString(s) }}
	out, e := a.platformModelCompletion(ctx, map[string]any{}, in)
	if e != nil || out.Content != "정상 응답" || emitted.String() != "정상 응답" || len(out.ToolCalls) != 0 || first.Load() != 1 || second.Load() != 1 {
		t.Fatalf("unsafe failover %v %q", e, emitted.String())
	}
	before := errors.New("current authority revoked")
	c := withModelCallContext(ctx, modelCallContext{Check: func(context.Context) error { return before }})
	if _, e = a.platformModelCompletion(c, map[string]any{}, in); !errors.Is(e, before) || first.Load() != 1 {
		t.Fatal("permission not rechecked")
	}
	saveModelTestConfig(t, a, agentModelsConfig{Enabled: true, Providers: []agentModelProvider{p1}})
	emitted.Reset()
	if _, e = a.platformModelCompletion(ctx, nil, in); !errors.Is(e, ErrAgentModelsUnavailable) || emitted.Len() != 0 {
		t.Fatal("all failed did not become typed unavailable")
	}
	admin := loginTest(t, s, "admin", "test-password-1234")
	old := mustRequest(t, s, "GET", "/api/agent-platform/models", nil, admin, 200)
	if strings.Contains(fmtJSON(old), "synthetic-model-secret") {
		t.Fatal("config secret leaked")
	}
	config := old["config"].(map[string]any)
	mustRequest(t, s, "PUT", "/api/agent-platform/models", map[string]any{"config": config, "expected_updated_at": old["updated_at"]}, admin, 200)
	mustRequest(t, s, "PUT", "/api/agent-platform/models", map[string]any{"config": config, "expected_updated_at": old["updated_at"]}, admin, 409)
	saved := defaultAgentModels()
	_, _ = a.loadPlatformConfig(ctx, "models", &saved)
	if saved.Providers[0].APIKey != "synthetic-model-secret" {
		t.Fatal("blank secret not preserved")
	}
	readonly := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "limited", "scopes": []string{"services:read"}, "expires_days": 1}, admin, 201)
	mustRequest(t, s, "GET", "/api/agent-platform/models", nil, asString(readonly["token"]), 403)
}
func fmtJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestAgentModelsCurrentRevisionBeforeCommit(t *testing.T) {
	a, _ := modelTestApp(t)
	ctx := context.Background()
	started, release := make(chan struct{}), make(chan struct{})
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, modelGoodSSE("old-revision-answer"))
	}))
	defer mock.Close()
	p := modelProvider("revision", "openai", mock.URL)
	c := agentModelsConfig{Enabled: true, Providers: []agentModelProvider{p}}
	saveModelTestConfig(t, a, c)
	var emitted strings.Builder
	result := make(chan error, 1)
	go func() {
		_, e := a.platformModelCompletion(ctx, nil, pentagicore.CompletionRequest{Role: "assistant", Messages: []pentagicore.Message{{Role: "user", Content: "질문"}}, MaxTokens: 256, ContextWindow: 32768, OnDelta: func(s string) { emitted.WriteString(s) }})
		result <- e
	}()
	<-started
	c.Providers[0].Model = "changed-model"
	saveModelTestConfig(t, a, c)
	close(release)
	if e := <-result; !errors.Is(e, ErrAgentModelsUnavailable) || emitted.Len() != 0 {
		t.Fatalf("stale revision emitted answer: %v", e)
	}
	var oldMetadata int
	_ = a.DB.QueryRow(ctx, `SELECT count(*) FROM agent_model_tool_metadata`).Scan(&oldMetadata)
	if oldMetadata != 0 {
		t.Fatal("stale metadata persisted")
	}
}

func TestAgentModelsCopilotAndBoundedLeases(t *testing.T) {
	a, s := modelTestApp(t)
	ctx := context.Background()
	admin := loginTest(t, s, "admin", "test-password-1234")
	me := mustRequest(t, s, "GET", "/api/auth/me", nil, admin, 200)
	u := me["user"].(map[string]any)
	release, held, e := a.acquireModelChat(ctx, asString(u["id"]))
	if e != nil || !held {
		t.Fatal("lease unavailable")
	}
	_, held, e = a.acquireModelChat(ctx, asString(u["id"]))
	if e != nil || held {
		t.Fatal("duplicate user lease allowed")
	}
	if a.DB.Stat().AcquiredConns() != 0 {
		t.Fatal("AI lease retained pool connection")
	}
	release()
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, modelGoodSSE("정상 응답 password=DO-NOT-DISCLOSE"))
	}))
	defer mock.Close()
	saveModelTestConfig(t, a, agentModelsConfig{Enabled: true, Providers: []agentModelProvider{modelProvider("copilot", "openai", mock.URL)}})
	status, body, _ := request(t, s, "POST", "/api/ai/chat", map[string]any{"messages": []map[string]string{{"role": "user", "content": "합성 질문"}}}, admin, true)
	if status != 200 || !strings.Contains(string(body), "정상 응답") || strings.Contains(string(body), "DO-NOT-DISCLOSE") || !strings.Contains(string(body), "[DONE]") {
		t.Fatalf("copilot response failed: %d", status)
	}
	release, held, e = a.acquireModelChat(ctx, asString(u["id"]))
	if e != nil || !held {
		t.Fatal("completed lease not released")
	}
	release()
	saveModelTestConfig(t, a, agentModelsConfig{Enabled: true, Providers: []agentModelProvider{}})
	status, body, _ = request(t, s, "POST", "/api/ai/chat", map[string]any{"messages": []map[string]string{{"role": "user", "content": "합성 질문"}}}, admin, true)
	if status != 200 || !strings.Contains(string(body), "사용 가능한 AI 연결이 없습니다") {
		t.Fatal("unavailable recovery message missing")
	}
}

func TestAgentModelsCommittedUnicodeChunks(t *testing.T) {
	content := strings.Repeat("한글을 온전히 보존합니다", 12000)
	var joined strings.Builder
	chunks := 0
	emitCommittedModel(func(s string) {
		chunks++
		if !utf8.ValidString(s) || len(s) > 8192 {
			t.Fatal("invalid persisted chunk")
		}
		joined.WriteString(s)
	}, content)
	if joined.String() != content || chunks < 2 {
		t.Fatal("long Korean answer lost bytes")
	}
	joined.Reset()
	emitCommittedModel(func(s string) { joined.WriteString(s) }, strings.Repeat("가", 4000)+"\npassword=NEVER-EMIT\n정상 내용")
	if strings.Contains(joined.String(), "NEVER-EMIT") || !strings.Contains(joined.String(), "정상 내용") {
		t.Fatal("chunk masking changed")
	}
}

func TestAgentModelsCopilotParentRevocationBeforeFailover(t *testing.T) {
	a, _ := modelTestApp(t)
	ctx := context.Background()
	userID, serviceID, findingID := newID(), newID(), newID()
	if _, e := a.DB.Exec(ctx, `INSERT INTO users(id,username,name,role,team) VALUES($1,$2,'Synthetic principal','analyst','same-team')`, userID, "model-"+userID); e != nil {
		t.Fatal(e)
	}
	if _, e := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'services',$2,'{"name":"synthetic service","team":"same-team"}')`, serviceID, userID); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]any{"title": "synthetic finding", "service_id": serviceID})
	if _, e := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'findings',$2,$3)`, findingID, userID, body); e != nil {
		t.Fatal(e)
	}
	u := User{ID: userID, Role: "analyst", Team: "same-team", Scopes: a.roleScopes(ctx, "analyst")}
	refs := []modelResourceRef{{Kind: "findings", ID: findingID}}
	if e := a.modelResourcesCurrent(ctx, u, refs); e != nil {
		t.Fatal(e)
	}
	var second atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = a.DB.Exec(ctx, `UPDATE resources SET owner_id='different-owner' WHERE id=$1`, serviceID)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, modelSSE(`{"choices":[{"index":0,"delta":{"content":"UNCOMMITTED"}}]}`))
	}))
	defer first.Close()
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, modelGoodSSE("must not request"))
	}))
	defer next.Close()
	saveModelTestConfig(t, a, agentModelsConfig{Enabled: true, Providers: []agentModelProvider{modelProvider("before", "openai", first.URL), modelProvider("after", "openai", next.URL)}})
	ctl := withModelCallContext(ctx, modelCallContext{Check: func(c context.Context) error { return a.modelResourcesCurrent(c, u, refs) }})
	var emitted strings.Builder
	_, e := a.platformModelCompletion(ctl, nil, pentagicore.CompletionRequest{Role: "copilot", MaxTokens: 256, ContextWindow: 32768, Messages: []pentagicore.Message{{Role: "user", Content: "authorized initial metadata"}}, OnDelta: func(s string) { emitted.WriteString(s) }})
	if e == nil || second.Load() != 0 || emitted.Len() != 0 {
		t.Fatal("revoked parent metadata sent to failover")
	}
}
