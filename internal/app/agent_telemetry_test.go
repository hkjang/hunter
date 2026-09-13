package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func telemetryExporter(id, base string) agentTelemetryExporter {
	return agentTelemetryExporter{ID: id, Name: "합성 수집기", Type: "otlp", Enabled: true, Endpoint: base, Signals: []string{"traces"}, APIKey: "synthetic-collector-secret", Priority: 10, TimeoutSeconds: 1, platformResilience: platformResilience{FailureThreshold: 3, CooldownSeconds: 5}}
}
func saveTelemetryTestConfig(t *testing.T, a *App, c agentTelemetryConfig) time.Time {
	t.Helper()
	old := defaultAgentTelemetry()
	rev, e := a.loadPlatformConfig(context.Background(), "observability", &old)
	if e != nil {
		t.Fatal(e)
	}
	next, e := a.mutatePlatformConfig(context.Background(), "observability", rev.Format(time.RFC3339Nano), func(json.RawMessage) (any, error) { return c, normalizeTelemetry(&c, old) })
	if e != nil {
		t.Fatal(e)
	}
	return next
}
func TestAgentTelemetryProtocolsAndPrivacy(t *testing.T) {
	a, s := modelTestApp(t)
	var mu sync.Mutex
	requests := map[string][]byte{}
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests[r.URL.Path] = b
		mu.Unlock()
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("OTLP content type")
		}
		if strings.Contains(string(b), "NEVER-SEND") || strings.Contains(string(b), "synthetic-collector-secret") {
			t.Error("telemetry leaked content")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	defer mock.Close()
	p := telemetryExporter("collector", mock.URL)
	p.Signals = []string{"traces", "metrics", "logs"}
	saveTelemetryTestConfig(t, a, agentTelemetryConfig{Enabled: true, Exporters: []agentTelemetryExporter{p}, MaxAttempts: 3, RetentionDays: 7})
	a.QueueAgentTelemetry(context.Background(), "synthetic-run", "model", "available", map[string]any{"input_tokens": int64(9), "duration_ms": 15, "provider_type": "anthropic", "prompt": "NEVER-SEND-PROMPT", "evidence": "NEVER-SEND-EVIDENCE", "api_key": "NEVER-SEND-KEY", "arguments": "NEVER-SEND-ARGS"})
	var n int
	if e := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM agent_telemetry_outbox`).Scan(&n); e != nil || n != 3 {
		t.Fatalf("outbox: %d %v", n, e)
	}
	var cipher string
	_ = a.DB.QueryRow(context.Background(), `SELECT payload_encrypted FROM agent_telemetry_outbox LIMIT 1`).Scan(&cipher)
	if strings.Contains(cipher, "input_tokens") {
		t.Fatal("unencrypted outbox")
	}
	plain, e := a.decrypt(cipher)
	if e != nil || strings.Contains(plain, "NEVER-SEND") || !strings.Contains(plain, "input_tokens") {
		t.Fatal("metadata whitelist failed")
	}
	if e = a.AgentTelemetryTick(context.Background()); e != nil {
		t.Fatal(e)
	}
	for _, signal := range []string{"traces", "metrics", "logs"} {
		mu.Lock()
		raw := requests["/v1/"+signal]
		mu.Unlock()
		var p map[string]any
		if len(raw) == 0 || json.Unmarshal(raw, &p) != nil {
			t.Fatalf("missing OTLP %s", signal)
		}
	}
	admin := loginTest(t, s, "admin", "test-password-1234")
	state := mustRequest(t, s, "GET", "/api/agent-platform/observability/status", nil, admin, 200)
	if asInt(state["summary"].(map[string]any)["sent"]) != 3 {
		t.Fatal("delivery count")
	}
	config := mustRequest(t, s, "GET", "/api/agent-platform/observability", nil, admin, 200)
	if strings.Contains(fmtJSON(config), "synthetic-collector-secret") {
		t.Fatal("read secret")
	}
	mustRequest(t, s, "POST", "/api/agent-platform/observability/test", map[string]any{"exporter_id": "collector", "expected_updated_at": config["updated_at"]}, admin, 200)
	lf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "synthetic-public" || p != "synthetic-private" || r.URL.Path != "/api/public/otel/v1/traces" || r.Header.Get("x-langfuse-ingestion-version") != "4" {
			t.Error("Langfuse OTLP protocol")
		}
		io.WriteString(w, `{}`)
	}))
	defer lf.Close()
	lp := telemetryExporter("lf", lf.URL)
	lp.Type = "langfuse"
	lp.PublicKey = "synthetic-public"
	lp.APIKey = "synthetic-private"
	rev := saveTelemetryTestConfig(t, a, agentTelemetryConfig{Enabled: true, Exporters: []agentTelemetryExporter{lp}})
	_, code := a.sendTelemetry(context.Background(), lp, rev, "traces", newTelemetryEvent("model", "available", time.Now()))
	if code != "accepted" {
		t.Fatal(code)
	}
}
func TestAgentTelemetryFailoverPartialRetentionAndFailOpen(t *testing.T) {
	a, _ := modelTestApp(t)
	ctx := context.Background()
	var badCount, goodCount atomic.Int32
	var mode atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badCount.Add(1)
		if mode.Load() == 1 {
			io.WriteString(w, `{"partialSuccess":{"rejectedSpans":"1","errorMessage":"NEVER-LOG"}}`)
			return
		}
		w.WriteHeader(503)
		io.WriteString(w, `{"message":"NEVER-LOG"}`)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { goodCount.Add(1); io.WriteString(w, `{}`) }))
	defer good.Close()
	p, q := telemetryExporter("first", bad.URL), telemetryExporter("second", good.URL)
	p.FailoverGroup = "same"
	q.FailoverGroup = "same"
	q.Priority = 20
	saveTelemetryTestConfig(t, a, agentTelemetryConfig{Enabled: true, Exporters: []agentTelemetryExporter{p, q}, MaxAttempts: 2, RetentionDays: 1})
	if e := a.enqueueAgentTelemetry(ctx, newTelemetryEvent("run", "completed", time.Now())); e != nil {
		t.Fatal(e)
	}
	if e := a.AgentTelemetryTick(ctx); e != nil {
		t.Fatal(e)
	}
	if badCount.Load() != 1 || goodCount.Load() != 1 {
		t.Fatal("collector failover missing")
	}
	mode.Store(1)
	if e := a.enqueueAgentTelemetry(ctx, newTelemetryEvent("run", "completed", time.Now())); e != nil {
		t.Fatal(e)
	}
	if e := a.AgentTelemetryTick(ctx); e != nil {
		t.Fatal(e)
	}
	if goodCount.Load() != 1 {
		t.Fatal("partial success was resent")
	}
	var partial int
	_ = a.DB.QueryRow(ctx, `SELECT count(*) FROM agent_telemetry_outbox WHERE status='failed' AND last_code='partial_success'`).Scan(&partial)
	if partial != 1 {
		t.Fatal("partial result missing")
	}
	if e := a.enqueueAgentTelemetry(ctx, newTelemetryEvent("run", "completed", time.Now())); e != nil {
		t.Fatal(e)
	}
	before := badCount.Load()
	saveTelemetryTestConfig(t, a, defaultAgentTelemetry())
	if e := a.AgentTelemetryTick(ctx); e != nil {
		t.Fatal(e)
	}
	if badCount.Load() != before {
		t.Fatal("old settings replayed")
	}
	_, _ = a.DB.Exec(ctx, `UPDATE agent_telemetry_outbox SET created_at=now()-interval '100 days'`)
	if e := a.AgentTelemetryTick(ctx); e != nil {
		t.Fatal(e)
	}
	var rows int
	_ = a.DB.QueryRow(ctx, `SELECT count(*) FROM agent_telemetry_outbox`).Scan(&rows)
	if rows != 0 {
		t.Fatal("retention incomplete")
	}
	saveTelemetryTestConfig(t, a, agentTelemetryConfig{Enabled: true, Exporters: []agentTelemetryExporter{p}, MaxAttempts: 2, RetentionDays: 1})
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(748621098)`)
	start := time.Now()
	a.QueueAgentTelemetry(ctx, "synthetic-run", "run", "completed", nil)
	if time.Since(start) > time.Second {
		t.Fatal("telemetry blocks business on DB lock")
	}
	_ = tx.Rollback(ctx)
}
func TestAgentTelemetryRetryAndConfigConflict(t *testing.T) {
	a, s := modelTestApp(t)
	ctx := context.Background()
	var calls atomic.Int32
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(429)
		io.WriteString(w, `{}`)
	}))
	defer mock.Close()
	p := telemetryExporter("limited", mock.URL)
	saveTelemetryTestConfig(t, a, agentTelemetryConfig{Enabled: true, Exporters: []agentTelemetryExporter{p}, MaxAttempts: 2, RetentionDays: 7})
	_ = a.enqueueAgentTelemetry(ctx, newTelemetryEvent("model", "available", time.Now()))
	if e := a.AgentTelemetryTick(ctx); e != nil {
		t.Fatal(e)
	}
	var status string
	_ = a.DB.QueryRow(ctx, `SELECT status FROM agent_telemetry_outbox LIMIT 1`).Scan(&status)
	if status != "retry" {
		t.Fatal(status)
	}
	_, _ = a.DB.Exec(ctx, `UPDATE agent_telemetry_outbox SET available_at=now()`)
	if e := a.AgentTelemetryTick(ctx); e != nil {
		t.Fatal(e)
	}
	_ = a.DB.QueryRow(ctx, `SELECT status FROM agent_telemetry_outbox LIMIT 1`).Scan(&status)
	if status != "failed" || calls.Load() != 2 {
		t.Fatal("retry unbounded")
	}
	admin := loginTest(t, s, "admin", "test-password-1234")
	old := mustRequest(t, s, "GET", "/api/agent-platform/observability", nil, admin, 200)
	mustRequest(t, s, "PUT", "/api/agent-platform/observability", map[string]any{"config": old["config"], "expected_updated_at": old["updated_at"]}, admin, 200)
	mustRequest(t, s, "POST", "/api/agent-platform/observability/test", map[string]any{"exporter_id": p.ID, "expected_updated_at": old["updated_at"]}, admin, 409)
}
