package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hkjang/hunter/internal/pentagicore"
	"github.com/jackc/pgx/v5"
)

type agentTelemetryEvent struct {
	ID       string         `json:"id"`
	TraceID  string         `json:"trace_id"`
	SpanID   string         `json:"span_id"`
	Kind     string         `json:"kind"`
	Status   string         `json:"status"`
	Started  time.Time      `json:"started"`
	Ended    time.Time      `json:"ended"`
	Metadata map[string]any `json:"metadata"`
}

func newTelemetryEvent(kind, status string, start time.Time) agentTelemetryEvent {
	id := newID()
	hash := sha256.Sum256([]byte(id))
	return agentTelemetryEvent{ID: id, TraceID: hex.EncodeToString(hash[:16]), SpanID: hex.EncodeToString(hash[16:24]), Kind: kind, Status: status, Started: start, Ended: time.Now().UTC(), Metadata: map[string]any{}}
}
func (a *App) queueModelTelemetry(ctx context.Context, p agentModelProvider, role string, out pentagicore.CompletionResult, status string, start time.Time) {
	ctl, _ := ctx.Value(modelCallContextKey{}).(modelCallContext)
	a.QueueAgentTelemetry(ctx, ctl.RunID, "model", status, map[string]any{"provider_id": p.ID, "provider_type": p.Type, "role": role, "input_tokens": out.InputTokens, "output_tokens": out.OutputTokens, "duration_ms": time.Since(start).Milliseconds(), "tool_calls": len(out.ToolCalls)})
}

// QueueAgentTelemetry accepts metadata, not event messages, prompts, arguments or
// tool results. DB enqueue has a short independent deadline and never returns an
// error into the business operation; remote delivery belongs to the controller.
func (a *App) QueueAgentTelemetry(ctx context.Context, runID, kind, status string, data map[string]any) {
	if !hasString([]string{"model", "run", "tool", "search", "memory", "execution"}, kind) {
		return
	}
	if !platformCodePattern.MatchString(status) {
		status = "unknown"
	}
	e := newTelemetryEvent(kind, status, time.Now().UTC())
	if modelSafeID.MatchString(runID) {
		sum := sha256.Sum256([]byte(runID))
		e.TraceID = hex.EncodeToString(sum[:16])
	}
	for _, key := range []string{"input_tokens", "output_tokens", "duration_ms", "tool_calls", "model_calls", "result_count", "attempts"} {
		if value, ok := data[key]; ok {
			switch n := value.(type) {
			case int:
				if n >= 0 {
					e.Metadata[key] = n
				}
			case int64:
				if n >= 0 {
					e.Metadata[key] = n
				}
			case float64:
				if n >= 0 && n <= 1e12 {
					e.Metadata[key] = n
				}
			}
		}
	}
	for _, key := range []string{"provider_id", "provider_type", "role", "tool_name"} {
		if s, ok := data[key].(string); ok && modelSafeID.MatchString(s) && maskAgentText(s) == s {
			e.Metadata[key] = s
		}
	}
	if ms := asInt(e.Metadata["duration_ms"]); ms > 0 && ms <= 3600000 {
		e.Started = e.Ended.Add(-time.Duration(ms) * time.Millisecond)
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 150*time.Millisecond)
	defer cancel()
	_ = a.enqueueAgentTelemetry(bounded, e)
}
func (a *App) enqueueAgentTelemetry(ctx context.Context, event agentTelemetryEvent) error {
	c := defaultAgentTelemetry()
	rev, e := a.loadPlatformConfig(ctx, "observability", &c)
	if e != nil || !c.Enabled {
		return e
	}
	groups := map[string][]agentTelemetryExporter{}
	for _, p := range c.Exporters {
		if !p.Enabled {
			continue
		}
		group := p.FailoverGroup
		if group == "" {
			group = "single:" + p.ID
		}
		groups[group] = append(groups[group], p)
	}
	if len(groups) == 0 {
		return nil
	}
	raw, e := json.Marshal(event)
	if e != nil {
		return e
	}
	cipher, e := a.encrypt(string(raw))
	if e != nil {
		return e
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(748621098)`); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM agent_telemetry_outbox LIMIT 10000) capped`).Scan(&n); e != nil {
		return e
	}
	needed := 0
	for _, ps := range groups {
		needed += len(ps[0].Signals)
	}
	if n+needed > 10000 {
		return nil
	}
	for _, ps := range groups {
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].Priority < ps[j].Priority })
		ids := []string{}
		for _, p := range ps {
			ids = append(ids, p.ID)
		}
		idJSON, _ := json.Marshal(ids)
		for _, signal := range ps[0].Signals {
			if _, e = tx.Exec(ctx, `INSERT INTO agent_telemetry_outbox(id,revision,signal,exporter_ids,payload_encrypted) VALUES($1,$2,$3,$4,$5)`, newID(), rev, signal, idJSON, cipher); e != nil {
				return e
			}
		}
	}
	return tx.Commit(ctx)
}
func telemetryAttributes(e agentTelemetryEvent) []any {
	attrs := []any{map[string]any{"key": "hunter.event.kind", "value": map[string]any{"stringValue": e.Kind}}, map[string]any{"key": "hunter.status", "value": map[string]any{"stringValue": e.Status}}}
	keys := []string{}
	for k := range e.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := e.Metadata[k]
		key := "hunter." + k
		if k == "input_tokens" {
			key = "gen_ai.usage.input_tokens"
		}
		if k == "output_tokens" {
			key = "gen_ai.usage.output_tokens"
		}
		var value map[string]any
		switch n := v.(type) {
		case string:
			value = map[string]any{"stringValue": n}
		case float64:
			value = map[string]any{"doubleValue": n}
		case int:
			value = map[string]any{"intValue": strconv.Itoa(n)}
		case int64:
			value = map[string]any{"intValue": strconv.FormatInt(n, 10)}
		default:
			continue
		}
		attrs = append(attrs, map[string]any{"key": key, "value": value})
	}
	if e.Kind == "model" {
		attrs = append(attrs, map[string]any{"key": "langfuse.observation.type", "value": map[string]any{"stringValue": "generation"}})
	}
	return attrs
}
func telemetryWire(signal string, e agentTelemetryEvent, version string) ([]byte, error) {
	resource := map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]any{"stringValue": "hunter"}}, map[string]any{"key": "service.version", "value": map[string]any{"stringValue": version}}}}
	scope := map[string]any{"name": "hunter.agent-platform", "version": "1"}
	attrs := telemetryAttributes(e)
	start, end := strconv.FormatInt(e.Started.UnixNano(), 10), strconv.FormatInt(e.Ended.UnixNano(), 10)
	switch signal {
	case "traces":
		status := 1
		if !hasString([]string{"available", "completed", "finished", "accepted", "running"}, e.Status) {
			status = 2
		}
		span := map[string]any{"traceId": e.TraceID, "spanId": e.SpanID, "name": "hunter." + e.Kind, "kind": 1, "startTimeUnixNano": start, "endTimeUnixNano": end, "attributes": attrs, "status": map[string]any{"code": status}}
		return json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{"resource": resource, "scopeSpans": []any{map[string]any{"scope": scope, "spans": []any{span}}}}}})
	case "logs":
		record := map[string]any{"timeUnixNano": end, "observedTimeUnixNano": end, "severityNumber": 9, "severityText": "INFO", "body": map[string]any{"stringValue": "hunter." + e.Kind + "." + e.Status}, "attributes": attrs, "traceId": e.TraceID, "spanId": e.SpanID}
		return json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{"resource": resource, "scopeLogs": []any{map[string]any{"scope": scope, "logRecords": []any{record}}}}}})
	case "metrics":
		point := map[string]any{"attributes": attrs, "timeUnixNano": end, "asInt": "1"}
		metric := map[string]any{"name": "hunter.agent.events", "unit": "{event}", "sum": map[string]any{"aggregationTemporality": 1, "isMonotonic": true, "dataPoints": []any{point}}}
		return json.Marshal(map[string]any{"resourceMetrics": []any{map[string]any{"resource": resource, "scopeMetrics": []any{map[string]any{"scope": scope, "metrics": []any{metric}}}}}})
	}
	return nil, fmt.Errorf("unsupported signal")
}
func telemetryURL(p agentTelemetryExporter, signal string) string {
	base := strings.TrimRight(p.Endpoint, "/")
	suffix := "/v1/" + signal
	if p.Type == "langfuse" {
		if strings.HasSuffix(base, "/api/public/otel/v1/traces") {
			return base
		}
		if strings.HasSuffix(base, "/api/public/otel") {
			return base + suffix
		}
		return base + "/api/public/otel" + suffix
	}
	if strings.HasSuffix(base, suffix) {
		return base
	}
	return base + suffix
}

// retryable=false includes partial success: OTLP explicitly forbids resending it.
func (a *App) sendTelemetry(ctx context.Context, p agentTelemetryExporter, rev time.Time, signal string, event agentTelemetryEvent) (retryable bool, code string) {
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	permit, e := a.platformPermit(ctx, "observability", p.ID, rev, p.platformResilience, timeout)
	if e != nil {
		return true, "configuration_unavailable"
	}
	if !permit {
		return true, "circuit_open"
	}
	start := time.Now()
	defer func() {
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = a.platformOutcome(bounded, "observability", p.ID, rev, code == "accepted", code, time.Since(start))
	}()
	body, e := telemetryWire(signal, event, a.Version)
	if e != nil {
		return false, "invalid_payload"
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", telemetryURL(p, signal), strings.NewReader(string(body)))
	if e != nil {
		return false, "invalid_endpoint"
	}
	req.Header.Set("Content-Type", "application/json")
	if p.Type == "langfuse" {
		req.SetBasicAuth(p.PublicKey, p.APIKey)
		req.Header.Set("x-langfuse-ingestion-version", "4")
	} else if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	client, e := a.outboundClient(ctx, timeout)
	if e != nil {
		return true, "tls_configuration"
	}
	defer client.CloseIdleConnections()
	resp, e := client.Do(req)
	if e != nil {
		return true, "connection_failed"
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return true, "invalid_response"
	}
	if resp.StatusCode == 200 {
		var v map[string]json.RawMessage
		if json.Unmarshal(raw, &v) != nil {
			return false, "invalid_response"
		}
		if part, ok := v["partialSuccess"]; ok && string(part) != "null" {
			return false, "partial_success"
		}
		if part, ok := v["partial_success"]; ok && string(part) != "null" {
			return false, "partial_success"
		}
		return false, "accepted"
	}
	if resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
		return true, fmt.Sprintf("http_%d", resp.StatusCode)
	}
	return false, fmt.Sprintf("http_%d", resp.StatusCode)
}
func (a *App) StartAgentTelemetry(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick, cancel := context.WithTimeout(ctx, 2*time.Minute)
				_ = a.AgentTelemetryTick(tick)
				cancel()
			}
		}
	}()
}
func (a *App) AgentTelemetryTick(ctx context.Context) error {
	c := defaultAgentTelemetry()
	rev, e := a.loadPlatformConfig(ctx, "observability", &c)
	if e != nil {
		return e
	}
	// Expired metadata is removed in bounded batches, including permanently queued rows.
	if _, e = a.DB.Exec(ctx, `DELETE FROM agent_telemetry_outbox WHERE id IN (SELECT id FROM agent_telemetry_outbox WHERE created_at<now()-make_interval(days=>$1) ORDER BY created_at LIMIT 100)`, c.RetentionDays); e != nil {
		return e
	}
	for i := 0; i < 10; i++ {
		var id, signal, cipher string
		var stored time.Time
		var idsRaw []byte
		var attempts int
		e = a.DB.QueryRow(ctx, `WITH q AS (SELECT id FROM agent_telemetry_outbox WHERE (status IN ('queued','retry') AND available_at<=now()) OR (status='sending' AND lease_until<now()) ORDER BY available_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE agent_telemetry_outbox o SET status='sending',lease_until=now()+interval '6 minutes',attempts=attempts+1 FROM q WHERE o.id=q.id RETURNING o.id,o.signal,o.revision,o.payload_encrypted,o.exporter_ids,o.attempts`).Scan(&id, &signal, &stored, &cipher, &idsRaw, &attempts)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		finish := func(status, code string) error {
			_, e := a.DB.Exec(ctx, `UPDATE agent_telemetry_outbox SET status=$2,last_code=$3,lease_until=NULL,completed_at=CASE WHEN $2 IN ('sent','failed','discarded') THEN now() ELSE NULL END,available_at=now()+make_interval(secs=>$4) WHERE id=$1 AND status='sending'`, id, status, code, min(3600, 1<<min(attempts, 10)))
			return e
		}
		if attempts > c.MaxAttempts {
			if e = finish("failed", "attempt_limit"); e != nil {
				return e
			}
			continue
		}
		if !c.Enabled || !stored.Equal(rev) {
			if e = finish("discarded", "configuration_changed"); e != nil {
				return e
			}
			continue
		}
		raw, e := a.decrypt(cipher)
		if e != nil {
			return e
		}
		var event agentTelemetryEvent
		var ids []string
		if json.Unmarshal([]byte(raw), &event) != nil || json.Unmarshal(idsRaw, &ids) != nil {
			if e = finish("failed", "invalid_payload"); e != nil {
				return e
			}
			continue
		}
		status, code := "failed", "no_exporter"
		retry := false
		for _, providerID := range ids {
			var selected *agentTelemetryExporter
			for _, p := range c.Exporters {
				if p.ID == providerID && p.Enabled && hasString(p.Signals, signal) {
					v := p
					selected = &v
				}
			}
			if selected == nil {
				continue
			}
			again, result := a.sendTelemetry(ctx, *selected, rev, signal, event)
			code = result
			if result == "accepted" {
				status = "sent"
				break
			}
			if !again {
				status = "failed"
				retry = false
				break
			}
			retry = retry || again
		}
		if status != "sent" && retry && attempts < c.MaxAttempts {
			status = "retry"
		}
		if e = finish(status, code); e != nil {
			return e
		}
	}
	return nil
}
