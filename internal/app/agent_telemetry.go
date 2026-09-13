package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

type agentTelemetryExporter struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Enabled          bool     `json:"enabled"`
	Endpoint         string   `json:"endpoint"`
	Signals          []string `json:"signals"`
	APIKey           string   `json:"api_key"`
	APIKeyConfigured bool     `json:"api_key_configured"`
	ClearAPIKey      bool     `json:"clear_api_key"`
	PublicKey        string   `json:"public_key"`
	Priority         int      `json:"priority"`
	FailoverGroup    string   `json:"failover_group"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	platformResilience
}
type agentTelemetryDashboard struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}
type agentTelemetryConfig struct {
	Enabled       bool                      `json:"enabled"`
	Exporters     []agentTelemetryExporter  `json:"exporters"`
	Dashboards    []agentTelemetryDashboard `json:"dashboards"`
	MaxAttempts   int                       `json:"max_attempts"`
	RetentionDays int                       `json:"retention_days"`
}

func defaultAgentTelemetry() agentTelemetryConfig {
	return agentTelemetryConfig{Exporters: []agentTelemetryExporter{}, Dashboards: []agentTelemetryDashboard{}, MaxAttempts: 5, RetentionDays: 7}
}
func normalizeTelemetry(c *agentTelemetryConfig, old agentTelemetryConfig) error {
	if len(c.Exporters) > 10 || len(c.Dashboards) > 10 {
		return errors.New("수집기와 대시보드는 각각 최대 10개입니다")
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 5
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 7
	}
	if c.MaxAttempts < 1 || c.MaxAttempts > 10 || c.RetentionDays < 1 || c.RetentionDays > 90 {
		return errors.New("최대 시도는 1~10회, 보존 기간은 1~90일입니다")
	}
	prior := map[string]agentTelemetryExporter{}
	for _, p := range old.Exporters {
		prior[p.ID] = p
	}
	seen := map[string]bool{}
	groups := map[string]string{}
	for i := range c.Exporters {
		p := &c.Exporters[i]
		if !modelSafeID.MatchString(p.ID) || seen[p.ID] || p.Name == "" || len(p.Name) > 200 {
			return errors.New("수집기의 고유 ID와 이름을 확인하세요")
		}
		seen[p.ID] = true
		if p.Type != "otlp" && p.Type != "langfuse" {
			return errors.New("수집기는 OTLP 또는 Langfuse입니다")
		}
		if e := platformEndpoint(p.Endpoint); e != nil {
			return e
		}
		if p.ClearAPIKey {
			p.APIKey = ""
		} else if p.APIKey == "" {
			p.APIKey = prior[p.ID].APIKey
		}
		if len(p.APIKey) > 16000 || len(p.PublicKey) > 1000 || strings.ContainsAny(p.APIKey+p.PublicKey, "\r\n") {
			return errors.New("수집기 인증정보 형식을 확인하세요")
		}
		if len(p.Signals) == 0 {
			p.Signals = []string{"traces"}
		}
		if len(p.Signals) > 3 {
			return errors.New("수집 신호를 확인하세요")
		}
		signals := map[string]bool{}
		for _, s := range p.Signals {
			if !hasString([]string{"traces", "metrics", "logs"}, s) || signals[s] {
				return errors.New("수집 신호는 traces, metrics, logs를 중복 없이 선택하세요")
			}
			signals[s] = true
		}
		sort.Strings(p.Signals)
		if p.Type == "langfuse" && (len(p.Signals) != 1 || p.Signals[0] != "traces" || p.Enabled && (p.PublicKey == "" || p.APIKey == "")) {
			return errors.New("Langfuse는 traces와 public/secret 키를 사용합니다")
		}
		if p.FailoverGroup != "" {
			if !modelSafeID.MatchString(p.FailoverGroup) {
				return errors.New("대체 그룹 ID 형식을 확인하세요")
			}
			signature := strings.Join(p.Signals, ",")
			if prev, ok := groups[p.FailoverGroup]; ok && prev != signature {
				return errors.New("같은 대체 그룹은 수집 신호가 같아야 합니다")
			}
			groups[p.FailoverGroup] = signature
		}
		if p.TimeoutSeconds == 0 {
			p.TimeoutSeconds = 10
		}
		if p.FailureThreshold == 0 {
			p.FailureThreshold = 3
		}
		if p.CooldownSeconds == 0 {
			p.CooldownSeconds = 30
		}
		if p.Priority < 0 || p.Priority > 1000 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 30 || p.FailureThreshold < 1 || p.FailureThreshold > 20 || p.CooldownSeconds < 5 || p.CooldownSeconds > 3600 {
			return errors.New("수집기의 시간·우선순위·장애 회복 한도를 확인하세요")
		}
		p.ClearAPIKey = false
		p.APIKeyConfigured = false
	}
	for _, d := range c.Dashboards {
		if strings.TrimSpace(d.Name) == "" || len(d.Name) > 200 {
			return errors.New("대시보드 이름을 확인하세요")
		}
		if e := platformEndpoint(d.URL); e != nil {
			return e
		}
	}
	if c.Exporters == nil {
		c.Exporters = []agentTelemetryExporter{}
	}
	if c.Dashboards == nil {
		c.Dashboards = []agentTelemetryDashboard{}
	}
	return nil
}
func telemetryOutput(c agentTelemetryConfig, rev time.Time) map[string]any {
	for i := range c.Exporters {
		p := &c.Exporters[i]
		p.APIKeyConfigured = p.APIKey != ""
		p.APIKey = ""
		p.ClearAPIKey = false
	}
	return map[string]any{"config": c, "updated_at": rev}
}
func (a *App) initAgentTelemetry(ctx context.Context) error {
	_, e := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS agent_telemetry_outbox(id text PRIMARY KEY,revision timestamptz NOT NULL,signal text NOT NULL,exporter_ids jsonb NOT NULL,payload_encrypted text NOT NULL,status text NOT NULL DEFAULT 'queued',attempts integer NOT NULL DEFAULT 0,available_at timestamptz NOT NULL DEFAULT now(),lease_until timestamptz,created_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz,last_code text NOT NULL DEFAULT '');CREATE INDEX IF NOT EXISTS agent_telemetry_due ON agent_telemetry_outbox(available_at) WHERE status IN ('queued','retry','sending');`)
	return e
}
func (a *App) registerAgentTelemetry(m *http.ServeMux) {
	m.HandleFunc("GET /api/agent-platform/observability", a.protect("admin:manage", a.getAgentTelemetry))
	m.HandleFunc("PUT /api/agent-platform/observability", a.protect("admin:manage", a.saveAgentTelemetry))
	m.HandleFunc("POST /api/agent-platform/observability/test", a.protect("admin:manage", a.testAgentTelemetry))
	m.HandleFunc("GET /api/agent-platform/observability/status", a.protect("admin:manage", a.agentTelemetryStatus))
}
func (a *App) getAgentTelemetry(w http.ResponseWriter, r *http.Request) {
	c := defaultAgentTelemetry()
	rev, e := a.loadPlatformConfig(r.Context(), "observability", &c)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	jsonResponse(w, 200, telemetryOutput(c, rev))
}
func (a *App) saveAgentTelemetry(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Config   agentTelemetryConfig `json:"config"`
		Expected string               `json:"expected_updated_at"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "관측 설정 형식을 확인하세요")
		return
	}
	rev, e := a.mutatePlatformConfig(r.Context(), "observability", in.Expected, func(raw json.RawMessage) (any, error) {
		old := defaultAgentTelemetry()
		if e := json.Unmarshal(raw, &old); e != nil {
			return nil, e
		}
		if e := normalizeTelemetry(&in.Config, old); e != nil {
			return nil, e
		}
		return in.Config, nil
	})
	if e != nil {
		platformConfigError(w, e)
		return
	}
	a.audit(r, "agent_platform.observability.save", "", map[string]any{"exporters": len(in.Config.Exporters)})
	jsonResponse(w, 200, telemetryOutput(in.Config, rev))
}
func (a *App) testAgentTelemetry(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       string `json:"exporter_id"`
		Expected string `json:"expected_updated_at"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "시험할 수집기를 선택하세요")
		return
	}
	c := defaultAgentTelemetry()
	rev, e := a.loadPlatformConfig(r.Context(), "observability", &c)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	if !modelRevisionMatches(in.Expected, rev) {
		fail(w, 409, "관측 설정이 변경되었습니다. 다시 조회하세요")
		return
	}
	var selected *agentTelemetryExporter
	for _, p := range c.Exporters {
		if p.ID == in.ID {
			v := p
			selected = &v
		}
	}
	if selected == nil {
		fail(w, 404, "수집기를 찾을 수 없습니다")
		return
	}
	start := time.Now()
	ok := true
	results := []map[string]any{}
	for _, signal := range selected.Signals {
		event := newTelemetryEvent("test", "available", start)
		_, code := a.sendTelemetry(r.Context(), *selected, rev, signal, event)
		success := code == "accepted"
		ok = ok && success
		results = append(results, map[string]any{"signal": signal, "ok": success, "status": code})
	}
	status := "accepted"
	if !ok {
		status = "failed"
	}
	a.audit(r, "agent_platform.observability.test", selected.ID, map[string]any{"status": status})
	jsonResponse(w, 200, map[string]any{"ok": ok, "status": status, "latency_ms": time.Since(start).Milliseconds(), "signals": results})
}
func (a *App) agentTelemetryStatus(w http.ResponseWriter, r *http.Request) {
	items, e := a.platformStatus(r.Context(), "observability")
	if e != nil {
		platformConfigError(w, e)
		return
	}
	for _, m := range items {
		m["exporter_id"] = m["provider_id"]
		m["status"] = m["state"]
		m["consecutive_failures"] = m["failures"]
		m["circuit_open_until"] = m["open_until"]
		m["last_error"] = m["code"]
	}
	summary := map[string]int64{"queued": 0, "retry": 0, "sent": 0, "failed": 0, "discarded": 0, "sending": 0}
	rows, e := a.DB.Query(r.Context(), `SELECT status,count(*) FROM agent_telemetry_outbox GROUP BY status`)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	for rows.Next() {
		var status string
		var n int64
		if rows.Scan(&status, &n) == nil {
			summary[status] = n
		}
	}
	rows.Close()
	recent := []map[string]any{}
	rows, e = a.DB.Query(r.Context(), `SELECT id,status,attempts,created_at,completed_at,last_code FROM agent_telemetry_outbox ORDER BY created_at DESC LIMIT 50`)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, s, code string
		var n int
		var created time.Time
		var completed *time.Time
		if e = rows.Scan(&id, &s, &n, &created, &completed, &code); e != nil {
			platformConfigError(w, e)
			return
		}
		recent = append(recent, map[string]any{"id": id, "status": s, "attempts": n, "created_at": created, "completed_at": completed, "code": code})
	}
	jsonResponse(w, 200, map[string]any{"items": items, "summary": summary, "recent": recent})
}
