package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type agentExecutionServer struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	Endpoint       string `json:"endpoint"`
	CAPEM          string `json:"ca_pem"`
	CertPEM        string `json:"client_cert_pem"`
	KeyPEM         string `json:"client_key_pem"`
	KeyConfigured  bool   `json:"client_key_pem_configured"`
	ClearKey       bool   `json:"clear_client_key_pem"`
	Priority       int    `json:"priority"`
	Network        string `json:"network"`
	ServiceNetwork string `json:"service_network"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	platformResilience
}
type agentExecutionProfile struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Kind      string   `json:"kind"`
	Image     string   `json:"image"`
	ServerIDs []string `json:"server_ids"`
}
type agentExecutionConfig struct {
	Enabled        bool                    `json:"enabled"`
	Servers        []agentExecutionServer  `json:"servers"`
	Profiles       []agentExecutionProfile `json:"profiles"`
	MaxConcurrent  int                     `json:"max_concurrent"`
	TimeoutSeconds int                     `json:"timeout_seconds"`
}

func defaultAgentExecution() agentExecutionConfig {
	return agentExecutionConfig{Servers: []agentExecutionServer{}, Profiles: []agentExecutionProfile{}, MaxConcurrent: 1, TimeoutSeconds: 30}
}

func executionServiceNetwork(s agentExecutionServer) string {
	if s.ServiceNetwork != "" {
		return s.ServiceNetwork
	}
	return s.Network
}

var executionImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,200}@sha256:[a-f0-9]{64}$`)
var executionNetwork = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func (a *App) initAgentExecution(ctx context.Context) error {
	_, e := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS agent_execution_jobs(scan_id text PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,server_id text NOT NULL,server_encrypted text NOT NULL,container_name text NOT NULL UNIQUE,container_id text NOT NULL DEFAULT '',image_id text NOT NULL,profile_id text NOT NULL,revision timestamptz NOT NULL,policy_hash text NOT NULL,status text NOT NULL,result_encrypted text NOT NULL DEFAULT '',code text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());CREATE INDEX IF NOT EXISTS agent_execution_active ON agent_execution_jobs(status,updated_at);`)
	if e == nil {
		_, e = a.DB.Exec(ctx, `ALTER TABLE agent_execution_jobs ADD COLUMN IF NOT EXISTS cleanup_at timestamptz`)
	}
	return e
}
func validateAgentExecution(c *agentExecutionConfig, old agentExecutionConfig) error {
	if len(c.Servers) > 10 || len(c.Profiles) > 20 || c.MaxConcurrent < 1 || c.MaxConcurrent > 4 || c.TimeoutSeconds < 5 || c.TimeoutSeconds > 120 {
		return errors.New("격리 실행은 서버10개·프로파일20개·동시1~4개·제한5~120초입니다")
	}
	prior := map[string]agentExecutionServer{}
	for _, s := range old.Servers {
		prior[s.ID] = s
	}
	seen := map[string]bool{}
	for i := range c.Servers {
		s := &c.Servers[i]
		if !knowledgeID.MatchString(s.ID) || seen[s.ID] || strings.TrimSpace(s.Name) == "" || len(s.Name) > 200 || s.Priority < 0 || s.Priority > 1000 || s.TimeoutSeconds < 5 || s.TimeoutSeconds > 120 || s.FailureThreshold < 1 || s.FailureThreshold > 20 || s.CooldownSeconds < 5 || s.CooldownSeconds > 3600 {
			return errors.New("실행 서버 식별자·이름·시간·회복 한도를 확인하세요")
		}
		seen[s.ID] = true
		if !executionNetwork.MatchString(s.Network) || hasString([]string{"host", "none", "bridge"}, s.Network) {
			return errors.New("별도로 만든 Docker 네트워크 이름을 지정하세요 (host·none·기본bridge 제외)")
		}
		s.ServiceNetwork = strings.TrimSpace(s.ServiceNetwork)
		if len(s.ServiceNetwork) > 200 || !utf8.ValidString(s.ServiceNetwork) || strings.IndexFunc(s.ServiceNetwork, unicode.IsControl) >= 0 {
			return errors.New("서비스 망은 제어 문자가 없는 200바이트 이내 문자열이어야 합니다")
		}
		u, e := url.Parse(s.Endpoint)
		if e != nil || u.Scheme != "https" || knowledgeEndpoint(s.Endpoint) != nil {
			return errors.New("Docker 서버는 mTLS HTTPS 주소만 허용합니다")
		}
		if len(s.CAPEM) > 65536 || len(s.CertPEM) > 65536 || len(s.KeyPEM) > 65536 {
			return errors.New("각 PEM은 64KiB 이내여야 합니다")
		}
		if s.ClearKey && s.KeyPEM != "" {
			return errors.New("인증서 비밀키 교체와 삭제를 함께 지정할 수 없습니다")
		}
		if s.ClearKey {
			s.KeyPEM = ""
		} else if s.KeyPEM == "" {
			s.KeyPEM = prior[s.ID].KeyPEM
		}
		s.ClearKey = false
		s.KeyConfigured = false
		if s.Enabled || s.KeyPEM != "" {
			if _, e = executionTLS(*s); e != nil {
				return e
			}
		}
	}
	profiles := map[string]bool{}
	for _, p := range c.Profiles {
		if !knowledgeID.MatchString(p.ID) || profiles[p.ID] || strings.TrimSpace(p.Name) == "" || len(p.Name) > 200 || !hasString([]string{"http_headers", "tls_certificate", "tcp_connect"}, p.Kind) || !executionImage.MatchString(p.Image) || len(p.ServerIDs) == 0 || len(p.ServerIDs) > 10 {
			return errors.New("고정 프로파일 종류·승인 이미지 digest·서버를 확인하세요")
		}
		profiles[p.ID] = true
		ids := map[string]bool{}
		for _, id := range p.ServerIDs {
			if !seen[id] || ids[id] {
				return errors.New("프로파일에는 등록된 서버를 중복 없이 선택하세요")
			}
			ids[id] = true
		}
	}
	if c.Servers == nil {
		c.Servers = []agentExecutionServer{}
	}
	if c.Profiles == nil {
		c.Profiles = []agentExecutionProfile{}
	}
	return nil
}
func executionTLS(s agentExecutionServer) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if s.CAPEM == "" || !roots.AppendCertsFromPEM([]byte(s.CAPEM)) {
		return nil, errors.New("Docker 서버 CA PEM을 확인하세요")
	}
	cert, e := tls.X509KeyPair([]byte(s.CertPEM), []byte(s.KeyPEM))
	if e != nil {
		return nil, errors.New("Docker 클라이언트 인증서와 비밀키가 일치해야 합니다")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}, nil
}
func (a *App) registerAgentExecution(m *http.ServeMux) {
	m.HandleFunc("GET /api/execution-profiles", a.protect("scans:write", a.listExecutionProfiles))
	m.HandleFunc("GET /api/agent-platform/execution", a.protect("admin:manage", a.getAgentExecution))
	m.HandleFunc("PUT /api/agent-platform/execution", a.protect("admin:manage", a.putAgentExecution))
	m.HandleFunc("POST /api/agent-platform/execution/test", a.protect("admin:manage", a.testAgentExecution))
	m.HandleFunc("GET /api/agent-platform/execution/status", a.protect("admin:manage", a.statusAgentExecution))
}
func executionOutput(c agentExecutionConfig, rev time.Time) map[string]any {
	for i := range c.Servers {
		c.Servers[i].KeyConfigured = c.Servers[i].KeyPEM != ""
		c.Servers[i].KeyPEM = ""
	}
	return map[string]any{"config": c, "updated_at": rev}
}
func (a *App) getAgentExecution(w http.ResponseWriter, r *http.Request) {
	c := defaultAgentExecution()
	rev, e := a.loadPlatformConfig(r.Context(), "execution", &c)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	jsonResponse(w, 200, executionOutput(c, rev))
}
func (a *App) putAgentExecution(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Config   agentExecutionConfig `json:"config"`
		Expected string               `json:"expected_updated_at"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "격리 실행 설정 형식을 확인하세요")
		return
	}
	rev, e := a.mutatePlatformConfig(r.Context(), "execution", in.Expected, func(raw json.RawMessage) (any, error) {
		old := defaultAgentExecution()
		if e := json.Unmarshal(raw, &old); e != nil {
			return nil, e
		}
		if e := validateAgentExecution(&in.Config, old); e != nil {
			return nil, e
		}
		return in.Config, nil
	})
	if e != nil {
		platformConfigError(w, e)
		return
	}
	a.audit(r, "agent.platform.execution.updated", "execution", map[string]any{"servers": len(in.Config.Servers), "profiles": len(in.Config.Profiles)})
	jsonResponse(w, 200, executionOutput(in.Config, rev))
}
func (a *App) statusAgentExecution(w http.ResponseWriter, r *http.Request) {
	items, e := a.platformStatus(r.Context(), "execution")
	if e != nil {
		platformConfigError(w, e)
		return
	}
	var active, uncertain int
	if e = a.DB.QueryRow(r.Context(), `SELECT count(*) FILTER(WHERE status IN ('creating','created','starting','running','uncertain')),count(*) FILTER(WHERE status='uncertain') FROM agent_execution_jobs`).Scan(&active, &uncertain); e != nil {
		platformConfigError(w, e)
		return
	}
	rows, e := a.DB.Query(r.Context(), `SELECT scan_id,server_id,profile_id,status,code,created_at,updated_at FROM agent_execution_jobs ORDER BY updated_at DESC LIMIT 20`)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	defer rows.Close()
	recent := []map[string]any{}
	for rows.Next() {
		var sid, server, profile, status, code string
		var created, updated time.Time
		if e = rows.Scan(&sid, &server, &profile, &status, &code, &created, &updated); e != nil {
			platformConfigError(w, e)
			return
		}
		recent = append(recent, map[string]any{"scan_id": sid, "server_id": server, "profile_id": profile, "status": status, "code": code, "created_at": created, "updated_at": updated})
	}
	if e = rows.Err(); e != nil {
		platformConfigError(w, e)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "summary": map[string]int{"active": active, "uncertain": uncertain}, "recent": recent})
}
func (a *App) testAgentExecution(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ServerID  string `json:"server_id"`
		ProfileID string `json:"profile_id"`
		Expected  string `json:"expected_updated_at"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "시험할 서버를 지정하세요")
		return
	}
	c := defaultAgentExecution()
	rev, e := a.loadPlatformConfig(r.Context(), "execution", &c)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	wanted, e := time.Parse(time.RFC3339Nano, in.Expected)
	if e != nil || !wanted.Equal(rev) {
		fail(w, 409, "최신 실행 설정을 조회하세요")
		return
	}
	var server agentExecutionServer
	for _, s := range c.Servers {
		if s.ID == in.ServerID {
			server = s
		}
	}
	if server.ID == "" {
		fail(w, 404, "서버를 찾을 수 없습니다")
		return
	}
	image := ""
	if in.ProfileID != "" {
		for _, p := range c.Profiles {
			if p.ID == in.ProfileID && hasString(p.ServerIDs, server.ID) {
				image = p.Image
			}
		}
		if image == "" {
			fail(w, 400, "이 서버에 등록된 프로파일이 필요합니다")
			return
		}
	}
	start := time.Now()
	_, checks, code := a.executionPreflight(r.Context(), server, image, rev)
	a.audit(r, "agent.platform.execution.test", server.ID, map[string]any{"code": code})
	jsonResponse(w, 200, map[string]any{"ok": code == "ok", "status": map[bool]string{true: "ok", false: "unavailable"}[code == "ok"], "code": code, "server_id": server.ID, "latency_ms": time.Since(start).Milliseconds(), "checks": checks})
}
