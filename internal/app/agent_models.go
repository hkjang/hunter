package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hkjang/hunter/internal/pentagicore"
)

var ErrAgentModelsUnavailable = errors.New("사용 가능한 모델 연결이 없습니다. 관리자 연결 상태 확인 후 재개할 수 있습니다")
var modelSafeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`)
var modelRoles = []string{"default", "primary_agent", "assistant", "simple", "simple_json", "adviser", "generator", "refiner", "searcher", "enricher", "coder", "installer", "pentester", "reflector", "copilot"}

type agentModelProvider struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Enabled          bool   `json:"enabled"`
	BaseURL          string `json:"base_url"`
	Model            string `json:"model"`
	APIKey           string `json:"api_key"`
	APIKeyConfigured bool   `json:"api_key_configured"`
	ClearAPIKey      bool   `json:"clear_api_key"`
	ContextWindow    int    `json:"context_window"`
	MaxTokens        int    `json:"max_tokens"`
	Priority         int    `json:"priority"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	platformResilience
}
type agentModelsConfig struct {
	Enabled       bool                 `json:"enabled"`
	Providers     []agentModelProvider `json:"providers"`
	RoleProviders map[string][]string  `json:"role_providers"`
}

func defaultAgentModels() agentModelsConfig {
	return agentModelsConfig{Providers: []agentModelProvider{}, RoleProviders: map[string][]string{}}
}
func platformEndpoint(s string) error {
	u, e := url.Parse(s)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" || strings.ContainsAny(s, "\r\n") || len(s) > 2048 {
		return errors.New("인증정보·query·fragment 없는 HTTP(S) 주소를 입력하세요")
	}
	return nil
}
func normalizeModelConfig(c *agentModelsConfig, old agentModelsConfig) error {
	if len(c.Providers) > 20 {
		return errors.New("모델 연결은 최대 20개입니다")
	}
	prior := map[string]agentModelProvider{}
	for _, p := range old.Providers {
		prior[p.ID] = p
	}
	seen := map[string]bool{}
	for i := range c.Providers {
		p := &c.Providers[i]
		if !modelSafeID.MatchString(p.ID) || seen[p.ID] || p.ID == "legacy" || strings.HasPrefix(p.ID, "legacy-") {
			return errors.New("모델 ID는 중복 없는 영문·숫자·밑줄·하이픈 1~80자입니다")
		}
		seen[p.ID] = true
		if len(strings.TrimSpace(p.Name)) == 0 || len(p.Name) > 200 || p.Model == "" || len(p.Model) > 200 || strings.ContainsAny(p.Model, "\r\n") {
			return errors.New("모델 이름과 모델 식별자를 확인하세요 (최대 200바이트)")
		}
		if !hasString([]string{"openai", "anthropic", "gemini", "ollama"}, p.Type) {
			return errors.New("지원하지 않는 모델 연결 유형입니다")
		}
		if err := platformEndpoint(p.BaseURL); err != nil {
			return err
		}
		if p.ClearAPIKey {
			p.APIKey = ""
		} else if p.APIKey == "" {
			p.APIKey = prior[p.ID].APIKey
		}
		if len(p.APIKey) > 16000 || strings.ContainsAny(p.APIKey, "\r\n") {
			return errors.New("API 키 형식을 확인하세요")
		}
		if p.Enabled && (p.Type == "anthropic" || p.Type == "gemini") && p.APIKey == "" {
			return errors.New("선택한 활성 연결에는 API 키가 필요합니다")
		}
		if p.ContextWindow == 0 {
			p.ContextWindow = 32768
		}
		if p.MaxTokens == 0 {
			p.MaxTokens = 4096
		}
		if p.TimeoutSeconds == 0 {
			p.TimeoutSeconds = 120
		}
		if p.FailureThreshold == 0 {
			p.FailureThreshold = 3
		}
		if p.CooldownSeconds == 0 {
			p.CooldownSeconds = 30
		}
		if p.ContextWindow < 1024 || p.ContextWindow > 262144 || p.MaxTokens < 1 || p.MaxTokens > p.ContextWindow || p.Priority < 0 || p.Priority > 1000 || p.TimeoutSeconds < 5 || p.TimeoutSeconds > 600 || p.FailureThreshold < 1 || p.FailureThreshold > 20 || p.CooldownSeconds < 5 || p.CooldownSeconds > 3600 {
			return errors.New("토큰·우선순위·시간·장애 회복 한도를 확인하세요")
		}
		p.ClearAPIKey = false
		p.APIKeyConfigured = false
	}
	if c.Providers == nil {
		c.Providers = []agentModelProvider{}
	}
	if c.RoleProviders == nil {
		c.RoleProviders = map[string][]string{}
	}
	for role, ids := range c.RoleProviders {
		if !hasString(modelRoles, role) || len(ids) > 20 {
			return errors.New("역할별 모델 선택을 확인하세요")
		}
		used := map[string]bool{}
		for _, id := range ids {
			if !seen[id] || used[id] {
				return errors.New("역할에는 등록된 모델 ID를 중복 없이 선택하세요")
			}
			used[id] = true
		}
	}
	return nil
}
func agentModelsOutput(c agentModelsConfig, rev time.Time) map[string]any {
	for i := range c.Providers {
		p := &c.Providers[i]
		p.APIKeyConfigured = p.APIKey != ""
		p.APIKey = ""
		p.ClearAPIKey = false
	}
	return map[string]any{"config": c, "updated_at": rev}
}
func (a *App) platformModelsEnabled(ctx context.Context) (bool, error) {
	c := defaultAgentModels()
	_, e := a.loadPlatformConfig(ctx, "models", &c)
	return c.Enabled, e
}
func (a *App) initAgentProviders(ctx context.Context) error {
	_, e := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS agent_model_tool_metadata(run_id text NOT NULL,call_id text NOT NULL,provider_id text NOT NULL,metadata_encrypted text NOT NULL,metadata_hash text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(run_id,call_id,provider_id));CREATE TABLE IF NOT EXISTS agent_model_chat_leases(user_id text PRIMARY KEY REFERENCES users(id),token text NOT NULL,expires_at timestamptz NOT NULL);`)
	if e != nil {
		return e
	}
	return a.initAgentTelemetry(ctx)
}
func (a *App) registerAgentProviders(m *http.ServeMux) {
	m.HandleFunc("GET /api/agent-platform/models", a.protect("admin:manage", a.getAgentModels))
	m.HandleFunc("PUT /api/agent-platform/models", a.protect("admin:manage", a.saveAgentModels))
	m.HandleFunc("POST /api/agent-platform/models/test", a.protect("admin:manage", a.testAgentModel))
	m.HandleFunc("GET /api/agent-platform/models/status", a.protect("admin:manage", a.agentModelsStatus))
	a.registerAgentTelemetry(m)
}
func (a *App) getAgentModels(w http.ResponseWriter, r *http.Request) {
	c := defaultAgentModels()
	rev, e := a.loadPlatformConfig(r.Context(), "models", &c)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	jsonResponse(w, 200, agentModelsOutput(c, rev))
}
func (a *App) saveAgentModels(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Config   agentModelsConfig `json:"config"`
		Expected string            `json:"expected_updated_at"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "모델 설정 형식을 확인하세요")
		return
	}
	rev, e := a.mutatePlatformConfig(r.Context(), "models", in.Expected, func(raw json.RawMessage) (any, error) {
		old := defaultAgentModels()
		if e := json.Unmarshal(raw, &old); e != nil {
			return nil, e
		}
		if e := normalizeModelConfig(&in.Config, old); e != nil {
			return nil, e
		}
		return in.Config, nil
	})
	if e != nil {
		platformConfigError(w, e)
		return
	}
	a.audit(r, "agent_platform.models.save", "", map[string]any{"providers": len(in.Config.Providers)})
	jsonResponse(w, 200, agentModelsOutput(in.Config, rev))
}
func (a *App) agentModelsStatus(w http.ResponseWriter, r *http.Request) {
	items, e := a.platformStatus(r.Context(), "models")
	if e != nil {
		platformConfigError(w, e)
		return
	}
	for _, item := range items {
		item["status"] = item["state"]
		item["consecutive_failures"] = item["failures"]
		item["circuit_open_until"] = item["open_until"]
		item["last_error"] = item["code"]
		item["last_test_at"] = item["checked_at"]
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}
func modelRevisionMatches(s string, t time.Time) bool {
	v, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && v.Equal(t)
}
func (a *App) testAgentModel(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       string `json:"provider_id"`
		Expected string `json:"expected_updated_at"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "시험할 모델을 선택하세요")
		return
	}
	c := defaultAgentModels()
	rev, e := a.loadPlatformConfig(r.Context(), "models", &c)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	if !modelRevisionMatches(in.Expected, rev) {
		fail(w, 409, "모델 설정이 변경되었습니다. 다시 조회하세요")
		return
	}
	var selected *agentModelProvider
	for _, p := range c.Providers {
		if p.ID == in.ID {
			v := p
			selected = &v
			break
		}
	}
	if selected == nil {
		fail(w, 404, "모델 연결을 찾을 수 없습니다")
		return
	}
	start := time.Now()
	out, e := a.attemptPlatformModel(r.Context(), *selected, rev, pentagicore.CompletionRequest{Role: "assistant", Messages: []pentagicore.Message{{Role: "user", Content: "연결 시험입니다. OK 한 단어만 답하세요."}}, MaxTokens: 32, ContextWindow: 1024}, nil)
	code := "available"
	if e != nil {
		code = modelErrorCode(e)
	}
	a.audit(r, "agent_platform.models.test", selected.ID, map[string]any{"status": code})
	jsonResponse(w, 200, map[string]any{"ok": e == nil, "status": code, "latency_ms": time.Since(start).Milliseconds(), "input_tokens": out.InputTokens, "output_tokens": out.OutputTokens, "finish_reason": out.FinishReason})
}

type modelCallContextKey struct{}
type modelCallContext struct {
	RunID  string
	Check  func(context.Context) error
	Before func(context.Context) error
}

func withModelCallContext(ctx context.Context, v modelCallContext) context.Context {
	return context.WithValue(ctx, modelCallContextKey{}, v)
}

type modelFailure struct{ code string }

type modelControlFailure struct{ cause error }

func (e *modelControlFailure) Error() string { return e.cause.Error() }
func (e *modelControlFailure) Unwrap() error { return e.cause }

func (a *App) modelPrincipalCurrent(ctx context.Context, u User) error {
	var role, team string
	if a.DB.QueryRow(ctx, `SELECT role,team FROM users WHERE id=$1 AND NOT disabled`, u.ID).Scan(&role, &team) != nil || role != u.Role || team != u.Team {
		return errors.New("현재 사용자 권한이 변경되었습니다")
	}
	scopes := a.roleScopes(ctx, role)
	if u.KeyID != "" {
		var raw []byte
		if a.DB.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, u.KeyID, u.ID).Scan(&raw) != nil {
			return errors.New("현재 API 키가 유효하지 않습니다")
		}
		var keys []string
		if json.Unmarshal(raw, &keys) != nil {
			return errors.New("현재 API 키 범위를 확인할 수 없습니다")
		}
		allowed := []string{}
		for _, scope := range scopes {
			if hasString(keys, scope) {
				allowed = append(allowed, scope)
			}
		}
		scopes = allowed
	}
	for _, scope := range []string{"ai:use", "services:read", "findings:read"} {
		if hasString(u.Scopes, scope) && !hasString(scopes, scope) {
			return errors.New("현재 분석 자료 권한이 변경되었습니다")
		}
	}
	return nil
}

func (a *App) acquireModelChat(ctx context.Context, userID string) (func(), bool, error) {
	token := newID()
	tag, e := a.DB.Exec(ctx, `INSERT INTO agent_model_chat_leases(user_id,token,expires_at) VALUES($1,$2,now()+interval '11 minutes') ON CONFLICT(user_id) DO UPDATE SET token=$2,expires_at=now()+interval '11 minutes' WHERE agent_model_chat_leases.expires_at<now()`, userID, token)
	release := func() {
		c, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = a.DB.Exec(c, `DELETE FROM agent_model_chat_leases WHERE user_id=$1 AND token=$2`, userID, token)
	}
	if e != nil {
		return nil, false, e
	}
	return release, tag.RowsAffected() == 1, nil
}

type modelResourceRef struct{ Kind, ID string }

func (a *App) modelResourcesCurrent(ctx context.Context, u User, refs []modelResourceRef) error {
	if e := a.modelPrincipalCurrent(ctx, u); e != nil {
		return e
	}
	for _, ref := range refs {
		v, e := a.resource(ctx, ref.Kind, ref.ID)
		if e != nil || !a.canAccess(ctx, u, v) {
			return errors.New("분석 자료의 현재 접근 권한이 변경되었습니다")
		}
		if parentID := asString(v.Data["service_id"]); parentID != "" {
			parent, e := a.resource(ctx, "services", parentID)
			if e != nil || !a.canAccess(ctx, u, parent) {
				return errors.New("분석 자료의 부모 서비스 접근 권한이 변경되었습니다")
			}
		}
	}
	return nil
}
func emitCommittedModel(onDelta func(string), content string) {
	if onDelta == nil {
		return
	}
	text := maskAgentText(content)
	for len(text) > 8192 {
		end := 8192
		for !utf8.RuneStart(text[end]) {
			end--
		}
		onDelta(text[:end])
		text = text[end:]
	}
	if text != "" {
		onDelta(text)
	}
}

func (e *modelFailure) Error() string { return "모델 연결 처리 실패: " + e.code }
func modelErrorCode(e error) string {
	var f *modelFailure
	if errors.As(e, &f) {
		return f.code
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(e, context.Canceled) {
		return "cancelled"
	}
	return "unavailable"
}
func (a *App) platformModelCompletion(ctx context.Context, ai map[string]any, in pentagicore.CompletionRequest) (pentagicore.CompletionResult, error) {
	c := defaultAgentModels()
	rev, e := a.loadPlatformConfig(ctx, "models", &c)
	if e != nil {
		return pentagicore.CompletionResult{}, e
	}
	providers := []agentModelProvider{}
	if c.Enabled {
		ids := c.RoleProviders[in.Role]
		if len(ids) == 0 {
			ids = c.RoleProviders["default"]
		}
		if len(ids) > 0 {
			for _, id := range ids {
				for _, p := range c.Providers {
					if p.ID == id && p.Enabled {
						providers = append(providers, p)
					}
				}
			}
		} else {
			for _, p := range c.Providers {
				if p.Enabled {
					providers = append(providers, p)
				}
			}
			sort.SliceStable(providers, func(i, j int) bool { return providers[i].Priority < providers[j].Priority })
		}
	}
	if len(providers) == 0 && !c.Enabled && asBool(ai["enabled"]) {
		providers = append(providers, agentModelProvider{ID: "legacy", Type: "openai", Enabled: true, BaseURL: asString(ai["base_url"]), Model: asString(ai["model"]), APIKey: asString(ai["api_key"]), MaxTokens: asInt(ai["max_tokens"]), ContextWindow: asInt(ai["context_window"]), TimeoutSeconds: 600, platformResilience: platformResilience{FailureThreshold: 3, CooldownSeconds: 30}})
		identity := providerIdentity(providers[0])
		providers[0].ID = "legacy-" + identity[strings.LastIndex(identity, ":")+1:]
	}
	ctl, _ := ctx.Value(modelCallContextKey{}).(modelCallContext)
	for _, p := range providers {
		if e := ctx.Err(); e != nil {
			return pentagicore.CompletionResult{}, e
		}
		if ctl.Check != nil {
			if e := ctl.Check(ctx); e != nil {
				return pentagicore.CompletionResult{}, e
			}
		}
		out, e := a.attemptPlatformModel(ctx, p, rev, in, ctl.Before)
		if e != nil {
			var control *modelControlFailure
			if errors.As(e, &control) {
				return pentagicore.CompletionResult{}, control.cause
			}
			if ctx.Err() != nil {
				return pentagicore.CompletionResult{}, ctx.Err()
			}
			continue
		}
		if ctl.Check != nil {
			if e := ctl.Check(ctx); e != nil {
				return pentagicore.CompletionResult{}, e
			}
		}
		// Commit only a completely validated answer. No tool or text from a failed attempt escapes.
		emitCommittedModel(in.OnDelta, out.Content)
		return out, nil
	}
	return pentagicore.CompletionResult{}, ErrAgentModelsUnavailable
}
func providerIdentity(p agentModelProvider) string {
	b, _ := json.Marshal([]string{p.Type, p.BaseURL, p.Model, p.APIKey})
	s := sha256.Sum256(b)
	return p.ID + ":" + hex.EncodeToString(s[:8])
}
func (a *App) attemptPlatformModel(ctx context.Context, p agentModelProvider, rev time.Time, in pentagicore.CompletionRequest, before func(context.Context) error) (out pentagicore.CompletionResult, err error) {
	start := time.Now()
	parentContext := ctx
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	permit, e := a.platformPermit(ctx, "models", p.ID, rev, p.platformResilience, timeout)
	if e != nil {
		return out, e
	}
	if !permit {
		return out, &modelFailure{"circuit_open"}
	}
	defer func() {
		code := "available"
		if err != nil {
			code = modelErrorCode(err)
		}
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		var control *modelControlFailure
		if parentContext.Err() != nil || errors.As(err, &control) {
			_, _ = a.DB.Exec(bounded, `UPDATE agent_platform_health SET probe_until=NULL WHERE group_name='models' AND provider_id=$1 AND revision=$2`, p.ID, rev)
		} else {
			_ = a.platformOutcome(bounded, "models", p.ID, rev, err == nil, code, time.Since(start))
		}
		cancel()
		a.queueModelTelemetry(ctx, p, in.Role, out, code, start)
	}()
	if before != nil {
		if e := before(ctx); e != nil {
			return out, &modelControlFailure{e}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	in.MaxTokens = minPositive(in.MaxTokens, p.MaxTokens, 262144)
	in.ContextWindow = minPositive(in.ContextWindow, p.ContextWindow, 262144)
	if in.MaxTokens < 1 || in.ContextWindow < 1024 {
		return out, &modelFailure{"token_budget"}
	}
	body, endpoint, e := a.modelWireRequest(ctx, p, in)
	if e != nil {
		return out, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(body)))
	if e != nil {
		return out, &modelFailure{"invalid_endpoint"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	switch p.Type {
	case "anthropic":
		req.Header.Set("x-api-key", p.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "gemini":
		req.Header.Set("x-goog-api-key", p.APIKey)
	case "ollama":
		req.Header.Set("Accept", "application/x-ndjson")
		if p.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIKey)
		}
	default:
		if p.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIKey)
		}
	}
	client, e := a.outboundClient(ctx, timeout)
	if e != nil {
		return out, &modelFailure{"tls_configuration"}
	}
	defer client.CloseIdleConnections()
	resp, e := client.Do(req)
	if e != nil {
		return out, &modelFailure{"connection_failed"}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, &modelFailure{fmt.Sprintf("http_%d", resp.StatusCode)}
	}
	var metadata map[string]json.RawMessage
	out, metadata, e = readModelWire(resp.Body, p.Type, resp.Header.Get("Content-Type"))
	if e != nil {
		return out, e
	}
	if out.FinishReason == "length" || out.FinishReason == "content_filter" {
		return out, &modelFailure{out.FinishReason}
	}
	current := defaultAgentModels()
	nowRev, e := a.loadPlatformConfig(ctx, "models", &current)
	if e != nil || !nowRev.Equal(rev) {
		return pentagicore.CompletionResult{}, &modelFailure{"configuration_changed"}
	}
	if strings.HasPrefix(p.ID, "legacy-") {
		legacy, e := a.setting(ctx, "ai")
		if e != nil || !asBool(legacy["enabled"]) || asString(legacy["base_url"]) != p.BaseURL || asString(legacy["model"]) != p.Model || asString(legacy["api_key"]) != p.APIKey || asInt(legacy["max_tokens"]) < in.MaxTokens || asInt(legacy["context_window"]) < in.ContextWindow {
			return pentagicore.CompletionResult{}, &modelFailure{"configuration_changed"}
		}
	}
	if e = a.storeModelMetadata(ctx, p, metadata); e != nil {
		return pentagicore.CompletionResult{}, e
	}
	return out, nil
}
func minPositive(values ...int) int {
	n := 262144
	for _, v := range values {
		if v > 0 && v < n {
			n = v
		}
	}
	return n
}
