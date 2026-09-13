package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type agentMemoryProvider struct {
	Enabled          bool   `json:"enabled"`
	Endpoint         string `json:"endpoint"`
	Model            string `json:"model,omitempty"`
	APIKey           string `json:"api_key"`
	APIKeyConfigured bool   `json:"api_key_configured"`
	ClearAPIKey      bool   `json:"clear_api_key"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
}
type agentMemoryConfig struct {
	MaxResults       int                 `json:"max_results"`
	VectorBackend    string              `json:"vector_backend"`
	FailureThreshold int                 `json:"failure_threshold"`
	CooldownSeconds  int                 `json:"cooldown_seconds"`
	Embedding        agentMemoryProvider `json:"embedding"`
	Graphiti         agentMemoryProvider `json:"graphiti"`
}

func defaultAgentMemory() agentMemoryConfig {
	return agentMemoryConfig{MaxResults: 10, VectorBackend: "auto", FailureThreshold: 3, CooldownSeconds: 30, Embedding: agentMemoryProvider{TimeoutSeconds: 10}, Graphiti: agentMemoryProvider{TimeoutSeconds: 10}}
}
func (a *App) initAgentKnowledge(ctx context.Context) error {
	_, e := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS agent_memory_index(memory_id text PRIMARY KEY REFERENCES agent_memory(id) ON DELETE CASCADE,content_hash text NOT NULL,embedding_cipher text NOT NULL DEFAULT '',embedding_model text NOT NULL DEFAULT '',episode_id text NOT NULL DEFAULT '',graph_model text NOT NULL DEFAULT '',updated_at timestamptz NOT NULL DEFAULT now());`)
	return e
}
func validateAgentMemory(c *agentMemoryConfig, old agentMemoryConfig) error {
	if c.MaxResults < 1 || c.MaxResults > 10 || !hasString([]string{"auto", "database", "pgvector"}, c.VectorBackend) || c.FailureThreshold < 1 || c.FailureThreshold > 20 || c.CooldownSeconds < 5 || c.CooldownSeconds > 3600 {
		return errors.New("메모리 검색 한도·방식·복구 설정을 확인하세요")
	}
	for i, p := range []*agentMemoryProvider{&c.Embedding, &c.Graphiti} {
		prior := old.Embedding
		if i == 1 {
			prior = old.Graphiti
		}
		var e error
		p.APIKey, e = knowledgeSecret(p.APIKey, prior.APIKey, p.ClearAPIKey)
		if e != nil {
			return e
		}
		p.APIKeyConfigured = false
		p.ClearAPIKey = false
		if p.TimeoutSeconds < 1 || p.TimeoutSeconds > 30 {
			return errors.New("메모리 공급자 시간 제한은 1~30초입니다")
		}
		if p.Endpoint != "" {
			if e = knowledgeEndpoint(p.Endpoint); e != nil {
				return e
			}
		} else if p.Enabled {
			return errors.New("활성 공급자의 주소가 필요합니다")
		}
		if len(p.Model) > 200 || strings.ContainsAny(p.Model, "\r\n\x00") {
			return errors.New("임베딩 모델 이름을 확인하세요")
		}
		if i == 0 && p.Enabled && strings.TrimSpace(p.Model) == "" {
			return errors.New("임베딩 모델 이름이 필요합니다")
		}
	}
	return nil
}
func (a *App) getAgentMemory(w http.ResponseWriter, r *http.Request) {
	c := defaultAgentMemory()
	rev, e := a.loadPlatformConfig(r.Context(), "memory", &c)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	for _, p := range []*agentMemoryProvider{&c.Embedding, &c.Graphiti} {
		p.APIKeyConfigured = p.APIKey != ""
		p.APIKey = ""
	}
	jsonResponse(w, 200, map[string]any{"config": c, "updated_at": rev})
}
func (a *App) putAgentMemory(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Config   agentMemoryConfig `json:"config"`
		Expected string            `json:"expected_updated_at"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "메모리 설정 형식이 올바르지 않습니다")
		return
	}
	rev, e := a.mutatePlatformConfig(r.Context(), "memory", in.Expected, func(raw json.RawMessage) (any, error) {
		old := defaultAgentMemory()
		if e := json.Unmarshal(raw, &old); e != nil {
			return nil, e
		}
		if e := validateAgentMemory(&in.Config, old); e != nil {
			return nil, e
		}
		return in.Config, nil
	})
	if e != nil {
		platformConfigError(w, e)
		return
	}
	a.audit(r, "agent.platform.memory.updated", "memory", nil)
	jsonResponse(w, 200, map[string]any{"updated_at": rev})
}
func (a *App) vectorSchema(ctx context.Context) (string, error) {
	var schema string
	e := a.DB.QueryRow(ctx, `SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='vector'`).Scan(&schema)
	return schema, e
}
func (a *App) statusAgentMemory(w http.ResponseWriter, r *http.Request) {
	items, e := a.platformStatus(r.Context(), "memory")
	if e != nil {
		platformConfigError(w, e)
		return
	}
	_, e = a.vectorSchema(r.Context())
	jsonResponse(w, 200, map[string]any{"providers": items, "local_available": true, "pgvector_available": e == nil, "vector_storage": "encrypted_local", "graph_results": "local_authorized_ids_only"})
}
func (a *App) testAgentMemory(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       string `json:"provider_id"`
		Query    string `json:"query"`
		Expected string `json:"expected_updated_at"`
	}
	if decode(r, &in) != nil || len(in.Query) > 2000 {
		fail(w, 400, "시험 설정을 확인하세요")
		return
	}
	c := defaultAgentMemory()
	rev, e := a.loadPlatformConfig(r.Context(), "memory", &c)
	if e != nil {
		platformConfigError(w, e)
		return
	}
	if !modelRevisionMatches(in.Expected, rev) {
		fail(w, 409, "메모리 설정이 변경되었습니다. 다시 조회한 뒤 시험하세요")
		return
	}
	start := time.Now()
	code := "unsupported_provider"
	details := map[string]any{}
	if in.Query == "" {
		in.Query = "Hunter 합성 메모리 연결 시험"
	}
	switch in.ID {
	case "embedding":
		if !c.Embedding.Enabled {
			fail(w, 400, "저장한 임베딩 연동을 활성화하세요")
			return
		}
		vec, status := a.memoryEmbedding(r.Context(), c, rev, maskAgentText(in.Query))
		code = status
		details["dimensions"] = len(vec)
	case "graphiti":
		if !c.Graphiti.Enabled {
			fail(w, 400, "저장한 Graphiti 연동을 활성화하세요")
			return
		}
		group := a.memoryGroup(currentUser(r).ID, "connection-test")
		_, code = a.memoryGraphSearch(r.Context(), c, rev, group, maskAgentText(in.Query))
		details["check_scope"] = "합성 전용 그룹의 검색 API 응답 형식 확인. 메모리 쓰기·비동기 인덱싱 완료를 의미하지 않습니다"
	case "pgvector":
		_, e = a.vectorSchema(r.Context())
		code = "extension_unavailable"
		if e == nil {
			var scores map[string]float64
			scores, e = a.memoryVectorScores(r.Context(), []float64{1, 0}, []memoryRecord{{ID: "synthetic", Vector: []float64{1, 0}}})
			if e == nil && scores["synthetic"] > 0.99 {
				code = "ok"
			} else {
				code = "vector_query_failed"
			}
		}
		details["fallback"] = "database_cosine_keyword"
	default:
		fail(w, 400, "시험 종류는 embedding, graphiti, pgvector입니다")
		return
	}
	a.audit(r, "agent.platform.memory.test", in.ID, map[string]any{"code": code})
	jsonResponse(w, 200, map[string]any{"status": map[bool]string{true: "ok", false: "unavailable"}[code == "ok"], "provider_id": in.ID, "code": code, "degraded": code != "ok", "elapsed_ms": time.Since(start).Milliseconds(), "details": details})
}
