package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type memoryRecord struct {
	ID, Title, Content, Hash, Episode, EmbeddingModel, GraphModel string
	Vector                                                        []float64
	Score                                                         float64
}

func memoryProviderHash(p agentMemoryProvider) string {
	return digest(p.Endpoint + "\x00" + p.Model + "\x00" + p.APIKey)
}
func (a *App) memoryGroup(owner, service string) string {
	mac := hmac.New(sha256.New, a.Key)
	_, _ = mac.Write([]byte("hunter-memory\x00" + owner + "\x00" + service))
	return "hunter_" + hex.EncodeToString(mac.Sum(nil))
}
func memoryEpisode(id, hash, model string) string {
	s := digest(id + "\x00" + hash + "\x00" + model)
	return s[:8] + "-" + s[8:12] + "-5" + s[13:16] + "-a" + s[17:20] + "-" + s[20:32]
}
func (a *App) memoryAccess(ctx context.Context, v agentRun) (User, error) {
	if e := a.checkAgent(ctx, v); e != nil {
		return User{}, e
	}
	u, e := a.agentPrincipal(ctx, v)
	if e != nil {
		return u, e
	}
	cfg, e := a.setting(ctx, "agents")
	if e != nil {
		return u, e
	}
	if !asBool(cfg["memory_enabled"]) || !asBool(v.Limits["memory_enabled"]) {
		return u, errors.New("에이전트 메모리가 비활성화되었습니다")
	}
	return u, nil
}
func (a *App) rememberAgentKnowledge(ctx context.Context, v agentRun, key, content string) (any, error) {
	u, e := a.memoryAccess(ctx, v)
	if e != nil {
		return nil, e
	}
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 200 || content == "" || len(content) > 16000 {
		return nil, errors.New("메모리 이름은 200바이트, 내용은 16,000바이트 이내로 입력하세요")
	}
	content = maskAgentText(content)
	title := maskAgentText(key)
	cipher, e := a.encrypt(content)
	if e != nil {
		return nil, e
	}
	id := digest(u.ID + ":" + v.ServiceID + ":" + key)
	hash := digest(title + "\x00" + content)
	e = a.agentMutation(ctx, v.ID, func(tx pgx.Tx) error { // Lock the owner as well: distinct runs cannot race past the shared 100-row limit.
		if _, e := tx.Exec(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, u.ID); e != nil {
			return e
		}
		var count int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM agent_memory WHERE owner_id=$1 AND service_id=$2 AND id<>$3`, u.ID, v.ServiceID, id).Scan(&count); e != nil {
			return e
		}
		if count >= 100 {
			return errors.New("서비스별 개인 메모리 한도(100개)에 도달했습니다")
		}
		if _, e := tx.Exec(ctx, `INSERT INTO agent_memory(id,owner_id,service_id,title,content) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET title=EXCLUDED.title,content=EXCLUDED.content,created_at=now()`, id, u.ID, v.ServiceID, title, cipher); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO agent_memory_index(memory_id,content_hash) VALUES($1,$2) ON CONFLICT(memory_id) DO UPDATE SET content_hash=EXCLUDED.content_hash,embedding_cipher=CASE WHEN agent_memory_index.content_hash=EXCLUDED.content_hash THEN agent_memory_index.embedding_cipher ELSE '' END,episode_id=CASE WHEN agent_memory_index.content_hash=EXCLUDED.content_hash THEN agent_memory_index.episode_id ELSE '' END,updated_at=now()`, id, hash)
		return e
	})
	if e != nil {
		return nil, e
	}
	out := map[string]any{"saved": true, "key": title, "scope": "현재 사용자와 현재 서비스에만 저장됨", "indexing": map[string]string{}, "degraded": false}
	c := defaultAgentMemory()
	rev, e := a.loadPlatformConfig(ctx, "memory", &c)
	if e != nil {
		out["degraded"] = true
		out["reason"] = "로컬 메모리는 저장되었습니다. 선택 연동 설정을 읽지 못했습니다"
		return out, nil
	}
	indexing := map[string]string{}
	if c.Embedding.Enabled {
		if _, e = a.memoryAccess(ctx, v); e != nil {
			return nil, e
		}
		vec, code := a.memoryEmbedding(ctx, c, rev, title+"\n"+content)
		indexing["embedding"] = code
		if code == "ok" {
			raw, _ := json.Marshal(vec)
			encrypted, err := a.encrypt(string(raw))
			if err == nil {
				if _, e = a.memoryAccess(ctx, v); e != nil {
					return nil, e
				}
				_, err = a.DB.Exec(ctx, `UPDATE agent_memory_index SET embedding_cipher=$3,embedding_model=$4,updated_at=now() WHERE memory_id=$1 AND content_hash=$2`, id, hash, encrypted, memoryProviderHash(c.Embedding))
			}
			if err != nil {
				indexing["embedding"] = "local_index_failed"
			}
		}
	}
	if c.Graphiti.Enabled {
		if _, e = a.memoryAccess(ctx, v); e != nil {
			return nil, e
		}
		episode := memoryEpisode(id, hash, memoryProviderHash(c.Graphiti))
		code := a.memoryGraphWrite(ctx, c, rev, a.memoryGroup(u.ID, v.ServiceID), episode, title, content)
		indexing["graphiti"] = code
		if code == "ok" {
			if _, e = a.memoryAccess(ctx, v); e != nil {
				return nil, e
			}
			_, err := a.DB.Exec(ctx, `UPDATE agent_memory_index SET episode_id=$3,graph_model=$4,updated_at=now() WHERE memory_id=$1 AND content_hash=$2`, id, hash, episode, memoryProviderHash(c.Graphiti))
			if err != nil {
				indexing["graphiti"] = "local_index_failed"
			} else {
				indexing["graphiti"] = "accepted_async"
			}
		}
	}
	for _, code := range indexing {
		if code != "ok" && code != "accepted_async" {
			out["degraded"] = true
		}
	}
	out["indexing"] = indexing
	return out, nil
}
func (a *App) loadMemoryRecords(ctx context.Context, u User, service string) ([]memoryRecord, error) {
	rows, e := a.DB.Query(ctx, `SELECT m.id,m.title,m.content,coalesce(i.content_hash,''),coalesce(i.embedding_cipher,''),coalesce(i.embedding_model,''),coalesce(i.episode_id,''),coalesce(i.graph_model,'') FROM agent_memory m LEFT JOIN agent_memory_index i ON i.memory_id=m.id WHERE m.owner_id=$1 AND m.service_id=$2 ORDER BY m.created_at DESC,m.id LIMIT 100`, u.ID, service)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []memoryRecord{}
	for rows.Next() {
		var v memoryRecord
		var encrypted, vector string
		if e = rows.Scan(&v.ID, &v.Title, &encrypted, &v.Hash, &vector, &v.EmbeddingModel, &v.Episode, &v.GraphModel); e != nil {
			return nil, e
		}
		v.Content, e = a.decrypt(encrypted)
		if e != nil {
			return nil, e
		}
		current := digest(v.Title + "\x00" + v.Content)
		if current != v.Hash {
			vector = ""
			v.Episode = ""
		}
		v.Hash = current
		if vector != "" {
			plain, err := a.decrypt(vector)
			if err == nil {
				_ = json.Unmarshal([]byte(plain), &v.Vector)
				if !memoryValidVector(v.Vector) {
					v.Vector = nil
				}
			}
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func (a *App) recallAgentKnowledge(ctx context.Context, v agentRun, query string) (any, error) {
	u, e := a.memoryAccess(ctx, v)
	if e != nil {
		return nil, e
	}
	if len(query) > 500 {
		return nil, errors.New("메모리 검색어는 500바이트 이내로 입력하세요")
	}
	query = maskAgentText(query)
	c := defaultAgentMemory()
	rev, cfgErr := a.loadPlatformConfig(ctx, "memory", &c)
	if cfgErr != nil {
		c = defaultAgentMemory()
	}
	items, e := a.loadMemoryRecords(ctx, u, v.ServiceID)
	if e != nil {
		return nil, e
	}
	scores := map[string]float64{}
	hashes := map[string]string{}
	backends := []string{"keyword"}
	degraded := cfgErr != nil
	statuses := map[string]string{}
	for _, item := range items {
		hashes[item.ID] = item.Hash
		text := strings.ToLower(item.Title + " " + item.Content)
		if query == "" || strings.Contains(text, strings.ToLower(query)) {
			scores[item.ID] = 1
		} else {
			for _, term := range strings.Fields(strings.ToLower(query)) {
				if strings.Contains(text, term) {
					scores[item.ID] += 0.15
				}
			}
		}
	}
	if cfgErr == nil && c.Embedding.Enabled && len(items) > 0 && query != "" {
		if _, e = a.memoryAccess(ctx, v); e != nil {
			return nil, e
		}
		qvec, code := a.memoryEmbedding(ctx, c, rev, query)
		statuses["embedding"] = code
		if code == "ok" {
			eligible := []memoryRecord{}
			for _, item := range items {
				if item.EmbeddingModel == memoryProviderHash(c.Embedding) && len(item.Vector) == len(qvec) {
					eligible = append(eligible, item)
				}
			}
			vectors := map[string]float64{}
			usedPG := false
			if c.VectorBackend != "database" {
				var err error
				vectors, err = a.memoryVectorScores(ctx, qvec, eligible)
				usedPG = err == nil
				if err != nil && c.VectorBackend == "pgvector" {
					degraded = true
					statuses["pgvector"] = "unavailable_database_fallback"
				}
			}
			if !usedPG {
				vectors = map[string]float64{}
				for _, item := range eligible {
					vectors[item.ID] = memoryCosine(qvec, item.Vector)
				}
			}
			if usedPG {
				backends = append(backends, "pgvector")
			} else {
				backends = append(backends, "database_cosine")
			}
			for id, score := range vectors {
				if score > 0 {
					scores[id] += score
				}
			}
		} else {
			degraded = true
		}
	}
	if cfgErr == nil && c.Graphiti.Enabled && len(items) > 0 && query != "" {
		if _, e = a.memoryAccess(ctx, v); e != nil {
			return nil, e
		}
		episodes, code := a.memoryGraphSearch(ctx, c, rev, a.memoryGroup(u.ID, v.ServiceID), query)
		statuses["graphiti"] = code
		if code == "ok" {
			backends = append(backends, "graphiti_local_ids")
			for _, item := range items {
				if item.GraphModel == memoryProviderHash(c.Graphiti) && item.Episode != "" && episodes[item.Episode] {
					scores[item.ID] += 1
				}
			}
		} else {
			degraded = true
		}
	}
	// External calls may outlive a key, ACL or local memory update. Re-read all authoritative data before returning it.
	u, e = a.memoryAccess(ctx, v)
	if e != nil {
		return nil, e
	}
	current, e := a.loadMemoryRecords(ctx, u, v.ServiceID)
	if e != nil {
		return nil, e
	}
	ranked := []memoryRecord{}
	for _, item := range current {
		if hashes[item.ID] != item.Hash {
			continue
		}
		item.Score = scores[item.ID]
		if item.Score > 0 {
			ranked = append(ranked, item)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].Score > ranked[j].Score })
	out := []map[string]any{}
	for _, item := range ranked {
		if len(out) >= c.MaxResults {
			break
		}
		out = append(out, map[string]any{"key": maskAgentText(item.Title), "content": knowledgeText(item.Content, 8000), "truncated": len(item.Content) > 8000, "score": math.Round(item.Score*10000) / 10000})
	}
	return map[string]any{"items": out, "degraded": degraded, "backends": backends, "providers": statuses, "scope": "현재 사용자와 현재 서비스"}, nil
}
func memoryValidVector(v []float64) bool {
	if len(v) == 0 || len(v) > 8192 {
		return false
	}
	norm := 0.0
	for _, n := range v {
		if math.IsNaN(n) || math.IsInf(n, 0) || math.Abs(n) > 1e30 {
			return false
		}
		norm += n * n
	}
	return norm > 0 && !math.IsInf(norm, 0)
}
func memoryCosine(a, b []float64) float64 {
	if len(a) != len(b) || !memoryValidVector(a) || !memoryValidVector(b) {
		return 0
	}
	dot, x, y := 0.0, 0.0, 0.0
	for i, n := range a {
		dot += n * b[i]
		x += n * n
		y += b[i] * b[i]
	}
	return dot / math.Sqrt(x*y)
}
func (a *App) memoryVectorScores(ctx context.Context, q []float64, items []memoryRecord) (map[string]float64, error) {
	schema, e := a.vectorSchema(ctx)
	if e != nil {
		return nil, e
	}
	result := map[string]float64{}
	if len(items) == 0 {
		return result, nil
	}
	typ := pgx.Identifier{schema, "vector"}.Sanitize()
	operator := "OPERATOR(" + pgx.Identifier{schema}.Sanitize() + ".<=>)"
	qraw, _ := json.Marshal(q)
	args := []any{string(qraw)}
	values := []string{}
	for _, item := range items {
		if len(item.Vector) != len(q) || !memoryValidVector(item.Vector) {
			continue
		}
		raw, _ := json.Marshal(item.Vector)
		args = append(args, item.ID, string(raw))
		values = append(values, fmt.Sprintf("($%d::text,$%d::%s)", len(args)-1, len(args), typ))
	}
	if len(values) == 0 {
		return result, nil
	}
	rows, e := a.DB.Query(ctx, `SELECT id,1-(embedding `+operator+` $1::`+typ+`) FROM (VALUES `+strings.Join(values, ",")+`) AS memories(id,embedding)`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var score float64
		if e = rows.Scan(&id, &score); e != nil {
			return nil, e
		}
		if !math.IsNaN(score) && !math.IsInf(score, 0) {
			result[id] = score
		}
	}
	return result, rows.Err()
}
func (a *App) memoryRequest(ctx context.Context, c agentMemoryConfig, rev time.Time, id, path string, p agentMemoryProvider, body any) (map[string]any, string) {
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	ok, e := a.platformPermit(ctx, "memory", id, rev, platformResilience{FailureThreshold: c.FailureThreshold, CooldownSeconds: c.CooldownSeconds}, timeout)
	if e != nil || !ok {
		return nil, "cooldown"
	}
	start := time.Now()
	raw, code := a.knowledgeJSON(ctx, http.MethodPost, strings.TrimRight(p.Endpoint, "/")+path, p.APIKey, body, timeout)
	if code == "ok" {
		code = memoryPayloadCode(id, path, raw)
	}
	if !a.knowledgeRevisionCurrent(ctx, "memory", rev) {
		code = "configuration_changed"
		raw = nil
	}
	a.knowledgeOutcome(ctx, "memory", id, rev, code == "ok", code, start)
	return raw, code
}
func (a *App) memoryEmbedding(ctx context.Context, c agentMemoryConfig, rev time.Time, input string) ([]float64, string) {
	raw, code := a.memoryRequest(ctx, c, rev, "embedding", "", c.Embedding, map[string]any{"model": c.Embedding.Model, "input": input, "encoding_format": "float"})
	if code != "ok" {
		return nil, code
	}
	data, ok := raw["data"].([]any)
	if !ok || len(data) != 1 {
		return nil, "invalid_embedding"
	}
	m, ok := data[0].(map[string]any)
	if !ok {
		return nil, "invalid_embedding"
	}
	list, ok := m["embedding"].([]any)
	if !ok {
		return nil, "invalid_embedding"
	}
	vector := []float64{}
	for _, x := range list {
		f, ok := x.(float64)
		if !ok {
			return nil, "invalid_embedding"
		}
		vector = append(vector, f)
	}
	if !memoryValidVector(vector) {
		return nil, "invalid_embedding"
	}
	return vector, "ok"
}
func (a *App) memoryGraphSearch(ctx context.Context, c agentMemoryConfig, rev time.Time, group, query string) (map[string]bool, string) {
	raw, code := a.memoryRequest(ctx, c, rev, "graphiti", "/search", c.Graphiti, map[string]any{"group_ids": []string{group}, "query": query, "max_facts": 20})
	if code != "ok" {
		return nil, code
	}
	facts, ok := raw["facts"].([]any)
	if !ok || len(facts) > 1000 {
		return nil, "invalid_graph_response"
	}
	episodes := map[string]bool{}
	for _, fact := range facts {
		m, ok := fact.(map[string]any)
		if !ok {
			continue
		}
		if m["expired_at"] != nil || m["invalid_at"] != nil {
			continue
		}
		if ids, ok := m["episodes"].([]any); ok {
			for _, id := range ids {
				if s, ok := id.(string); ok && len(s) == 36 {
					episodes[s] = true
				}
			}
		}
	}
	return episodes, "ok"
}
func (a *App) memoryGraphWrite(ctx context.Context, c agentMemoryConfig, rev time.Time, group, episode, title, content string) string {
	raw, code := a.memoryRequest(ctx, c, rev, "graphiti", "/messages", c.Graphiti, map[string]any{"group_id": group, "messages": []any{map[string]any{"uuid": episode, "name": title, "content": content, "role_type": "user", "role": "Hunter scoped memory", "timestamp": time.Now().UTC(), "source_description": "Current user and service scoped Hunter memory"}}})
	if code == "ok" && !asBool(raw["success"]) {
		return "invalid_graph_response"
	}
	return code
}

func memoryPayloadCode(id, path string, raw map[string]any) string {
	if id == "embedding" {
		data, ok := raw["data"].([]any)
		if !ok || len(data) != 1 {
			return "invalid_embedding"
		}
		m, ok := data[0].(map[string]any)
		if !ok {
			return "invalid_embedding"
		}
		entries, ok := m["embedding"].([]any)
		if !ok {
			return "invalid_embedding"
		}
		v := make([]float64, 0, len(entries))
		for _, x := range entries {
			f, ok := x.(float64)
			if !ok {
				return "invalid_embedding"
			}
			v = append(v, f)
		}
		if !memoryValidVector(v) {
			return "invalid_embedding"
		}
	}
	if id == "graphiti" && path == "/search" {
		v, ok := raw["facts"].([]any)
		if !ok || len(v) > 1000 {
			return "invalid_graph_response"
		}
	}
	if id == "graphiti" && path == "/messages" && !asBool(raw["success"]) {
		return "invalid_graph_response"
	}
	return "ok"
}
