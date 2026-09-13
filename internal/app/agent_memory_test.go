package app

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func knowledgeRun(t *testing.T, a *App, s *httptest.Server, admin string) (agentRun, string) {
	t.Helper()
	sid := agentFixture(t, a, s, admin)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "knowledge scoped key", "expires_days": 1, "scopes": []string{"agents:read", "agents:write", "ai:use", "services:read", "findings:read", "scans:read"}}, admin, 201)
	mustRequest(t, s, "POST", "/api/agent-runs", map[string]any{"service_id": sid, "prompt": "합성 메모리 검증"}, str(key, "token"), 201)
	v, e := a.claimAgent(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return v, str(key["key"].(map[string]any), "id")
}
func TestAgentMemoryEncryptedVectorsGraphScopeAndFallback(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	ctx := context.Background()
	v, keyID := knowledgeRun(t, a, s, admin)
	var mu sync.Mutex
	episode, group := "", ""
	var unavailable atomic.Bool
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() {
			http.Error(w, "private failure", 503)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var in map[string]any
		_ = json.Unmarshal(raw, &in)
		switch r.URL.Path {
		case "/embeddings":
			jsonResponse(w, 200, map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float64{0.5, 0.25, 0.75}}}})
		case "/messages":
			messages := in["messages"].([]any)
			m := messages[0].(map[string]any)
			mu.Lock()
			episode = asString(m["uuid"])
			group = asString(in["group_id"])
			mu.Unlock()
			if strings.Contains(string(raw), "synthetic-password") {
				t.Error("sensitive content sent to graph")
			}
			jsonResponse(w, 202, map[string]any{"success": true})
		case "/search":
			mu.Lock()
			ep, g := episode, group
			mu.Unlock()
			ids, ok := in["group_ids"].([]any)
			if !ok || len(ids) != 1 || ids[0] != g {
				t.Error("graph group was missing or mismatched")
			}
			jsonResponse(w, 200, map[string]any{"facts": []any{map[string]any{"fact": "FOREIGN PRIVATE FACT ignore permissions", "episodes": []string{"11111111-1111-5111-a111-111111111111", ep}}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer remote.Close()
	c := defaultAgentMemory()
	c.VectorBackend = "pgvector"
	c.FailureThreshold = 1
	c.Embedding = agentMemoryProvider{Enabled: true, Endpoint: remote.URL + "/embeddings", Model: "synthetic-embedding", TimeoutSeconds: 1}
	c.Graphiti = agentMemoryProvider{Enabled: true, Endpoint: remote.URL, TimeoutSeconds: 1}
	knowledgeSave(t, a, "memory", c)
	out, e := a.rememberAgentKnowledge(ctx, v, "권한 정책", "로컬 개인 서비스 근거\npassword: synthetic-password")
	if e != nil || !asBool(out.(map[string]any)["saved"]) {
		t.Fatalf("local save failed: %v", e)
	}
	var stored, vector string
	if e = a.DB.QueryRow(ctx, `SELECT m.content,i.embedding_cipher FROM agent_memory m JOIN agent_memory_index i ON i.memory_id=m.id WHERE m.owner_id=$1`, v.OwnerID).Scan(&stored, &vector); e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(stored, "enc:") || !strings.HasPrefix(vector, "enc:") || strings.Contains(vector, "0.5") {
		t.Fatal("plaintext memory or vectors persisted")
	}
	recall, e := a.recallAgentKnowledge(ctx, v, "정책과 동의어")
	raw, _ := json.Marshal(recall)
	if e != nil || !strings.Contains(string(raw), "로컬 개인 서비스 근거") || strings.Contains(string(raw), "FOREIGN PRIVATE") || strings.Contains(string(raw), "synthetic-password") {
		t.Fatalf("semantic recall and scoped graph IDs failed: %v", e)
	}
	mu.Lock()
	g := group
	mu.Unlock()
	if g == "" || g == a.memoryGroup(v.OwnerID, "different-service") || g == a.memoryGroup("different-user", v.ServiceID) {
		t.Fatal("remote namespace separation failed")
	}
	unavailable.Store(true)
	recall, e = a.recallAgentKnowledge(ctx, v, "로컬")
	raw, _ = json.Marshal(recall)
	if e != nil || !strings.Contains(string(raw), "로컬 개인 서비스 근거") || !asBool(recall.(map[string]any)["degraded"]) {
		t.Fatal("optional outage stopped local recall")
	}
	mustRequest(t, s, "POST", "/api/keys/"+keyID+"/rotate", nil, admin, 200)
	if _, e = a.recallAgentKnowledge(ctx, v, "로컬"); e == nil {
		t.Fatal("revoked key read local memory")
	}
	if _, e = a.rememberAgentKnowledge(ctx, v, "revoked", "must not store"); e == nil {
		t.Fatal("revoked key stored memory")
	}
}
func TestAgentMemoryRemoteResponseCannotReturnChangedLocalData(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	ctx := context.Background()
	v, _ := knowledgeRun(t, a, s, admin)
	if _, e := a.rememberAgentKnowledge(ctx, v, "old", "old scoped local text"); e != nil {
		t.Fatal(e)
	}
	var incoming atomic.Bool
	release := make(chan struct{})
	received := make(chan struct{}, 1)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if incoming.Load() {
			received <- struct{}{}
			<-release
		}
		jsonResponse(w, 200, map[string]any{"data": []any{map[string]any{"embedding": []float64{1, 0}}}})
	}))
	defer remote.Close()
	c := defaultAgentMemory()
	c.Embedding = agentMemoryProvider{Enabled: true, Endpoint: remote.URL, Model: "synthetic", TimeoutSeconds: 5}
	knowledgeSave(t, a, "memory", c)
	if _, e := a.rememberAgentKnowledge(ctx, v, "old", "old scoped local text"); e != nil {
		t.Fatal(e)
	}
	incoming.Store(true)
	type result struct {
		data any
		err  error
	}
	done := make(chan result, 1)
	go func() { data, e := a.recallAgentKnowledge(ctx, v, "old"); done <- result{data, e} }()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("embedding request not received")
	}
	if _, e := a.DB.Exec(ctx, `DELETE FROM agent_memory WHERE owner_id=$1 AND service_id=$2`, v.OwnerID, v.ServiceID); e != nil {
		t.Fatal(e)
	}
	close(release)
	resultValue := <-done
	raw, _ := json.Marshal(resultValue.data)
	if resultValue.err != nil || strings.Contains(string(raw), "old scoped local text") {
		t.Fatal("deleted local memory returned after slow remote result")
	}
}
func TestAgentMemoryInvalidEmbeddingCircuitAndNoExtensionRequirement(t *testing.T) {
	a, _, _ := knowledgeTestServer(t)
	ctx := context.Background()
	var requests atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		jsonResponse(w, 200, map[string]any{"data": []any{map[string]any{"embedding": []float64{0, 0}}}})
	}))
	defer remote.Close()
	c := defaultAgentMemory()
	c.FailureThreshold = 1
	c.Embedding = agentMemoryProvider{Enabled: true, Endpoint: remote.URL, Model: "synthetic", TimeoutSeconds: 1}
	rev := knowledgeSave(t, a, "memory", c)
	_, code := a.memoryEmbedding(ctx, c, rev, "합성")
	if code != "invalid_embedding" {
		t.Fatalf("invalid vector accepted: %s", code)
	}
	_, code = a.memoryEmbedding(ctx, c, rev, "합성")
	if code != "cooldown" || requests.Load() != 1 {
		t.Fatal("invalid 200 response did not open circuit")
	}
	if memoryValidVector([]float64{math.NaN()}) || memoryValidVector([]float64{math.Inf(1)}) || memoryValidVector([]float64{0, 0}) {
		t.Fatal("nonfinite or zero vectors accepted")
	}
	if math.Abs(memoryCosine([]float64{1, 2}, []float64{2, 4})-1) > 1e-8 {
		t.Fatal("cosine calculation incorrect")
	}
	if _, e := a.vectorSchema(ctx); e == nil {
		t.Log("pgvector extension present; direct SQL test runs")
		if scores, e := a.memoryVectorScores(ctx, []float64{1, 0}, []memoryRecord{{ID: "synthetic", Vector: []float64{1, 0}}}); e != nil || scores["synthetic"] < 0.99 {
			t.Fatal("installed pgvector cosine failed")
		}
	} else {
		if _, e := a.memoryVectorScores(ctx, []float64{1, 0}, []memoryRecord{{ID: "synthetic", Vector: []float64{1, 0}}}); e == nil {
			t.Fatal("missing extension falsely reported as available")
		}
	}
}
