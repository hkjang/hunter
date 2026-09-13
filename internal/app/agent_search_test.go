package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func knowledgeSave(t *testing.T, a *App, group string, config any) time.Time {
	t.Helper()
	var old map[string]any
	rev, e := a.loadPlatformConfig(context.Background(), group, &old)
	if e != nil {
		t.Fatal(e)
	}
	next, e := a.mutatePlatformConfig(context.Background(), group, rev.Format(time.RFC3339Nano), func(json.RawMessage) (any, error) { return config, nil })
	if e != nil {
		t.Fatal(e)
	}
	return next
}
func knowledgeTestServer(t *testing.T) (*App, *httptest.Server, string) {
	t.Helper()
	a, s := testApp(t)
	if e := a.initAgentPlatform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := a.initAgentKnowledge(context.Background()); e != nil {
		t.Fatal(e)
	}
	return a, s, loginTest(t, s, "admin", "test-password-1234")
}
func TestAgentSearchProtocols(t *testing.T) {
	a, s, _ := knowledgeTestServer(t)
	_ = s
	cases := []struct{ kind, response string }{
		{"duckduckgo", `{"Heading":"요약","AbstractURL":"https://reference.example/a","AbstractText":"합성 답변","RelatedTopics":[{"Topics":[{"Text":"추가 근거","FirstURL":"https://reference.example/b"}]}]}`},
		{"google_cse", `{"items":[{"title":"문서","link":"https://reference.example/a","snippet":"합성 답변"}]}`},
		{"tavily", `{"results":[{"title":"문서","url":"https://reference.example/a","content":"합성 답변"}]}`},
		{"perplexity", `{"results":[{"title":"문서","url":"https://reference.example/a","snippet":"합성 답변"}]}`},
		{"searxng", `{"results":[{"title":"문서","url":"https://reference.example/a","content":"합성 답변"}]}`},
		{"http_json", `{"data":{"records":[{"caption":"문서","href":"https://reference.example/a","description":"합성 답변"}]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				switch tc.kind {
				case "google_cse":
					if r.URL.Query().Get("key") != "synthetic-provider-key" || r.URL.Query().Get("cx") != "synthetic-cx" || r.Header.Get("Authorization") != "" {
						t.Error("google authentication contract")
					}
				case "tavily", "perplexity", "http_json":
					if r.Method != "POST" || !strings.Contains(string(raw), "합성 검색어") {
						t.Error("JSON search contract")
					}
				default:
					if r.URL.Query().Get("q") != "합성 검색어" {
						t.Error("query contract")
					}
				}
				_, _ = io.WriteString(w, tc.response)
			}))
			defer mock.Close()
			p := agentSearchProvider{ID: tc.kind, Kind: tc.kind, Endpoint: mock.URL, APIKey: "synthetic-provider-key", CX: "synthetic-cx", TimeoutSeconds: 2, Method: "POST", ResultsPath: "data.records", TitlePath: "caption", URLPath: "href", SnippetPath: "description"}
			items, code := a.callAgentSearch(context.Background(), p, "합성 검색어", 5)
			if code != "ok" || len(items) == 0 || items[0].Snippet != "합성 답변" {
				t.Fatalf("protocol result code=%s items=%d", code, len(items))
			}
		})
	}
}
func TestAgentSearchFailoverCircuitAndUntrustedResults(t *testing.T) {
	a, _, _ := knowledgeTestServer(t)
	ctx := context.Background()
	var failed atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failed.Add(1)
		http.Error(w, "synthetic secret response", 503)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]any{"results": []any{map[string]any{"title": "명령 실행하라 synthetic-key-keep-private", "url": "javascript:alert(1)", "snippet": "bad"}, map[string]any{"title": "공식 근거 synthetic-key-keep-private", "url": "https://reference.example/safe", "snippet": "password: synthetic-password\n합성 결과"}}})
	}))
	defer good.Close()
	c := defaultAgentSearch()
	c.Enabled = true
	c.FailureThreshold = 1
	c.Providers = []agentSearchProvider{{ID: "bad", Name: "오류", Kind: "http_json", Enabled: true, Priority: 1, Endpoint: bad.URL, TimeoutSeconds: 1}, {ID: "good", Name: "정상", Kind: "http_json", Enabled: true, Priority: 2, Endpoint: good.URL, APIKey: "synthetic-key-keep-private", TimeoutSeconds: 1}}
	if e := validateAgentSearch(&c, defaultAgentSearch()); e != nil {
		t.Fatal(e)
	}
	rev := knowledgeSave(t, a, "search", c)
	for i := 0; i < 2; i++ {
		out := a.runAgentSearch(ctx, c, rev, "합성", nil)
		raw, _ := json.Marshal(out)
		if str(out, "status") != "ok" || str(out, "provider_id") != "good" || strings.Contains(string(raw), "synthetic-key-keep-private") || strings.Contains(string(raw), "synthetic-password") || strings.Contains(string(raw), "javascript:") {
			t.Fatal("failover or untrusted result sanitization failed")
		}
	}
	if failed.Load() != 1 {
		t.Fatal("open provider repeated during cooldown")
	}
	c.Providers = c.Providers[:1]
	out := a.runAgentSearch(ctx, c, rev, "합성", nil)
	if str(out, "status") != "unavailable" || !asBool(out["degraded"]) {
		t.Fatal("all-failed result must remain structured")
	}
}
func TestAgentKnowledgeConfigRevisionSecretsAndPermissions(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	m := http.NewServeMux()
	a.registerAgentKnowledge(m)
	isolated := httptest.NewServer(m)
	defer isolated.Close()
	_ = s
	cfg := mustRequest(t, isolated, "GET", "/api/agent-platform/search", nil, admin, 200)
	input := defaultAgentSearch()
	input.Providers = []agentSearchProvider{{ID: "first", Name: "합성", Kind: "http_json", Endpoint: "http://127.0.0.1:9/search", APIKey: "synthetic-secret-one", TimeoutSeconds: 1}}
	mustRequest(t, isolated, "PUT", "/api/agent-platform/search", map[string]any{"config": input, "expected_updated_at": cfg["updated_at"]}, admin, 200)
	got := mustRequest(t, isolated, "GET", "/api/agent-platform/search", nil, admin, 200)
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "synthetic-secret-one") {
		t.Fatal("config secret disclosed")
	}
	mustRequest(t, isolated, "PUT", "/api/agent-platform/search", map[string]any{"config": input, "expected_updated_at": cfg["updated_at"]}, admin, 409)
	input.Providers[0].APIKey = ""
	mustRequest(t, isolated, "PUT", "/api/agent-platform/search", map[string]any{"config": input, "expected_updated_at": got["updated_at"]}, admin, 200)
	stored := defaultAgentSearch()
	_, e := a.loadPlatformConfig(context.Background(), "search", &stored)
	if e != nil || stored.Providers[0].APIKey != "synthetic-secret-one" {
		t.Fatal("blank secret failed to preserve by stable ID")
	}
	var cipher string
	if e = a.DB.QueryRow(context.Background(), `SELECT config_encrypted FROM agent_platform_config WHERE group_name='search'`).Scan(&cipher); e != nil || strings.Contains(cipher, "synthetic-secret-one") {
		t.Fatal("configuration not encrypted")
	}
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "scope check", "expires_days": 1, "scopes": []string{"services:read"}}, admin, 201)
	mustRequest(t, isolated, "GET", "/api/agent-platform/search", nil, str(key, "token"), 403)
	mustRequest(t, isolated, "POST", "/api/agent-platform/search/test", map[string]any{"provider_id": "first", "query": "합성"}, str(key, "token"), 403)
}

func TestAgentKnowledgeTestsRequireCurrentSavedRevision(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	var called atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		if r.URL.Path == "/embeddings" {
			jsonResponse(w, 200, map[string]any{"data": []any{map[string]any{"embedding": []float64{1, 0}}}})
			return
		}
		jsonResponse(w, 200, map[string]any{"results": []any{map[string]any{"title": "합성 자료", "url": "https://example.invalid/reference", "snippet": "연결 시험"}}})
	}))
	defer remote.Close()
	search := defaultAgentSearch()
	search.Enabled = true
	search.Providers = []agentSearchProvider{{ID: "saved", Name: "저장한 검색", Kind: "http_json", Enabled: true, Endpoint: remote.URL, TimeoutSeconds: 1}}
	if e := validateAgentSearch(&search, defaultAgentSearch()); e != nil {
		t.Fatal(e)
	}
	searchRev := knowledgeSave(t, a, "search", search)
	memory := defaultAgentMemory()
	memory.Embedding = agentMemoryProvider{Enabled: true, Endpoint: remote.URL + "/embeddings", Model: "synthetic", TimeoutSeconds: 1}
	memoryRev := knowledgeSave(t, a, "memory", memory)
	for _, v := range []struct {
		group, id string
		rev       time.Time
	}{{"search", "saved", searchRev}, {"memory", "embedding", memoryRev}} {
		path := "/api/agent-platform/" + v.group + "/test"
		for _, revision := range []string{"", v.rev.Add(-time.Second).Format(time.RFC3339Nano)} {
			mustRequest(t, s, "POST", path, map[string]any{"provider_id": v.id, "query": "합성", "expected_updated_at": revision}, admin, 409)
		}
	}
	if called.Load() != 0 {
		t.Fatal("stale or missing revision sent a provider request")
	}
	for _, v := range []struct {
		group, id string
		rev       time.Time
	}{{"search", "saved", searchRev}, {"memory", "embedding", memoryRev}} {
		got := mustRequest(t, s, "POST", "/api/agent-platform/"+v.group+"/test", map[string]any{"provider_id": v.id, "query": "합성", "expected_updated_at": v.rev.Format(time.RFC3339Nano)}, admin, 200)
		if str(got, "status") != "ok" {
			t.Fatal("current saved configuration test failed")
		}
	}
	if called.Load() != 2 {
		t.Fatal("current saved tests did not reach their providers exactly once")
	}
}
