package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

type agentSearchItem struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}

func knowledgeText(s string, n int) string {
	s = maskAgentText(strings.ToValidUTF8(s, ""))
	if len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
func knowledgeJSONPath(v any, path string) any {
	for _, p := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}
func (a *App) knowledgeJSON(ctx context.Context, method, endpoint, key string, body any, timeout time.Duration) (map[string]any, string) {
	var data []byte
	var e error
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return nil, "invalid_request"
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if e != nil {
		return nil, "invalid_endpoint"
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	client, e := a.outboundClient(ctx, timeout)
	if e != nil {
		return nil, "tls_configuration"
	}
	defer client.CloseIdleConnections()
	res, e := client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return nil, "cancelled"
		}
		return nil, "connection_failed"
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Sprintf("http_%d", res.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if e != nil {
		return nil, "response_read_failed"
	}
	if len(raw) > 2*1024*1024 {
		return nil, "response_too_large"
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || result == nil {
		return nil, "invalid_json"
	}
	return result, "ok"
}
func (a *App) callAgentSearch(ctx context.Context, p agentSearchProvider, query string, limit int) ([]agentSearchItem, string) {
	endpoint, e := url.Parse(p.Endpoint)
	if e != nil {
		return nil, "invalid_endpoint"
	}
	method := "GET"
	key := p.APIKey
	var body any
	q := endpoint.Query()
	switch p.Kind {
	case "duckduckgo":
		q.Set("q", query)
		q.Set("format", "json")
		q.Set("no_html", "1")
		q.Set("skip_disambig", "1")
	case "google_cse":
		q.Set("q", query)
		q.Set("cx", p.CX)
		q.Set("key", key)
		q.Set("num", fmt.Sprint(limit))
		key = ""
	case "tavily":
		method = "POST"
		body = map[string]any{"query": query, "max_results": limit, "search_depth": "basic", "include_answer": false, "include_raw_content": false, "include_images": false}
	case "perplexity":
		method = "POST"
		body = map[string]any{"query": query, "max_results": limit, "max_tokens": 4096, "max_tokens_per_page": 1024}
	case "searxng":
		q.Set("q", query)
		q.Set("format", "json")
	case "http_json":
		method = p.Method
		if method == "POST" {
			body = map[string]any{"query": query, "q": query, "limit": limit}
		} else {
			q.Set("q", query)
			q.Set("limit", fmt.Sprint(limit))
		}
	default:
		return nil, "unsupported_provider"
	}
	endpoint.RawQuery = q.Encode()
	raw, code := a.knowledgeJSON(ctx, method, endpoint.String(), key, body, time.Duration(p.TimeoutSeconds)*time.Second)
	if code != "ok" {
		return nil, code
	}
	items := []agentSearchItem{}
	seen := map[string]bool{}
	add := func(title, link, snippet string) {
		if p.APIKey != "" {
			title = strings.ReplaceAll(title, p.APIKey, "[마스킹]")
			snippet = strings.ReplaceAll(snippet, p.APIKey, "[마스킹]")
			if strings.Contains(link, p.APIKey) {
				return
			}
		}
		u, e := url.Parse(link)
		if e != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || len(link) > 2048 || seen[link] || len(items) >= limit {
			return
		}
		u.Fragment = ""
		for k := range u.Query() {
			if strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "key") || strings.Contains(strings.ToLower(k), "password") {
				return
			}
		}
		seen[link] = true
		items = append(items, agentSearchItem{knowledgeText(title, 500), knowledgeText(u.String(), 2048), knowledgeText(snippet, 4000)})
	}
	if p.Kind == "duckduckgo" {
		add(asString(raw["Heading"]), asString(raw["AbstractURL"]), asString(raw["AbstractText"]))
		var walk func(any, int)
		walk = func(v any, depth int) {
			if depth > 5 {
				return
			}
			if list, ok := v.([]any); ok {
				for _, entry := range list {
					if m, ok := entry.(map[string]any); ok {
						add(asString(m["Text"]), asString(m["FirstURL"]), asString(m["Text"]))
						walk(m["Topics"], depth+1)
					}
				}
			}
		}
		walk(raw["RelatedTopics"], 0)
	} else {
		path, title, link, snippet := "results", "title", "url", "snippet"
		switch p.Kind {
		case "google_cse":
			path = "items"
			link = "link"
		case "tavily", "searxng":
			snippet = "content"
		case "http_json":
			path = p.ResultsPath
			title = p.TitlePath
			link = p.URLPath
			snippet = p.SnippetPath
		}
		list, ok := knowledgeJSONPath(raw, path).([]any)
		if !ok {
			return nil, "invalid_results"
		}
		for _, v := range list {
			add(asString(knowledgeJSONPath(v, title)), asString(knowledgeJSONPath(v, link)), asString(knowledgeJSONPath(v, snippet)))
		}
	}
	if len(items) == 0 {
		return items, "empty"
	}
	return items, "ok"
}
func (a *App) knowledgeOutcome(ctx context.Context, group, id string, rev time.Time, success bool, code string, start time.Time) {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = a.platformOutcome(bounded, group, id, rev, success, code, time.Since(start))
}

func (a *App) knowledgeRevisionCurrent(ctx context.Context, group string, rev time.Time) bool {
	var current time.Time
	return a.DB.QueryRow(ctx, `SELECT updated_at FROM agent_platform_config WHERE group_name=$1`, group).Scan(&current) == nil && current.Equal(rev)
}
