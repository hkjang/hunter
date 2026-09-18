package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// mcpRequestKey marks a request on the MCP path: the only place authenticate
// may turn a Keycloak access token into a principal.
type mcpRequestKey struct{}

func (a *App) registerMCP(m *http.ServeMux) {
	m.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), mcpRequestKey{}, true))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			a.mcpChallenge(w, r, false)
			fail(w, 401, "개인 API 키가 필요합니다")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			g, _ := a.setting(r.Context(), "general")
			if e != nil || (u.Host != r.Host && origin != strings.TrimSuffix(asString(g["public_url"]), "/")) {
				fail(w, 403, "허용되지 않은 Origin입니다")
				return
			}
		}
		// Bearer requests are exempt from the cookie CSRF rule in protect; the
		// key path keeps its generic refusal, an SSO token gets the sentence the
		// client can act on while the cause goes to the log here and only here.
		u, e := a.authenticate(r)
		if e != nil {
			a.mcpChallenge(w, r, true)
			var refusal mcpOAuthRefusal
			if errors.As(e, &refusal) {
				slog.Warn("mcp sso token rejected", "cause", refusal.cause.Error())
				fail(w, 401, refusal.message)
				return
			}
			fail(w, 401, "로그인이 필요합니다")
			return
		}
		a.mcp(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, u)))
	})
	m.HandleFunc("/.well-known/oauth-protected-resource", a.mcpResourceMetadata)
	m.HandleFunc("/.well-known/oauth-protected-resource/mcp", a.mcpResourceMetadata)
	m.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "이 서버는 상태 없는 Streamable HTTP POST를 지원합니다")
	})
	m.HandleFunc("GET /api/openapi.json", a.protect("", func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, 200, a.openapi()) }))
}
func mcpTool(name, description, scope string, properties map[string]any, required []string) map[string]any {
	return map[string]any{"name": name, "description": description, "inputSchema": map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": scope != "scans:write", "destructiveHint": false, "idempotentHint": scope != "scans:write", "openWorldHint": false}}
}
func (a *App) mcp(w http.ResponseWriter, r *http.Request) {
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !slices.Contains([]string{"2025-03-26", "2025-06-18", "2025-11-25"}, v) {
		fail(w, 400, "지원하지 않는 MCP 프로토콜 버전입니다")
		return
	}
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if decode(r, &req) != nil || req.JSONRPC != "2.0" {
		jsonResponse(w, 400, map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "잘못된 JSON-RPC 요청"}})
		return
	}
	reply := func(result any) {
		jsonResponse(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	errReply := func(code int, message string) {
		jsonResponse(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": code, "message": message}})
	}
	if len(req.ID) == 0 {
		if strings.HasPrefix(req.Method, "notifications/") {
			w.WriteHeader(202)
			return
		}
		w.WriteHeader(202)
		return
	}
	u := currentUser(r)
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := "2025-06-18"
		if p.ProtocolVersion == "2025-11-25" {
			version = p.ProtocolVersion
		}
		reply(map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]string{"name": "hunter", "version": a.Version}, "instructions": "승인된 서비스 범위 내에서만 진단합니다. 발견 건은 검증 전 확정하지 않습니다. 개인 API 키 권한이 모든 도구 호출에 적용됩니다."})
	case "ping":
		reply(map[string]any{})
	case "tools/list":
		list := []map[string]any{}
		if slices.Contains(u.Scopes, "services:read") {
			list = append(list, mcpTool("hunter_list_services", "접근 가능한 사내 서비스 조회", "services:read", map[string]any{}, []string{}))
			list = append(list, mcpTool("hunter_list_components", "서비스별 최신 SBOM의 구성요소와 정확히 일치하는 발견 건 조회. 발견 건은 추가 조회 권한이 있을 때만 포함합니다", "services:read", map[string]any{"service_id": map[string]string{"type": "string"}, "q": map[string]string{"type": "string"}}, []string{}))
			if slices.Contains(u.Scopes, "findings:read") {
				list = append(list, mcpTool("hunter_finding_queue", "접근 가능한 미조치 발견 건의 우선순위·근거·SLA·위협 정보 조회", "findings:read", map[string]any{"view": map[string]any{"type": "string", "enum": []string{"all", "mine", "overdue", "due_soon", "unassigned"}}, "q": map[string]string{"type": "string"}, "page": map[string]any{"type": "integer", "minimum": 1}, "size": map[string]any{"type": "integer", "enum": []int{10, 25, 50, 100}}}, []string{}))
			}
			if slices.Contains(u.Scopes, "scans:read") {
				list = append(list, mcpTool("hunter_list_campaigns", "접근 가능한 서비스 집합의 진단 캠페인과 실제 실행 상태 조회", "scans:read", map[string]any{}, []string{}))
				if slices.Contains(u.Scopes, "findings:read") {
					list = append(list, mcpTool("hunter_compare_campaigns", "동일 조건의 완료된 캠페인 결과 비교. 미관측은 해결을 의미하지 않습니다", "scans:read", map[string]any{"current_id": map[string]string{"type": "string"}, "baseline_id": map[string]string{"type": "string"}}, []string{"current_id", "baseline_id"}))
				}
			}
		}
		if slices.Contains(u.Scopes, "findings:read") {
			list = append(list, mcpTool("hunter_list_findings", "접근 가능한 발견 건 및 개선 상태 조회", "findings:read", map[string]any{}, []string{}))
		}
		if slices.Contains(u.Scopes, "scans:write") {
			list = append(list, mcpTool("hunter_request_scan", "등록·승인된 서비스의 정책 범위 내 진단 요청", "scans:write", map[string]any{"service_id": map[string]string{"type": "string"}, "profile": map[string]any{"type": "string", "enum": []string{"http-baseline", "import-only", "authorization"}}, "scope_id": map[string]string{"type": "string"}, "scenario_id": map[string]string{"type": "string"}}, []string{"service_id", "profile"}))
		}
		reply(map[string]any{"tools": list})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if json.Unmarshal(req.Params, &p) != nil {
			errReply(-32602, "도구 입력이 올바르지 않습니다")
			return
		}
		scope := ""
		switch p.Name {
		case "hunter_list_services":
			scope = "services:read"
		case "hunter_list_findings":
			scope = "findings:read"
		case "hunter_request_scan":
			scope = "scans:write"
		case "hunter_list_components":
			scope = "services:read"
		case "hunter_finding_queue":
			scope = "findings:read"
		case "hunter_list_campaigns", "hunter_compare_campaigns":
			scope = "scans:read"
		default:
			errReply(-32602, "알 수 없는 도구입니다")
			return
		}
		if !slices.Contains(u.Scopes, scope) {
			errReply(-32003, "도구 권한이 없습니다")
			return
		}
		if (p.Name == "hunter_finding_queue" || p.Name == "hunter_list_campaigns" || p.Name == "hunter_compare_campaigns") && !slices.Contains(u.Scopes, "services:read") || p.Name == "hunter_compare_campaigns" && !slices.Contains(u.Scopes, "findings:read") {
			errReply(-32003, "도구의 추가 조회 권한이 없습니다")
			return
		}
		var result any
		var e error
		switch p.Name {
		case "hunter_request_scan":
			result, e = a.RequestScan(r.Context(), u, p.Arguments)
		case "hunter_list_components":
			result, e = a.Components(r.Context(), u, str(p.Arguments, "service_id"), str(p.Arguments, "q"))
		case "hunter_finding_queue":
			result, e = a.FindingQueue(r.Context(), u, FindingQueueOptions{View: str(p.Arguments, "view"), Query: str(p.Arguments, "q"), Page: number(p.Arguments, "page", 1), Size: number(p.Arguments, "size", 25)})
		case "hunter_list_campaigns":
			result, e = a.ListCampaigns(r.Context(), u)
		case "hunter_compare_campaigns":
			result, e = a.CompareCampaigns(r.Context(), u, str(p.Arguments, "current_id"), str(p.Arguments, "baseline_id"))
		default:
			kind := "services"
			if p.Name == "hunter_list_findings" {
				kind = "findings"
			}
			result, e = a.ListResources(r.Context(), kind, u)
		}
		if e != nil {
			reply(map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": e.Error()}}})
			return
		}
		detail := map[string]string{"tool": p.Name}
		if u.Auth == "oauth" {
			detail["auth"] = "sso"
		}
		a.audit(r, "mcp."+p.Name, "", detail)
		b, _ := json.Marshal(result)
		reply(map[string]any{"isError": false, "content": []map[string]string{{"type": "text", "text": string(b)}}})
	default:
		errReply(-32601, "지원하지 않는 메서드입니다")
	}
}
