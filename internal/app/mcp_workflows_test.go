package app

import "testing"

func TestMCPWorkflowReadersKeepKeyIntersection(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	invoke := func(token, name string, args map[string]any) map[string]any {
		return mustRequest(t, s, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}}, token, 200)
	}
	serviceKey := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "software-reader", "scopes": []string{"services:read"}, "expires_days": 7}, admin, 201)
	token := str(serviceKey, "token")
	if r := invoke(token, "hunter_list_components", map[string]any{}); r["error"] != nil || boolean(object(r["result"]), "isError") {
		t.Fatalf("component reader failed: %v", r)
	}
	for _, tool := range []string{"hunter_finding_queue", "hunter_list_campaigns", "hunter_compare_campaigns"} {
		if invoke(token, tool, map[string]any{})["error"] == nil {
			t.Fatalf("admin key bypassed missing scope for %s", tool)
		}
	}
	readKey := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "workflow-reader", "scopes": []string{"services:read", "findings:read", "scans:read"}, "expires_days": 7}, admin, 201)
	token = str(readKey, "token")
	for _, tool := range []string{"hunter_finding_queue", "hunter_list_campaigns"} {
		r := invoke(token, tool, map[string]any{})
		if r["error"] != nil || boolean(object(r["result"]), "isError") {
			t.Fatalf("authorized read failed %s %v", tool, r)
		}
	}
	invalid := invoke(token, "hunter_finding_queue", map[string]any{"size": 7})
	if !boolean(object(invalid["result"]), "isError") {
		t.Fatal("invalid server page size accepted")
	}
	if invoke(token, "hunter_request_scan", map[string]any{})["error"] == nil {
		t.Fatal("read tools granted scan write")
	}
}
