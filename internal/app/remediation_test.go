package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOutboundRemediationIdempotency(t *testing.T) {
	_, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || !strings.HasPrefix(r.Header.Get("Idempotency-Key"), "hunter-") {
			t.Error("missing safe outbound method/idempotency")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["title"] != "확인된 테스트 항목" {
			t.Error("template did not expand")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		io.WriteString(w, `{"id":"TICKET-1","url":"https://tickets.example.internal/1"}`)
	}))
	defer target.Close()
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "test", "environment": "staging"}, cookie, 200)
	finding := mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "확인된 테스트 항목", "service_id": service["id"], "severity": "high", "status": "confirmed"}, cookie, 200)
	integration := mustRequest(t, s, "POST", "/api/integrations", map[string]any{"name": "ticket API", "type": "rest", "endpoint": target.URL, "enabled": true, "config": map[string]any{"direction": "outbound", "template": map[string]any{"title": "{{finding.title}}", "id": "{{remediation.id}}"}}}, cookie, 200)
	rem := mustRequest(t, s, "POST", "/api/remediations", map[string]any{"name": "test remediation", "finding_id": finding["id"], "integration_id": integration["id"]}, cookie, 200)
	path := "/api/remediations/" + asString(rem["id"]) + "/dispatch"
	result := mustRequest(t, s, "POST", path, nil, cookie, 200)
	if result["external_id"] != "TICKET-1" || result["dispatch_state"] != "sent" {
		t.Fatal("upstream mapping failed")
	}
	mustRequest(t, s, "POST", path, nil, cookie, 409)
	if calls.Load() != 1 {
		t.Fatal("duplicate ticket created")
	}
}
func TestTemplateDoesNotInterpretJSON(t *testing.T) {
	v, e := expandTemplate(map[string]any{"title": "{{finding.title}}"}, map[string]map[string]any{"finding": {"title": "\"},\"admin\":true"}})
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	if len(out) != 1 {
		t.Fatal("value escaped JSON boundary")
	}
	if _, e = expandTemplate("{{finding.unknown}}", map[string]map[string]any{}); e == nil {
		t.Fatal("unknown template accepted")
	}
}
