package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const workflowTestSecret = "hunter-automation-local-test-signing-key-only"

func workflowTestApp(t *testing.T) (*App, *httptest.Server, string) {
	a, _ := testApp(t)
	if e := a.initWorkflowAutomation(context.Background()); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	a.registerWorkflowAutomation(mux)
	mux.Handle("/", a.Routes())
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return a, s, loginTest(t, s, "admin", "test-password-1234")
}
func workflowTestSave(t *testing.T, s *httptest.Server, admin string, changes []map[string]any, tickets []map[string]any) map[string]any {
	old := mustRequest(t, s, "GET", "/api/workflow-automation", nil, admin, 200)
	return mustRequest(t, s, "PUT", "/api/workflow-automation", map[string]any{"enabled": true, "change_rules": changes, "ticket_rules": tickets, "signing_secret": workflowTestSecret, "expected_updated_at": str(old, "updated_at")}, admin, 200)
}
func workflowTestKey(t *testing.T, s *httptest.Server, admin string, scopes []string) string {
	return str(mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "workflow integration test", "scopes": scopes, "expires_days": 7}, admin, 201), "token")
}
func workflowSigned(t *testing.T, s *httptest.Server, path string, payload any, key, secret string) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(payload)
	stamp := fmt.Sprint(time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stamp + "\n"))
	mac.Write(raw)
	r, _ := http.NewRequest("POST", s.URL+path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Hunter-Timestamp", stamp)
	r.Header.Set("X-Hunter-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("Content-Type", "application/json")
	response, e := s.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return response.StatusCode, out
}
func TestWorkflowPatternsAndTicketValidation(t *testing.T) {
	if !workflowGlob("src/**", "src/team/api.go") || workflowGlob("src/*", "src/team/api.go") || !workflowGlob("/api/v?/*", "/api/v1/items") {
		t.Fatal("glob boundaries")
	}
	if validateWorkflowChanges(workflowChanges{Paths: []string{"a[b]"}}, true) == nil {
		t.Fatal("unsupported pattern")
	}
	for _, u := range []string{"https://{{external_id}}.example/tickets", "https://example/tickets/no-marker", "https://example/tickets/{{external_id}}?token=value"} {
		if validateTicketURL(u) == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
	if _, e := workflowTicketURL("https://example/tickets/{{external_id}}", "a/b?x=1"); e == nil {
		t.Fatal("unsafe external identifier accepted")
	}
	fields := workflowTicketFields{ExternalID: "id", Status: "status", UpdatedAt: "updated", DeploymentConfirmed: "deployed"}
	if _, e := workflowTicketMap(map[string]any{"id": "x", "status": "done", "updated": time.Now().UTC().Format(time.RFC3339), "deployed": "true"}, fields); e == nil {
		t.Fatal("non-boolean deployment accepted")
	}
}
func TestWorkflowChangeSignedIdempotencyAndCurrentPolicy(t *testing.T) {
	a, s, admin := workflowTestApp(t)
	ctx := context.Background()
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Change target", "environment": "staging", "url": "https://change.internal"}, admin, 200)
	sid := str(service, "id")
	integration := mustRequest(t, s, "POST", "/api/integrations", map[string]any{"name": "signed changes", "type": "webhook", "enabled": true}, admin, 200)
	iid := str(integration, "id")
	rules := []map[string]any{{"id": "code", "name": "Source import", "enabled": true, "integration_id": iid, "service_id": sid, "event_types": []string{"push"}, "match": map[string]any{"paths": []string{"src/**"}}, "profile": "import-only"}, {"id": "api", "name": "API requires approval", "enabled": true, "integration_id": iid, "service_id": sid, "event_types": []string{"push"}, "match": map[string]any{"api_paths": []string{"/api/**"}}, "profile": "http-baseline"}}
	config := workflowTestSave(t, s, admin, rules, nil)
	if str(config, "signing_secret") != "" || !boolean(config, "signing_secret_configured") {
		t.Fatal("secret response")
	}
	var encrypted string
	if e := a.DB.QueryRow(ctx, `SELECT encrypted FROM workflow_automation_config`).Scan(&encrypted); e != nil || strings.Contains(encrypted, workflowTestSecret) {
		t.Fatal("config secret not encrypted")
	}
	mustRequest(t, s, "PUT", "/api/workflow-automation", map[string]any{"expected_updated_at": "2000-01-01T00:00:00Z"}, admin, 409)
	key := workflowTestKey(t, s, admin, []string{"integrations:manage", "services:read", "scans:read", "scans:write"})
	event := map[string]any{"service_id": sid, "event_type": "push", "reference": "commit-1", "changes": map[string]any{"paths": []string{"src/nested/main.go", "docs/readme.md"}, "api_paths": []string{"/api/v1/items"}}}
	endpoint := "/api/integrations/" + iid + "/webhook"
	if code, _ := workflowSigned(t, s, endpoint, event, key, "wrong"); code != 401 {
		t.Fatal("unsigned changes accepted")
	}
	preview := cloneMap(event)
	preview["integration_id"] = iid
	mustRequest(t, s, "POST", "/api/workflow-automation/preview", preview, admin, 200)
	var count int
	a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='scans'`).Scan(&count)
	if count != 0 {
		t.Fatal("preview wrote scans")
	}
	var wg sync.WaitGroup
	codes := make(chan int, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, out := workflowSigned(t, s, endpoint, event, key, workflowTestSecret)
			if str(object(out["run"]), "status") != "partial" {
				code = 599
			}
			codes <- code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 && code != 201 {
			t.Fatalf("concurrent event failed: %d", code)
		}
	}
	a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='scans'`).Scan(&count)
	if count != 1 {
		t.Fatalf("matched scan count=%d", count)
	}
	event["changes"] = map[string]any{"paths": []string{"different.go"}}
	if code, _ := workflowSigned(t, s, endpoint, event, key, workflowTestSecret); code != 409 {
		t.Fatal("same identity changed payload accepted")
	}
	event["reference"] = "no-match"
	if code, out := workflowSigned(t, s, endpoint, event, key, workflowTestSecret); code != 201 || str(object(out["run"]), "status") != "no_match" {
		t.Fatal("no match did not remain idle")
	}
	narrow := workflowTestKey(t, s, admin, []string{"integrations:manage"})
	event["reference"] = "narrow"
	if code, _ := workflowSigned(t, s, endpoint, event, narrow, workflowTestSecret); code != 403 {
		t.Fatalf("key expanded: %d", code)
	}
	// Existing discovery input remains a separate, non-scanning workflow.
	out := mustRequest(t, s, "POST", endpoint, map[string]any{"assets": []any{map[string]any{"name": "discovered", "url": "https://new.internal"}}}, key, 200)
	if number(out, "candidates", 0) != 1 {
		t.Fatal("discovery fallback lost")
	}
}
func TestWorkflowTicketSyncConflictDeploymentAndPolling(t *testing.T) {
	a, s, admin := workflowTestApp(t)
	ctx := context.Background()
	var reads atomic.Int32
	var mu sync.Mutex
	stamp := time.Now().Add(-time.Minute).UTC()
	payload := map[string]any{"id": "INC-1", "status": "done", "updated_at": stamp.Format(time.RFC3339Nano), "assignee": "external-owner", "due": "2030-01-01T00:00:00Z", "deployment": map[string]any{"id": "deploy-1", "confirmed": false}}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("sync mutated upstream")
		}
		reads.Add(1)
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(payload)
	}))
	defer remote.Close()
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer closeTarget()
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Ticket target", "url": target, "environment": "staging", "approved": true}, admin, 200)
	sid := str(service, "id")
	targetURL, _ := url.Parse(target)
	scope := mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "Ticket scope", "service_id": sid, "allowed_hosts": []string{targetURL.Host}, "allowed_paths": []string{"/"}, "approved": true, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)}, admin, 200)
	finding := mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "Header regression", "service_id": sid, "source": "http-baseline", "rule_id": "x-content-type-options", "location": "/", "status": "confirmed", "severity": "high"}, admin, 200)
	// Simulate immutable provenance written by the existing HTTP scanner, which manual findings cannot claim.
	if _, err := a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"source":"http-baseline"}'::jsonb WHERE id=$1`, str(finding, "id")); err != nil {
		t.Fatal(err)
	}
	integration := mustRequest(t, s, "POST", "/api/integrations", map[string]any{"name": "ITSM read", "type": "rest", "endpoint": remote.URL + "/tickets", "enabled": true, "config": map[string]any{"direction": "outbound", "service_id": sid}}, admin, 200)
	iid := str(integration, "id")
	rem := mustRequest(t, s, "POST", "/api/remediations", map[string]any{"name": "Local remediation", "finding_id": str(finding, "id"), "integration_id": iid}, admin, 200)
	rid := str(rem, "id")
	a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"dispatch_state":"sent","external_id":"INC-1"}'::jsonb WHERE id=$1`, rid)
	ticketRule := map[string]any{"id": "itsm", "name": "ITSM mapping", "enabled": true, "service_id": sid, "integration_id": iid, "read_url_template": remote.URL + "/tickets/{{external_id}}", "poll_interval_minutes": 5, "field_map": map[string]any{"external_id": "id", "assignee": "assignee", "due_date": "due", "status": "status", "updated_at": "updated_at", "deployment_reference": "deployment.id", "deployment_confirmed": "deployment.confirmed"}, "complete_statuses": []string{"done"}, "retest_on_deploy": true, "scope_id": str(scope, "id")}
	workflowTestSave(t, s, admin, nil, []map[string]any{ticketRule})
	syncNow := func(accept bool) map[string]any {
		current := mustRequest(t, s, "GET", "/api/remediations/"+rid, nil, admin, 200)
		input := map[string]any{"remediation_id": rid, "expected_updated_at": current["updated_at"]}
		if accept {
			f := mustRequest(t, s, "GET", "/api/findings/"+str(finding, "id"), nil, admin, 200)
			input["accept_external"] = true
			input["expected_finding_updated_at"] = f["updated_at"]
			mu.Lock()
			input["expected_external_updated_at"] = payload["updated_at"]
			mu.Unlock()
		}
		return mustRequest(t, s, "POST", "/api/workflow-automation/sync", input, admin, 200)
	}
	first := syncNow(false)
	if str(first, "status") != "completed" {
		t.Fatalf("sync failed: %v", first)
	}
	f := mustRequest(t, s, "GET", "/api/findings/"+str(finding, "id"), nil, admin, 200)
	if str(f, "status") != "confirmed" || str(f, "assignee") != "external-owner" {
		t.Fatal("external completion changed finding status")
	}
	var scans int
	a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='scans'`).Scan(&scans)
	if scans != 0 {
		t.Fatal("external done alone triggered retest")
	}
	duplicate := syncNow(false)
	if str(duplicate, "id") != str(first, "id") {
		t.Fatal("duplicate sync not idempotent")
	}
	mustRequest(t, s, "PUT", "/api/findings/"+str(finding, "id"), map[string]any{"assignee": "local-edit"}, admin, 200)
	mu.Lock()
	payload["updated_at"] = stamp.Add(time.Second).Format(time.RFC3339Nano)
	payload["assignee"] = "remote-edit"
	payload["deployment"] = map[string]any{"id": "deploy-1", "confirmed": true}
	mu.Unlock()
	conflict := syncNow(false)
	if str(conflict, "status") != "conflict" {
		t.Fatal("local edit overwritten")
	}
	// The user's approval applies to both versions they reviewed, not to a new
	// remote GET or a local revision fetched only after clicking override.
	currentRem := mustRequest(t, s, "GET", "/api/remediations/"+rid, nil, admin, 200)
	reviewedFinding := mustRequest(t, s, "GET", "/api/findings/"+str(finding, "id"), nil, admin, 200)
	reviewedExternal := stamp.Add(time.Second).Format(time.RFC3339Nano)
	forceInput := map[string]any{"remediation_id": rid, "expected_updated_at": currentRem["updated_at"], "accept_external": true, "expected_finding_updated_at": reviewedFinding["updated_at"]}
	mustRequest(t, s, "POST", "/api/workflow-automation/sync", forceInput, admin, 409)
	forceInput["expected_external_updated_at"] = reviewedExternal
	mu.Lock()
	payload["updated_at"] = stamp.Add(2 * time.Second).Format(time.RFC3339Nano)
	mu.Unlock()
	mustRequest(t, s, "POST", "/api/workflow-automation/sync", forceInput, admin, 409)
	mu.Lock()
	payload["updated_at"] = reviewedExternal
	payload["assignee"] = "changed-with-reused-timestamp"
	mu.Unlock()
	mustRequest(t, s, "POST", "/api/workflow-automation/sync", forceInput, admin, 409)
	mu.Lock()
	payload["assignee"] = "remote-edit"
	mu.Unlock()
	mustRequest(t, s, "PUT", "/api/findings/"+str(finding, "id"), map[string]any{"assignee": "local-edit-after-review"}, admin, 200)
	mustRequest(t, s, "POST", "/api/workflow-automation/sync", forceInput, admin, 409)
	unchangedFinding := mustRequest(t, s, "GET", "/api/findings/"+str(finding, "id"), nil, admin, 200)
	if str(unchangedFinding, "assignee") != "local-edit-after-review" {
		t.Fatal("stale override changed local data")
	}
	if err := a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='scans'`).Scan(&scans); err != nil || scans != 0 {
		t.Fatal("stale override created a retest")
	}
	forced := syncNow(true)
	if str(forced, "status") != "completed" || len(array(object(forced["result"])["scan_ids"])) != 1 {
		t.Fatalf("explicit deployment retest not requested: %v", forced)
	}
	mu.Lock()
	payload["updated_at"] = stamp.Add(2 * time.Second).Format(time.RFC3339Nano)
	mu.Unlock()
	again := syncNow(false)
	if len(array(object(again["result"])["scan_ids"])) != 0 {
		t.Fatal("same deployment requested twice")
	}
	if e := a.WorkflowAutomationTick(ctx); e != nil {
		t.Fatal(e)
	}
	before := reads.Load()
	if e := a.WorkflowAutomationTick(ctx); e != nil || reads.Load() != before {
		t.Fatal("poll interval not respected")
	}
	// Polling uses the current settings owner's role, not an elevated synthetic account.
	c, e := a.workflowConfig(ctx)
	if e != nil {
		t.Fatal(e)
	}
	a.DB.Exec(ctx, `UPDATE users SET disabled=true WHERE id=$1`, c.OwnerID)
	if e = a.WorkflowAutomationTick(ctx); e == nil {
		t.Fatal("disabled owner still polled")
	}
	if reads.Load() != before {
		t.Fatal("revoked authority made outbound read")
	}
}

func TestWorkflowTicketCallbackReplayAndCurrentAuthority(t *testing.T) {
	a, s, admin := workflowTestApp(t)
	ctx := context.Background()
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "callback service", "environment": "staging"}, admin, 200)
	sid := str(service, "id")
	integration := mustRequest(t, s, "POST", "/api/integrations", map[string]any{"name": "callback integration", "type": "rest", "endpoint": "https://itsm.example/tickets", "enabled": true}, admin, 200)
	iid := str(integration, "id")
	finding := mustRequest(t, s, "POST", "/api/findings", map[string]any{"service_id": sid, "title": "Callback candidate", "severity": "high"}, admin, 200)
	rem := mustRequest(t, s, "POST", "/api/remediations", map[string]any{"finding_id": str(finding, "id"), "integration_id": iid, "name": "Callback ticket"}, admin, 200)
	rid := str(rem, "id")
	a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"dispatch_state":"sent","external_id":"EXT-1"}'::jsonb WHERE id=$1`, rid)
	workflowTestSave(t, s, admin, nil, []map[string]any{{"id": "callback", "name": "Callback mapping", "enabled": true, "service_id": sid, "integration_id": iid, "read_url_template": "https://itsm.example/tickets/{{external_id}}", "field_map": map[string]any{"external_id": "id", "status": "status", "updated_at": "updated"}}})
	scopes := []string{"admin:manage", "integrations:manage", "services:read", "findings:read", "findings:write", "scans:read", "scans:write"}
	key := workflowTestKey(t, s, admin, scopes)
	endpoint := "/api/integrations/" + iid + "/tickets/callback"
	stamp := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	payload := map[string]any{"remediation_id": rid, "ticket": map[string]any{"id": "EXT-1", "status": "done", "updated": stamp}}
	if code, _ := workflowSigned(t, s, endpoint, payload, key, "bad-signature"); code != 401 {
		t.Fatal("callback signature bypass")
	}
	firstCode, first := workflowSigned(t, s, endpoint, payload, key, workflowTestSecret)
	if firstCode != 200 || str(first, "status") != "completed" {
		t.Fatalf("callback failed: %d %v", firstCode, first)
	}
	if code, again := workflowSigned(t, s, endpoint, payload, key, workflowTestSecret); code != 200 || str(again, "id") != str(first, "id") {
		t.Fatal("callback duplicated")
	}
	payload["ticket"] = map[string]any{"id": "EXT-1", "status": "other", "updated": stamp}
	if code, _ := workflowSigned(t, s, endpoint, payload, key, workflowTestSecret); code != 409 {
		t.Fatal("same revision different fields accepted")
	}
	narrow := workflowTestKey(t, s, admin, []string{"integrations:manage", "services:read", "findings:read"})
	if code, _ := workflowSigned(t, s, endpoint, payload, narrow, workflowTestSecret); code != 403 {
		t.Fatalf("callback scope bypass: %d", code)
	}
	status, _, _ := request(t, s, "GET", "/api/workflow-automation/runs", nil, workflowTestKey(t, s, admin, []string{"admin:manage"}), true)
	if status != 403 {
		t.Fatal("aggregate leaked without source scopes")
	}
	// A principal loaded before a concurrent team edit cannot retain its old ACL.
	req, _ := http.NewRequest("GET", s.URL, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	u, e := a.authenticate(req)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.DB.Exec(ctx, `UPDATE users SET team='changed-team' WHERE id=$1`, u.ID); e != nil {
		t.Fatal(e)
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = workflowAccessTx(ctx, tx, u, iid, sid); e == nil {
		t.Fatal("stale team principal retained access")
	}
	tx.Rollback(ctx)
	// The scheduler retains the configuring API key and rechecks its revocation.
	current := mustRequest(t, s, "GET", "/api/workflow-automation", nil, key, 200)
	current["expected_updated_at"] = current["updated_at"]
	mustRequest(t, s, "PUT", "/api/workflow-automation", current, key, 200)
	var keyID string
	a.DB.QueryRow(ctx, `SELECT id FROM api_keys WHERE token_hash=$1`, digest(key)).Scan(&keyID)
	mustRequest(t, s, "DELETE", "/api/keys/"+keyID, nil, admin, 200)
	if e = a.WorkflowAutomationTick(ctx); e == nil {
		t.Fatal("revoked configuring key remained a polling authority")
	}
}
