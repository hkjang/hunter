package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func findingOpsTestApp(t *testing.T) (*App, *httptest.Server, *httptest.Server) {
	t.Helper()
	a, base := testApp(t)
	if err := a.initFindingOps(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := http.NewServeMux()
	a.registerFindingOps(m)
	ops := httptest.NewServer(m)
	t.Cleanup(ops.Close)
	return a, base, ops
}

func TestFindingOpsParsingAndValidation(t *testing.T) {
	date := "2026-01-01"
	valid := []struct{ format, body string }{{"kev", `{"count":1,"dateReleased":"2026-01-01T12:00:00Z","vulnerabilities":[{"cveID":"CVE-2025-12345","dateAdded":"2025-12-01"}]}`}, {"epss", "#model_version:v2025.03.14,score_date:2026-01-01\ncve,epss,percentile\nCVE-2025-12345,0,0\nCVE-2025-23456,0.2,\n"}}
	for _, v := range valid {
		entries, e := parseFindingIntelligence(v.format, v.body, date)
		if e != nil || len(entries) < 1 {
			t.Fatalf("%s parse: %v", v.format, e)
		}
	}
	invalid := []struct{ format, body string }{{"kev", `{"count":2,"vulnerabilities":[{"cveID":"CVE-2025-12345"}]}`}, {"kev", `{"vulnerabilities":[{"cveID":"CVE-2025-12345"},{"cveID":"CVE-2025-12345"}]}`}, {"kev", `{"vulnerabilities":[{"cveID":"CVE-2025-1"}]}`}, {"kev", `{"dateReleased":"2025-12-31","vulnerabilities":[{"cveID":"CVE-2025-12345"}]}`}, {"epss", "cve,epss\nCVE-2025-12345,NaN"}, {"epss", "cve,epss\nCVE-2025-12345,1.1"}, {"epss", "#score_date:2025-12-31\ncve,epss\nCVE-2025-12345,0.1"}, {"epss", "cve,epss\nCVE-2025-12345,0.1\nCVE-2025-12345,0.2"}, {"epss", "cve,epss\nCVE-2025-12345,0.1,extra"}}
	for _, v := range invalid {
		if _, e := parseFindingIntelligence(v.format, v.body, date); e == nil {
			t.Errorf("unsafe %s accepted: %s", v.format, v.body)
		}
	}
	for group, values := range findingOpsDefaultSettings() {
		if err := validateFindingOpsSettings(group, values); err != nil {
			t.Fatal(err)
		}
	}
	s := findingOpsDefaultSettings()["sla"]
	s["enabled"] = "yes"
	if validateFindingOpsSettings("sla", s) == nil {
		t.Fatal("nonboolean enabled")
	}
	r := findingOpsDefaultSettings()["risk"]
	r["epss_threshold"] = -0.1
	if validateFindingOpsSettings("risk", r) == nil {
		t.Fatal("negative threshold")
	}
	if validateFindingOpsResource(map[string]any{"due_date": "not-a-date"}) == nil {
		t.Fatal("invalid date")
	}
	if validateFindingOpsResource(map[string]any{"due_date": "2020-01-01T00:00:00Z"}) != nil {
		t.Fatal("historical deadline must be permitted")
	}
}

func TestFindingQueueIncludesOldRecordsAndRestrictsOwnership(t *testing.T) {
	a, base, ops := findingOpsTestApp(t)
	ctx := context.Background()
	admin := loginTest(t, base, "admin", "test-password-1234")
	for _, u := range []map[string]any{{"username": "queue-alice", "role": "analyst", "team": "red"}, {"username": "queue-bob", "role": "analyst", "team": "blue"}, {"username": "queue-red", "role": "lead", "team": "red"}, {"username": "queue-blue", "role": "lead", "team": "blue"}} {
		u["name"] = u["username"]
		u["password"] = "test-password-1234"
		mustRequest(t, base, "POST", "/api/users", u, admin, 201)
	}
	alice := loginTest(t, base, "queue-alice", "test-password-1234")
	bob := loginTest(t, base, "queue-bob", "test-password-1234")
	red := loginTest(t, base, "queue-red", "test-password-1234")
	blue := loginTest(t, base, "queue-blue", "test-password-1234")
	svc := mustRequest(t, base, "POST", "/api/services", map[string]any{"name": "Red service", "environment": "staging", "team": "red"}, alice, 200)
	foreign := mustRequest(t, base, "POST", "/api/services", map[string]any{"name": "Hidden blue service", "environment": "staging", "team": "blue"}, bob, 200)
	sid, owner := str(svc, "id"), str(svc, "owner_id")
	_, err := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data,created_at) SELECT 'queue-bulk-'||n,'findings',$1,jsonb_build_object('title','Ordinary '||n,'service_id',$2::text,'severity','low','status','candidate','assignee','reviewer'),now() FROM generate_series(1,5002) n`, owner, sid)
	if err != nil {
		t.Fatal(err)
	}
	old := domainResource{ID: newID(), Kind: "findings", OwnerID: owner, Data: map[string]any{"title": "Old critical needle", "service_id": sid, "severity": "critical", "status": "confirmed", "due_date": "2020-01-01T00:00:00Z", "cve": "CVE-2025-12345", "component": "core@1"}}
	if err = a.persistResource(ctx, &old); err != nil {
		t.Fatal(err)
	}
	_, _ = a.DB.Exec(ctx, `UPDATE resources SET created_at=now()-interval '5 years' WHERE id=$1`, old.ID)
	second := domainResource{ID: newID(), Kind: "findings", OwnerID: owner, Data: map[string]any{"title": "Second grouped needle", "service_id": sid, "severity": "high", "status": "candidate", "due_date": "not-a-valid-date", "cve": "CVE-2025-12345", "component": "core@1"}}
	if err = a.persistResource(ctx, &second); err != nil {
		t.Fatal(err)
	}
	outsider := domainResource{ID: newID(), Kind: "findings", OwnerID: str(foreign, "owner_id"), Data: map[string]any{"title": "SECRET BLUE", "service_id": str(foreign, "id"), "severity": "critical", "status": "candidate", "cve": "CVE-2025-12345", "component": "core@1"}}
	if err = a.persistResource(ctx, &outsider); err != nil {
		t.Fatal(err)
	}
	u := User{ID: owner, Role: "analyst", Scopes: []string{"findings:read", "services:read"}}
	direct, e := a.FindingQueue(ctx, u, FindingQueueOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if direct["total"].(int64) != 5004 {
		t.Fatalf("queue capped: %v", direct["total"])
	}
	response := mustRequest(t, ops, "GET", "/api/finding-queue", nil, alice, 200)
	items := array(response["items"])
	if len(items) != 25 || str(object(items[0]), "id") != old.ID {
		t.Fatal("old high priority record disappeared")
	}
	if object(object(items[0])["intelligence"])["kev"] != nil || object(object(items[0])["intelligence"])["epss"] != nil {
		t.Fatal("missing feed must be null")
	}
	if number(object(response["summary"]), "overdue", 0) != 1 || number(object(response["summary"]), "invalid_due_date", 0) != 1 {
		t.Fatal("deadline state mismatch")
	}
	groups := array(response["groups"])
	if len(groups) != 1 || number(object(groups[0]), "finding_count", 0) != 2 {
		t.Fatal("cross-service group leak or wrong grouping")
	}
	for _, credential := range []string{red} {
		v := mustRequest(t, ops, "GET", "/api/finding-queue?q=needle", nil, credential, 200)
		if number(v, "total", 0) != 2 {
			t.Fatal("lead cannot see own team")
		}
	}
	v := mustRequest(t, ops, "GET", "/api/finding-queue?q=needle", nil, blue, 200)
	if number(v, "total", 0) != 0 || len(array(v["groups"])) != 0 {
		t.Fatal("cross-team queue leaked")
	}
	v = mustRequest(t, ops, "GET", "/api/finding-queue?view=mine", nil, red, 200)
	if number(v, "total", 0) != 0 {
		t.Fatal("mine must mean finding owner")
	}
	v = mustRequest(t, ops, "GET", "/api/finding-queue?view=overdue", nil, alice, 200)
	if number(v, "total", 0) != 1 {
		t.Fatal("overdue view")
	}
	v = mustRequest(t, ops, "GET", "/api/finding-queue?q=needle&group="+str(object(groups[0]), "id"), nil, alice, 200)
	if number(v, "total", 0) != 2 {
		t.Fatal("group filtering")
	}
	v = mustRequest(t, ops, "GET", "/api/finding-queue?page=201", nil, alice, 200)
	if len(array(v["items"])) != 4 {
		t.Fatal("final page total wrong")
	}
	if _, e = a.FindingQueue(ctx, User{ID: owner, Role: "admin"}, FindingQueueOptions{}); e == nil {
		t.Fatal("scope-less admin bypassed exported method")
	}
	key := mustRequest(t, base, "POST", "/api/keys", map[string]any{"name": "queue-scope", "scopes": []string{"services:read"}, "expires_days": 1}, admin, 201)
	mustRequest(t, ops, "GET", "/api/finding-queue", nil, str(key, "token"), 403)
	key = mustRequest(t, base, "POST", "/api/keys", map[string]any{"name": "queue-no-service-scope", "scopes": []string{"findings:read"}, "expires_days": 1}, admin, 201)
	mustRequest(t, ops, "GET", "/api/finding-queue", nil, str(key, "token"), 403)
	if _, e = a.FindingQueue(ctx, User{ID: owner, Role: "admin", Scopes: []string{"findings:read"}}, FindingQueueOptions{}); e == nil {
		t.Fatal("MCP method bypassed service read scope")
	}
}

func TestFindingIntelligenceImportAndSLACalculation(t *testing.T) {
	a, base, ops := findingOpsTestApp(t)
	ctx := context.Background()
	admin := loginTest(t, base, "admin", "test-password-1234")
	svc := mustRequest(t, base, "POST", "/api/services", map[string]any{"name": "Intel service", "environment": "staging", "criticality": "tier3"}, admin, 200)
	f := mustRequest(t, base, "POST", "/api/findings", map[string]any{"title": "Intel finding", "service_id": svc["id"], "severity": "high", "cve": "CVE-2025-12345", "component": "lib@1"}, admin, 200)
	now := time.Now().UTC()
	date := now.Format("2006-01-02")
	kev := `{"count":1,"vulnerabilities":[{"cveID":"CVE-2025-12345"}]}`
	mustRequest(t, ops, "POST", "/api/intelligence/import", map[string]any{"format": "kev", "content": kev, "source_date": date}, admin, 200)
	mustRequest(t, ops, "POST", "/api/intelligence/import", map[string]any{"format": "epss", "content": "cve,epss,percentile\nCVE-2025-12345,0.9,0.99\n", "source_date": date}, admin, 200)
	v := mustRequest(t, ops, "GET", "/api/finding-queue", nil, admin, 200)
	item := object(array(v["items"])[0])
	if number(object(item["priority"]), "score", 0) != 90 || object(item["intelligence"])["kev"] != true {
		t.Fatalf("risk signal mismatch: %v", item["priority"])
	}
	if str(object(item["sla"]), "state") != "not_set" {
		t.Fatal("SLA must be disabled by default")
	}
	if str(item, "status") != "candidate" || str(item, "severity") != "high" {
		t.Fatal("priority altered original classification")
	}
	sla := findingOpsDefaultSettings()["sla"]
	sla["enabled"] = true
	raw, _ := json.Marshal(sla)
	_, err := a.DB.Exec(ctx, `INSERT INTO settings(key,value) VALUES('sla',$1) ON CONFLICT(key) DO UPDATE SET value=$1`, raw)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.DB.Exec(ctx, `UPDATE resources SET created_at=now()-interval '40 days' WHERE id=$1`, f["id"])
	v = mustRequest(t, ops, "GET", "/api/finding-queue?view=overdue", nil, admin, 200)
	item = object(array(v["items"])[0])
	if str(object(item["sla"]), "source") != "policy" {
		t.Fatal("automatic SLA not derived")
	}
	var stored map[string]any
	if a.DB.QueryRow(ctx, `SELECT data FROM resources WHERE id=$1`, f["id"]).Scan(&stored) != nil {
		t.Fatal("finding disappeared")
	}
	if _, ok := stored["due_date"]; ok {
		t.Fatal("derived SLA mutated existing finding")
	}
	manualDue := now.Add(48 * time.Hour).Format(time.RFC3339)
	mustRequest(t, base, "PUT", "/api/findings/"+str(f, "id"), map[string]any{"due_date": manualDue}, admin, 200)
	v = mustRequest(t, ops, "GET", "/api/finding-queue?view=due_soon", nil, admin, 200)
	item = object(array(v["items"])[0])
	if str(object(item["sla"]), "source") != "manual" || str(object(item["sla"]), "due_date") != manualDue {
		t.Fatal("manual deadline must override derived policy")
	}
	mustRequest(t, base, "PUT", "/api/findings/"+str(f, "id"), map[string]any{"due_date": "broken"}, admin, 400)
	mustRequest(t, ops, "POST", "/api/intelligence/import", map[string]any{"format": "epss", "content": "cve,epss\nCVE-2025-12345,NaN", "source_date": date}, admin, 400)
	mustRequest(t, ops, "POST", "/api/intelligence/import", map[string]any{"format": "kev", "content": kev, "source_date": now.AddDate(0, 0, -1).Format("2006-01-02")}, admin, 409)
	var count int
	_ = a.DB.QueryRow(ctx, `SELECT count(*) FROM finding_intel_entries WHERE format='epss' AND epss=0.9`).Scan(&count)
	if count != 1 {
		t.Fatal("invalid import clobbered active snapshot")
	}
	_, _ = a.DB.Exec(ctx, `UPDATE finding_intel_datasets SET source_date=current_date-60 WHERE format='epss'`)
	v = mustRequest(t, ops, "GET", "/api/finding-queue", nil, admin, 200)
	item = object(array(v["items"])[0])
	if number(object(item["priority"]), "score", 0) != 80 || object(item["intelligence"])["stale"] != true {
		t.Fatal("stale EPSS used as current score")
	}
	key := mustRequest(t, base, "POST", "/api/keys", map[string]any{"name": "intel-denied", "scopes": []string{"findings:read"}, "expires_days": 1}, admin, 201)
	mustRequest(t, ops, "POST", "/api/intelligence/import", map[string]any{"format": "kev", "content": kev, "source_date": date}, str(key, "token"), 403)
	mustRequest(t, ops, "GET", "/api/intelligence", nil, str(key, "token"), 403)
	// Active acceptance leaves the queue; expired acceptance returns immediately,
	// even before maintenance changes its persisted status back to candidate.
	_, _ = a.DB.Exec(ctx, `UPDATE resources SET data=data||jsonb_build_object('status','accepted','expires_at',now()+interval '1 day') WHERE id=$1`, f["id"])
	v = mustRequest(t, ops, "GET", "/api/finding-queue", nil, admin, 200)
	if number(v, "total", 0) != 0 {
		t.Fatal("active acceptance not excluded")
	}
	_, _ = a.DB.Exec(ctx, `UPDATE resources SET data=data||jsonb_build_object('expires_at',now()-interval '1 day') WHERE id=$1`, f["id"])
	v = mustRequest(t, ops, "GET", "/api/finding-queue", nil, admin, 200)
	if number(v, "total", 0) != 1 {
		t.Fatal("expired acceptance hidden until maintenance")
	}
}

func TestFindingActivityEncryptionAndParentPermissions(t *testing.T) {
	a, base, ops := findingOpsTestApp(t)
	ctx := context.Background()
	admin := loginTest(t, base, "admin", "test-password-1234")
	for _, input := range []map[string]any{{"username": "comment-owner", "role": "analyst", "team": "red"}, {"username": "comment-outsider", "role": "analyst", "team": "blue"}, {"username": "comment-lead", "role": "lead", "team": "red"}} {
		input["name"] = input["username"]
		input["password"] = "test-password-1234"
		mustRequest(t, base, "POST", "/api/users", input, admin, 201)
	}
	owner := loginTest(t, base, "comment-owner", "test-password-1234")
	outsider := loginTest(t, base, "comment-outsider", "test-password-1234")
	lead := loginTest(t, base, "comment-lead", "test-password-1234")
	svc := mustRequest(t, base, "POST", "/api/services", map[string]any{"name": "Comment service", "environment": "staging", "team": "red"}, owner, 200)
	f := mustRequest(t, base, "POST", "/api/findings", map[string]any{"title": "Comment finding", "service_id": svc["id"], "severity": "high"}, owner, 200)
	path := "/api/findings/" + str(f, "id") + "/activity"
	body := "보존할 검토 의견\nAuthorization: Bearer should-never-appear\n확인 완료"
	item := mustRequest(t, ops, "POST", path, map[string]any{"body": body}, owner, 201)
	if strings.Contains(str(item, "body"), "should-never-appear") || !strings.Contains(str(item, "body"), "[REDACTED]") {
		t.Fatal("comment secret not masked")
	}
	var cipher string
	if err := a.DB.QueryRow(ctx, `SELECT body_encrypted FROM finding_comments WHERE id=$1`, item["id"]).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cipher, "검토 의견") || strings.Contains(cipher, "should-never-appear") {
		t.Fatal("plaintext comment stored")
	}
	plain, err := a.decrypt(cipher)
	if err != nil || plain != str(item, "body") {
		t.Fatal("encrypted comment round trip")
	}
	var logs string
	_ = a.DB.QueryRow(ctx, `SELECT string_agg(detail::text,' ') FROM audit_logs WHERE action='finding.comment'`).Scan(&logs)
	if strings.Contains(logs, "검토 의견") || strings.Contains(logs, "should-never-appear") {
		t.Fatal("body leaked to global audit")
	}
	mustRequest(t, ops, "GET", path, nil, outsider, 404)
	mustRequest(t, ops, "POST", path, map[string]any{"body": "not allowed"}, outsider, 404)
	mustRequest(t, ops, "GET", path, nil, lead, 200)
	key := mustRequest(t, base, "POST", "/api/keys", map[string]any{"name": "comment-read-only", "scopes": []string{"findings:read"}, "expires_days": 1}, owner, 201)
	mustRequest(t, ops, "POST", path, map[string]any{"body": "not allowed"}, str(key, "token"), 403)
	key = mustRequest(t, base, "POST", "/api/keys", map[string]any{"name": "comment-no-read", "scopes": []string{"findings:write"}, "expires_days": 1}, owner, 201)
	mustRequest(t, ops, "GET", path, nil, str(key, "token"), 403)
	mustRequest(t, ops, "POST", path, map[string]any{"body": " "}, owner, 400)
	mustRequest(t, ops, "POST", path, map[string]any{"body": strings.Repeat("x", 16001)}, owner, 400)
	_, _ = a.DB.Exec(ctx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,'fixture','findings.save',$3,'{"title":"allowed title","password":"HIDDEN-AUDIT","evidence":"HIDDEN-EVIDENCE"}')`, newID(), f["owner_id"], f["id"])
	v := mustRequest(t, ops, "GET", path+"?size=100", nil, owner, 200)
	encoded, _ := json.Marshal(v)
	if strings.Contains(string(encoded), "HIDDEN-") || strings.Contains(string(encoded), "body_encrypted") {
		t.Fatal("activity allowlist leaked arbitrary metadata")
	}
	if number(v, "total", 0) < 2 {
		t.Fatal("comment and audit timeline absent")
	}
	_, _ = a.DB.Exec(ctx, `UPDATE users SET team='blue' WHERE username='comment-lead'`)
	mustRequest(t, ops, "GET", path, nil, lead, 404)
	if status, _, _ := request(t, ops, "POST", path, map[string]any{"body": "missing csrf"}, owner, false); status != 403 {
		t.Fatal(fmt.Sprint("CSRF not required: ", status))
	}
}
