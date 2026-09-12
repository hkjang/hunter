package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func campaignTestCreate(t *testing.T, s *httptest.Server, credential string, targets []map[string]any) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/campaigns", map[string]any{"name": "합성 진단 캠페인", "description": "DB 회귀 검사", "targets": targets}, credential, 201)
}

func campaignTestStart(t *testing.T, s *httptest.Server, credential string, c map[string]any) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/campaigns/"+str(c, "id")+"/start", nil, credential, 200)
}

func campaignTestScanID(t *testing.T, campaign map[string]any) string {
	t.Helper()
	scans := array(campaign["scans"])
	if len(scans) != 1 {
		t.Fatalf("want one scan, got %d", len(scans))
	}
	return str(object(scans[0]), "id")
}

func TestCampaignTargetValidation(t *testing.T) {
	if targets, err := normalizeCampaignTargets([]campaignTarget{{ServiceID: "svc"}}); err != nil || targets[0].Profile != "http-baseline" {
		t.Fatal("default profile not normalized")
	}
	invalid := [][]campaignTarget{nil, make([]campaignTarget, 21), {{ServiceID: "s", Profile: "shell"}}, {{ServiceID: "s", Profile: "authorization"}}, {{ServiceID: "s", ScenarioID: "unexpected"}}, {{ServiceID: "s"}, {ServiceID: "s", ScopeID: "different"}}}
	for _, targets := range invalid {
		if _, err := normalizeCampaignTargets(targets); err == nil {
			t.Fatalf("invalid targets accepted: %#v", targets)
		}
	}
}

func TestCampaignAtomicStartAndLiveAccess(t *testing.T) {
	a, s := testApp(t)
	ctx := context.Background()
	admin := loginTest(t, s, "admin", "test-password-1234")
	aliceUser := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "campaign-alice", "name": "Alice", "team": "red", "role": "analyst", "password": "test-password-1234"}, admin, 201)
	blueUser := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "campaign-blue", "name": "Blue", "team": "blue", "role": "lead", "password": "test-password-1234"}, admin, 201)
	alice := loginTest(t, s, "campaign-alice", "test-password-1234")
	blue := loginTest(t, s, "campaign-blue", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Campaign red", "url": "https://campaign.internal", "environment": "staging", "team": "red"}, alice, 200)
	sid := str(service, "id")
	input := []map[string]any{{"service_id": sid, "profile": "import-only"}, {"service_id": sid, "profile": "http-baseline"}}
	c := campaignTestCreate(t, s, alice, input)
	id := str(c, "id")
	mustRequest(t, s, "POST", "/api/campaigns/"+id+"/start", nil, alice, 400)
	var count int
	if err := a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='scans'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial campaign leaked a scan: %d %v", count, err)
	}
	if got := mustRequest(t, s, "GET", "/api/campaigns/"+id, nil, alice, 200); str(got, "status") != "draft" {
		t.Fatal("failed start changed draft state")
	}
	c = campaignTestCreate(t, s, alice, input[:1])
	id = str(c, "id")
	results := make(chan string, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, body, _ := request(t, s, "POST", "/api/campaigns/"+id+"/start", nil, alice, true)
			if code != 200 {
				results <- "failed"
				return
			}
			var result map[string]any
			_ = json.Unmarshal(body, &result)
			scans := array(result["scans"])
			if len(scans) != 1 {
				results <- "failed"
				return
			}
			results <- str(object(scans[0]), "id")
		}()
	}
	wg.Wait()
	close(results)
	first := ""
	for scan := range results {
		if scan == "failed" || scan == "" || first != "" && first != scan {
			t.Fatal("concurrent starts were not idempotent")
		}
		first = scan
	}
	if err := a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='scans'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate scan rows: %d %v", count, err)
	}
	if err := a.DB.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='campaign.start' AND target=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate start audit: %d %v", count, err)
	}
	var mark string
	if err := a.DB.QueryRow(ctx, `SELECT data->>'campaign_id' FROM resources WHERE id=$1`, first).Scan(&mark); err != nil || mark != id {
		t.Fatal("scan does not identify its campaign")
	}
	secondService := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Campaign second", "url": "https://second.internal", "environment": "staging", "team": "red"}, alice, 200)
	lateFailure := campaignTestCreate(t, s, alice, []map[string]any{{"service_id": sid, "profile": "import-only"}, {"service_id": str(secondService, "id"), "profile": "import-only"}})
	// Fail the second INSERT, after all preparation succeeds, to prove rollback
	// includes the first scan, links, campaign transition and start audit.
	if _, err := a.DB.Exec(ctx, `CREATE TABLE campaign_test_rejected_service(id text);
	CREATE FUNCTION campaign_test_reject_scan() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
	 IF NEW.kind='scans' AND EXISTS(SELECT 1 FROM campaign_test_rejected_service WHERE id=NEW.data->>'service_id') THEN RAISE EXCEPTION 'synthetic insert failure'; END IF;
	 RETURN NEW; END $$;
	CREATE TRIGGER campaign_test_reject BEFORE INSERT ON resources FOR EACH ROW EXECUTE FUNCTION campaign_test_reject_scan()`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(ctx, `INSERT INTO campaign_test_rejected_service(id) VALUES($1)`, str(secondService, "id")); err != nil {
		t.Fatal(err)
	}
	mustRequest(t, s, "POST", "/api/campaigns/"+str(lateFailure, "id")+"/start", nil, alice, 400)
	if err := a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='scans'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("late insert failure left a partial scan")
	}
	if got := mustRequest(t, s, "GET", "/api/campaigns/"+str(lateFailure, "id"), nil, alice, 200); str(got, "status") != "draft" || len(array(got["scans"])) != 0 {
		t.Fatal("late failure left a campaign transition or link")
	}
	if _, err := a.DB.Exec(ctx, `DROP TRIGGER campaign_test_reject ON resources; DROP FUNCTION campaign_test_reject_scan(); DROP TABLE campaign_test_rejected_service`); err != nil {
		t.Fatal(err)
	}
	blueService := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Private blue", "url": "https://blue.internal", "environment": "staging", "team": "blue"}, blue, 200)
	mixed := campaignTestCreate(t, s, admin, []map[string]any{{"service_id": sid, "profile": "import-only"}, {"service_id": str(blueService, "id"), "profile": "import-only"}})
	mustRequest(t, s, "GET", "/api/campaigns/"+str(mixed, "id"), nil, alice, 404)
	mustRequest(t, s, "GET", "/api/campaigns/"+str(mixed, "id"), nil, blue, 404)
	mustRequest(t, s, "GET", "/api/campaigns/"+id, nil, blue, 404)
	if got := mustRequest(t, s, "GET", "/api/campaigns", nil, blue, 200); number(got, "total", -1) != 0 {
		t.Fatal("campaign aggregate leaked other team")
	}
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "campaign-read", "scopes": []string{"services:read", "scans:read"}, "expires_days": 7}, admin, 201)
	mustRequest(t, s, "GET", "/api/campaigns/"+id, nil, str(key, "token"), 200)
	mustRequest(t, s, "POST", "/api/campaigns/"+id+"/start", nil, str(key, "token"), 403)
	mustRequest(t, s, "GET", "/api/campaigns/"+id+"/compare?baseline="+id, nil, str(key, "token"), 403)
	missing := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "campaign-no-services", "scopes": []string{"scans:read", "scans:write"}, "expires_days": 7}, admin, 201)
	mustRequest(t, s, "GET", "/api/campaigns", nil, str(missing, "token"), 403)
	code, _, _ := request(t, s, "POST", "/api/campaigns/"+id+"/start", nil, alice, false)
	if code != 403 {
		t.Fatal("campaign start bypassed CSRF")
	}
	// Ownership changes must remove access even from the original campaign creator.
	if _, err := a.DB.Exec(ctx, `UPDATE resources SET owner_id=$2,data=data||'{"team":"blue"}'::jsonb WHERE id=$1 AND owner_id=$3`, sid, str(blueUser, "id"), str(aliceUser, "id")); err != nil {
		t.Fatal(err)
	}
	mustRequest(t, s, "GET", "/api/campaigns/"+id, nil, alice, 404)
	mustRequest(t, s, "POST", "/api/campaigns/"+id+"/start", nil, alice, 404)
	if got := mustRequest(t, s, "GET", "/api/campaigns", nil, alice, 200); number(got, "total", -1) != 0 {
		t.Fatal("creator retained stale parent access")
	}
}

func TestCampaignImmutableComparisons(t *testing.T) {
	a, s := testApp(t)
	ctx := context.Background()
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Compare fixture", "url": "https://compare.internal", "approved": true, "environment": "staging"}, admin, 200)
	sid := str(service, "id")
	mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "Compare scope", "service_id": sid, "allowed_hosts": []string{"compare.internal"}, "allowed_paths": []string{"/"}, "approved": true, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)}, admin, 200)
	var owner string
	if err := a.DB.QueryRow(ctx, `SELECT owner_id FROM resources WHERE id=$1`, sid).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	makeRun := func(profile string) map[string]any {
		return campaignTestStart(t, s, admin, campaignTestCreate(t, s, admin, []map[string]any{{"service_id": sid, "profile": profile}}))
	}
	complete := func(c map[string]any, policy string, findings []map[string]any) {
		id := campaignTestScanID(t, c)
		if _, _, err := a.ingestFindings(withScanObservationContext(ctx, policy, "fixture-engine-1"), User{ID: owner}, sid, findings, id); err != nil {
			t.Fatal(err)
		}
		if _, err := a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"status":"completed"}'::jsonb WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	base := makeRun("http-baseline")
	complete(base, "same-approved-condition", []map[string]any{{"title": "Persisting finding", "rule_id": "P", "source": "http-baseline", "severity": "low", "evidence": "private-evidence"}, {"title": "Previously observed", "rule_id": "M", "source": "http-baseline", "severity": "high"}})
	current := makeRun("http-baseline")
	comparePath := "/api/campaigns/" + str(current, "id") + "/compare?baseline=" + str(base, "id")
	if out := mustRequest(t, s, "GET", comparePath, nil, admin, 200); boolean(out, "comparable") || len(array(out["reasons"])) == 0 {
		t.Fatal("unfinished scan compared")
	}
	complete(current, "same-approved-condition", []map[string]any{{"title": "Persisting finding", "rule_id": "P", "source": "http-baseline", "severity": "high"}, {"title": "Added finding", "rule_id": "A", "source": "http-baseline", "severity": "medium"}})
	out := mustRequest(t, s, "GET", comparePath, nil, admin, 200)
	if !boolean(out, "comparable") || len(array(out["added"])) != 1 || len(array(out["persisting"])) != 1 || len(array(out["not_seen"])) != 1 || len(array(out["changed"])) != 1 {
		t.Fatalf("wrong comparison classifications: %#v", out)
	}
	missingID := str(object(array(out["not_seen"])[0]), "finding_id")
	finding := mustRequest(t, s, "GET", "/api/findings/"+missingID, nil, admin, 200)
	if str(finding, "status") != "candidate" {
		t.Fatal("absence changed lifecycle")
	}
	// Later editable fields and capped observation history cannot rewrite a scan.
	if _, err := a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"title":"later mutation","observations":[]}'::jsonb WHERE kind='findings'`); err != nil {
		t.Fatal(err)
	}
	after := mustRequest(t, s, "GET", comparePath, nil, admin, 200)
	if str(object(array(after["not_seen"])[0]), "title") != "Previously observed" {
		t.Fatal("comparison read mutable finding fields")
	}
	baseScanID := campaignTestScanID(t, base)
	var stored []byte
	if err := a.DB.QueryRow(ctx, `SELECT findings FROM scan_observations WHERE scan_id=$1`, baseScanID).Scan(&stored); err != nil || bytes.Contains(stored, []byte("private-evidence")) || bytes.Contains(stored, []byte(`"evidence"`)) {
		t.Fatal("snapshot leaked evidence")
	}
	if _, _, err := a.ingestFindings(withScanObservationContext(ctx, "same-approved-condition", "fixture-engine-1"), User{ID: owner}, sid, []map[string]any{{"title": "attempt overwrite", "rule_id": "X", "source": "http-baseline", "severity": "critical"}}, baseScanID); err == nil {
		t.Fatal("immutable snapshot overwritten")
	}
	var addedCount int
	if err := a.DB.QueryRow(ctx, `SELECT count(*) FROM resources WHERE kind='findings' AND data->>'rule_id'='X'`).Scan(&addedCount); err != nil || addedCount != 0 {
		t.Fatal("snapshot conflict did not roll back findings")
	}
	different := makeRun("http-baseline")
	complete(different, "policy-changed", nil)
	differentPath := "/api/campaigns/" + str(different, "id") + "/compare?baseline=" + str(base, "id")
	if result := mustRequest(t, s, "GET", differentPath, nil, admin, 200); boolean(result, "comparable") || len(array(result["not_seen"])) != 0 {
		t.Fatal("changed policy compared")
	}
	legacy := makeRun("http-baseline")
	if _, err := a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"status":"completed"}'::jsonb WHERE id=$1`, campaignTestScanID(t, legacy)); err != nil {
		t.Fatal(err)
	}
	if result := mustRequest(t, s, "GET", "/api/campaigns/"+str(legacy, "id")+"/compare?baseline="+str(base, "id"), nil, admin, 200); boolean(result, "comparable") {
		t.Fatal("pre-snapshot execution compared")
	}
	external := makeRun("import-only")
	mustRequest(t, s, "POST", "/api/imports", map[string]any{"scan_id": campaignTestScanID(t, external), "service_id": sid, "format": "generic", "results": []any{}}, admin, 200)
	if result := mustRequest(t, s, "GET", "/api/campaigns/"+str(external, "id")+"/compare?baseline="+str(external, "id"), nil, admin, 200); boolean(result, "comparable") {
		t.Fatal("unverified external execution compared")
	}
	if _, err := a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"status":"inconclusive"}'::jsonb WHERE id=$1`, campaignTestScanID(t, current)); err != nil {
		t.Fatal(err)
	}
	if result := mustRequest(t, s, "GET", comparePath, nil, admin, 200); boolean(result, "comparable") || len(array(result["not_seen"])) != 0 {
		t.Fatal("failed run with a saved snapshot produced absence conclusions")
	}
}

func TestCampaignRealWorkerApprovalAndEmptySnapshot(t *testing.T) {
	a, s := testApp(t)
	ctx := context.Background()
	admin := loginTest(t, s, "admin", "test-password-1234")
	var fixed atomic.Bool
	var requests atomic.Int32
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if fixed.Load() {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		}
		_, _ = io.WriteString(w, "synthetic campaign target")
	}))
	defer closeTarget()
	domainEnableWorker(t, a, "campaign-test-worker", "")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Bounded campaign target", "url": target, "environment": "staging", "approved": true}, admin, 200)
	sid := str(service, "id")
	u, _ := url.Parse(target)
	mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "Bounded scope", "service_id": sid, "allowed_hosts": []string{u.Host}, "allowed_paths": []string{"/"}, "approved": true, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339), "max_requests": 4, "timeout_seconds": 10, "max_rps": 2}, admin, 200)
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]any{"approval_enabled": true}, admin, 200)
	targets := []map[string]any{{"service_id": sid, "profile": "http-baseline"}}
	base := campaignTestStart(t, s, admin, campaignTestCreate(t, s, admin, targets))
	if str(base, "status") != "pending_approval" {
		t.Fatal("campaign bypassed optional approval")
	}
	if id, _ := a.claimScan(ctx, "campaign-test-worker"); id != "" {
		t.Fatal("campaign scan claimed before approval")
	}
	scanID := campaignTestScanID(t, base)
	mustRequest(t, s, "POST", "/api/scans/"+scanID+"/approve", map[string]any{"decision": "approved", "reason": "합성 대상 승인"}, admin, 200)
	if id, err := a.claimScan(ctx, "campaign-test-worker"); err != nil || id != scanID {
		t.Fatalf("approved campaign scan not claimable: %s %v", id, err)
	}
	a.executeScan(ctx, "campaign-test-worker", scanID)
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]any{"approval_enabled": false}, admin, 200)
	fixed.Store(true)
	current := campaignTestStart(t, s, admin, campaignTestCreate(t, s, admin, targets))
	scanID = campaignTestScanID(t, current)
	if id, err := a.claimScan(ctx, "campaign-test-worker"); err != nil || id != scanID {
		t.Fatalf("second campaign not claimable: %s %v", id, err)
	}
	a.executeScan(ctx, "campaign-test-worker", scanID)
	result := mustRequest(t, s, "GET", "/api/campaigns/"+str(current, "id")+"/compare?baseline="+str(base, "id"), nil, admin, 200)
	if !boolean(result, "comparable") || len(array(result["not_seen"])) < 1 || requests.Load() != 2 {
		t.Fatalf("actual worker comparison failed: %v, requests=%d", result, requests.Load())
	}
	for _, item := range array(result["not_seen"]) {
		finding := mustRequest(t, s, "GET", "/api/findings/"+str(object(item), "finding_id"), nil, admin, 200)
		if str(finding, "status") == "resolved" {
			t.Fatal("campaign comparison auto-resolved a finding")
		}
	}
	var trusted bool
	if err := a.DB.QueryRow(ctx, `SELECT trusted FROM scan_observations WHERE scan_id=$1`, scanID).Scan(&trusted); err != nil || !trusted {
		t.Fatalf("actual bounded worker snapshot not trusted: %v", err)
	}
	var observed int
	if err := a.DB.QueryRow(ctx, `SELECT jsonb_array_length(findings) FROM scan_observations WHERE scan_id=$1`, scanID).Scan(&observed); err != nil || observed != 0 {
		t.Fatalf("successful empty run did not save an explicit empty snapshot: %d %v", observed, err)
	}
}
