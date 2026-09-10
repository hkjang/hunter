package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestAggregateAPIsRespectEachKeyScope(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Visible service", "environment": "staging"}, admin, 200)
	mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "RESTRICTED-FINDING-TITLE", "service_id": str(service, "id"), "severity": "critical", "cve": "CVE-RESTRICTED"}, admin, 200)
	mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": str(service, "id"), "profile": "import-only"}, admin, 201)
	serviceKey := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "services-only", "scopes": []string{"services:read"}, "expires_days": 7}, admin, 201)
	status, b, _ := request(t, s, "GET", "/api/graph", nil, str(serviceKey, "token"), true)
	if status != 200 || bytes.Contains(b, []byte("RESTRICTED")) {
		t.Fatalf("graph leaked unscoped finding %d %s", status, b)
	}
	findingKey := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "findings-only", "scopes": []string{"findings:read"}, "expires_days": 7}, admin, 201)
	dashboard := mustRequest(t, s, "GET", "/api/dashboard", nil, str(findingKey, "token"), 200)
	if number(dashboard, "services", 0) != 0 || number(dashboard, "scans", 0) != 0 || len(array(dashboard["recent_scans"])) != 0 || len(array(dashboard["restricted_datasets"])) != 2 {
		t.Fatalf("dashboard exposed other datasets %v", dashboard)
	}
}

func TestStaleMutationCannotOverwriteDispatchState(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	v := domainResource{ID: newID(), Kind: "remediations", OwnerID: "owner", Data: map[string]any{"name": "Draft", "dispatch_state": "draft"}}
	if err := a.persistResource(ctx, &v); err != nil {
		t.Fatal(err)
	}
	stale := v
	stale.Data = cloneMap(v.Data)
	if _, err := a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"dispatch_state":"sent","external_id":"ticket-1"}'::jsonb,updated_at=now() WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	stale.Data["name"] = "Edited from stale browser"
	if err := a.persistResource(ctx, &stale); !errors.Is(err, errResourceConflict) {
		t.Fatalf("stale write accepted: %v", err)
	}
	saved, err := a.resource(ctx, "remediations", v.ID)
	if err != nil || str(saved.Data, "dispatch_state") != "sent" {
		t.Fatal("dispatch state overwritten")
	}
}

func TestServiceSafetyChangesRevokeApproval(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	for _, field := range []string{"environment", "network", "team", "targets"} {
		service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Scope reset " + field, "environment": "production", "url": "https://target.internal", "approved": true}, admin, 200)
		change := map[string]any{"environment": "staging", "network": "other-network", "team": "other-team", "targets": []any{map[string]any{"type": "api", "value": "/new"}}}
		updated := mustRequest(t, s, "PUT", "/api/services/"+str(service, "id"), map[string]any{field: change[field]}, admin, 200)
		if boolean(updated, "approved") {
			t.Fatalf("approval retained after %s changed", field)
		}
	}
}

func TestQueuedScanRechecksRevokedOriginatingKey(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	domainEnableWorker(t, a, "key-worker", "")
	var requests atomic.Int32
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); io.WriteString(w, "should not execute") }))
	defer closeTarget()
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Revoked key target", "environment": "staging", "url": target, "approved": true}, admin, 200)
	u, _ := url.Parse(target)
	mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "Key scope", "service_id": str(service, "id"), "allowed_hosts": []string{u.Host}, "allowed_paths": []string{"/"}, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339), "approved": true}, admin, 200)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "scan-origin", "scopes": []string{"scans:write"}, "expires_days": 7}, admin, 201)
	scan := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": str(service, "id")}, str(key, "token"), 201)
	mustRequest(t, s, "DELETE", "/api/keys/"+str(object(key["key"]), "id"), nil, admin, 200)
	id, err := a.claimScan(context.Background(), "key-worker")
	if err != nil || id != str(scan, "id") {
		t.Fatal("claim failed")
	}
	a.executeScan(context.Background(), "key-worker", id)
	saved := mustRequest(t, s, "GET", "/api/scans/"+id, nil, admin, 200)
	if str(saved, "status") != "inconclusive" || requests.Load() != 0 {
		t.Fatalf("revoked key executed target %v %d", saved, requests.Load())
	}
}

func TestCancelledRetestCannotResolveFinding(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	fid, scanID := newID(), newID()
	finding := domainResource{ID: fid, Kind: "findings", OwnerID: "owner", Data: map[string]any{"title": "Header missing", "source": "http-baseline", "status": "candidate", "rule_id": "x-content-type-options", "location": "/"}}
	if err := a.persistResource(ctx, &finding); err != nil {
		t.Fatal(err)
	}
	scan := domainResource{ID: scanID, Kind: "scans", OwnerID: "owner", Data: map[string]any{"finding_id": fid, "status": "cancelled"}}
	if err := a.persistResource(ctx, &scan); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(ctx, `INSERT INTO scan_jobs(scan_id,status,worker_id,lease_until) VALUES($1,'cancelled','worker',now()+interval '1 minute')`, scanID); err != nil {
		t.Fatal(err)
	}
	result := map[string]any{"path": "/", "tested_controls": map[string]bool{"x-content-type-options": true}, "http_status": 200}
	if err := a.resolveBaselineFinding(ctx, fid, scanID, "worker", result); err == nil {
		t.Fatal("cancelled retest resolved a finding")
	}
	saved, err := a.resource(ctx, "findings", fid)
	if err != nil || str(saved.Data, "status") != "candidate" {
		t.Fatal("cancelled finding state changed")
	}
}

func TestPolicySnapshotDetectsScopeAndPolicyChanges(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Snapshot target", "url": "https://snapshot.internal", "environment": "staging", "approved": true}, admin, 200)
	scope := mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "Snapshot scope", "service_id": str(service, "id"), "allowed_hosts": []string{"snapshot.internal"}, "allowed_paths": []string{"/"}, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339), "approved": true}, admin, 200)
	input := map[string]any{"service_id": str(service, "id"), "scope_id": str(scope, "id")}
	_, _, before, err := a.scanPolicy(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	_, _, same, err := a.scanPolicy(context.Background(), input)
	if err != nil || before.Fingerprint != same.Fingerprint {
		t.Fatal("unchanged policy fingerprint unstable")
	}
	mustRequest(t, s, "PUT", "/api/scopes/"+str(scope, "id"), map[string]any{"allowed_cidrs": []string{"10.1.0.0/16"}}, admin, 200)
	_, _, after, err := a.scanPolicy(context.Background(), input)
	if err != nil || before.Fingerprint == after.Fingerprint {
		t.Fatal("CIDR restriction change not detected")
	}
	mustRequest(t, s, "POST", "/api/policies", map[string]any{"name": "New restriction", "max_requests": 1, "blocked_paths": []string{"/own"}}, admin, 200)
	_, _, newPolicy, err := a.scanPolicy(context.Background(), input)
	if err != nil || after.Fingerprint == newPolicy.Fingerprint {
		t.Fatal("new policy not detected")
	}
}
