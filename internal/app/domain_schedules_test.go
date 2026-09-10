package app

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func domainEnableWorker(t *testing.T, a *App, id, network string) {
	t.Helper()
	if err := a.registerWorker(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(context.Background(), `UPDATE resources SET data=data||jsonb_build_object('enabled',true,'network',$2::text) WHERE kind='workers' AND id=$1`, id, network); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleConcurrencyAndPendingDeduplication(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Scheduled import", "environment": "staging"}, admin, 200)
	now := time.Now().UTC()
	due := now.Add(-time.Minute).Format(time.RFC3339)
	schedule := mustRequest(t, s, "POST", "/api/schedules", map[string]any{"name": "5 minute import", "service_id": str(service, "id"), "profile": "import-only", "interval_minutes": 5, "next_run_at": due, "enabled": true}, admin, 200)
	scheduleID := str(schedule, "id")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.runSchedule(context.Background(), scheduleID, now); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var count int
	if err := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM resources WHERE kind='scans' AND data->>'schedule_id'=$1`, scheduleID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("concurrent scheduler generated %d scans: %v", count, err)
	}
	saved := mustRequest(t, s, "GET", "/api/schedules/"+scheduleID, nil, admin, 200)
	if str(saved, "last_result") != "scan_requested" {
		t.Fatalf("schedule failed %v", saved)
	}
	scanID := str(saved, "last_scan_id")
	mustRequest(t, s, "PUT", "/api/schedules/"+scheduleID, map[string]any{"next_run_at": now.Add(-time.Second).Format(time.RFC3339)}, admin, 200)
	if err := a.runSchedule(context.Background(), scheduleID, now); err != nil {
		t.Fatal(err)
	}
	saved = mustRequest(t, s, "GET", "/api/schedules/"+scheduleID, nil, admin, 200)
	if str(saved, "last_result") != "skipped_pending" {
		t.Fatal("pending schedule was duplicated")
	}
	mustRequest(t, s, "POST", "/api/scans/"+scanID+"/cancel", nil, admin, 200)
	next := now.Add(time.Minute)
	mustRequest(t, s, "PUT", "/api/schedules/"+scheduleID, map[string]any{"next_run_at": next.Add(-time.Second).Format(time.RFC3339)}, admin, 200)
	if err := a.runSchedule(context.Background(), scheduleID, next); err != nil {
		t.Fatal(err)
	}
	if err := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM resources WHERE kind='scans' AND data->>'schedule_id'=$1`, scheduleID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("next occurrence missing: %d %v", count, err)
	}
}

func TestScheduleRespectsRevokedAPIKey(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Key schedule", "environment": "staging"}, admin, 200)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "scheduler", "scopes": []string{"scans:read", "scans:write"}, "expires_days": 7}, admin, 201)
	schedule := mustRequest(t, s, "POST", "/api/schedules", map[string]any{"name": "API key reservation", "service_id": str(service, "id"), "profile": "import-only", "interval_minutes": 5, "next_run_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}, str(key, "token"), 200)
	if _, ok := schedule["credential_key_id"]; ok {
		t.Fatal("internal credential metadata exposed")
	}
	keyID := str(object(key["key"]), "id")
	mustRequest(t, s, "DELETE", "/api/keys/"+keyID, nil, admin, 200)
	if err := a.runSchedule(context.Background(), str(schedule, "id"), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	saved := mustRequest(t, s, "GET", "/api/schedules/"+str(schedule, "id"), nil, admin, 200)
	if str(saved, "last_result") != "blocked" || str(saved, "last_error") == "" {
		t.Fatalf("revoked key still ran: %v", saved)
	}
}

func TestWorkerRequiresEnrollmentAndExactNetwork(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	if err := a.registerWorker(context.Background(), "blue-worker"); err != nil {
		t.Fatal(err)
	}
	worker := mustRequest(t, s, "GET", "/api/workers/blue-worker", nil, admin, 200)
	if boolean(worker, "enabled") {
		t.Fatal("external worker auto-enrolled")
	}
	mustRequest(t, s, "PUT", "/api/workers/blue-worker", map[string]any{"enabled": true, "network": "blue", "name": "Blue worker"}, admin, 200)
	domainEnableWorker(t, a, "red-worker", "red")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Blue service", "environment": "staging", "url": "https://blue.internal", "network": "blue", "approved": true}, admin, 200)
	sid := str(service, "id")
	mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "Blue scope", "service_id": sid, "allowed_hosts": []string{"blue.internal"}, "allowed_paths": []string{"/"}, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339), "approved": true}, admin, 200)
	scan := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, admin, 201)
	if id, err := a.claimScan(context.Background(), "red-worker"); err != nil || id != "" {
		t.Fatalf("worker escaped network: %s %v", id, err)
	}
	mustRequest(t, s, "PUT", "/api/workers/blue-worker", map[string]any{"enabled": false}, admin, 200)
	if id, err := a.claimScan(context.Background(), "blue-worker"); err != nil || id != "" {
		t.Fatal("disabled worker claimed a job")
	}
	mustRequest(t, s, "PUT", "/api/workers/blue-worker", map[string]any{"enabled": true}, admin, 200)
	if err := a.registerWorker(context.Background(), "blue-worker"); err != nil {
		t.Fatal(err)
	}
	worker = mustRequest(t, s, "GET", "/api/workers/blue-worker", nil, admin, 200)
	if str(worker, "network") != "blue" || str(worker, "name") != "Blue worker" || !boolean(worker, "enabled") {
		t.Fatal("heartbeat overwrote administrator settings")
	}
	if id, err := a.claimScan(context.Background(), "blue-worker"); err != nil || id != str(scan, "id") {
		t.Fatalf("matching worker cannot claim: %s %v", id, err)
	}
}

func TestPolicyHistoryAndJSONExport(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	policy := mustRequest(t, s, "POST", "/api/policies", map[string]any{"name": "Read policy", "max_requests": 10}, admin, 200)
	mustRequest(t, s, "PUT", "/api/policies/"+str(policy, "id"), map[string]any{"max_requests": 5}, admin, 200)
	status, b, _ := request(t, s, "GET", "/api/policies/"+str(policy, "id")+"/history", nil, admin, true)
	var versions []map[string]any
	if json.Unmarshal(b, &versions) != nil || status != 200 || len(versions) != 2 {
		t.Fatalf("policy history %d %s", status, b)
	}
	export := mustRequest(t, s, "GET", "/api/policies/export", nil, admin, 200)
	if str(export, "schema_version") != "1" || len(array(export["policies"])) != 1 {
		t.Fatal("policy export failed")
	}
}
