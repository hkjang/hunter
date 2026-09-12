package app

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestFindingEvidenceRejectsStructuredPlaintext(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Validation service", "environment": "staging"}, admin, 200)
	for _, evidence := range []any{map[string]any{"password": "structured-private-value"}, []any{"structured-private-value"}, 42, true} {
		status, _, _ := request(t, s, "POST", "/api/findings", map[string]any{"title": "Invalid evidence", "service_id": str(service, "id"), "severity": "high", "evidence": evidence}, admin, true)
		if status != 400 {
			t.Errorf("structured evidence accepted with HTTP %d", status)
		}
	}
	var stored int
	if err := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM resources WHERE kind='findings' AND data::text LIKE '%structured-private-value%'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Error("structured evidence persisted in plaintext")
	}
	finding := mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "Valid evidence", "service_id": str(service, "id"), "severity": "high", "evidence": "normal evidence"}, admin, 200)
	status, _, _ := request(t, s, "PUT", "/api/findings/"+str(finding, "id"), map[string]any{"evidence": map[string]any{"password": "structured-private-value"}}, admin, true)
	if status != 400 {
		t.Errorf("structured evidence update accepted with HTTP %d", status)
	}
	var raw []byte
	if err := a.DB.QueryRow(context.Background(), `SELECT data FROM resources WHERE id=$1`, str(finding, "id")).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("structured-private-value")) || bytes.Contains(raw, []byte("normal evidence")) {
		t.Error("evidence lost its encrypted storage boundary")
	}
}

func TestFindingLegacyEvidenceIsHiddenAndRepairedOnMutation(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Legacy evidence", "environment": "staging"}, admin, 200)
	for _, bulk := range []bool{false, true} {
		finding := bulkTestFinding(t, s, admin, str(service, "id"), fmt.Sprintf("Legacy %v", bulk))
		if _, err := a.DB.Exec(context.Background(), `UPDATE resources SET data=(data-'evidence_encrypted')||'{"evidence":{"password":"legacy-credential-value","context":"preserved context"}}'::jsonb WHERE id=$1`, str(finding, "id")); err != nil {
			t.Fatal(err)
		}
		status, body, _ := request(t, s, "GET", "/api/findings/"+str(finding, "id"), nil, admin, true)
		if status != 200 || bytes.Contains(body, []byte("legacy-credential-value")) || bytes.Contains(body, []byte("preserved context")) {
			t.Fatal("legacy malformed evidence exposed on read")
		}
		if bulk {
			mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(finding), "patch": map[string]any{"assignee": "Repaired"}}, admin, 200)
		} else {
			mustRequest(t, s, "PUT", "/api/findings/"+str(finding, "id"), map[string]any{"assignee": "Repaired"}, admin, 200)
		}
		var raw []byte
		if err := a.DB.QueryRow(context.Background(), `SELECT data FROM resources WHERE id=$1`, str(finding, "id")).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("legacy-credential-value")) || bytes.Contains(raw, []byte("preserved context")) {
			t.Fatal("legacy structured evidence was not encrypted on edit")
		}
		got := mustRequest(t, s, "GET", "/api/findings/"+str(finding, "id"), nil, admin, 200)
		if !strings.Contains(str(got, "evidence"), "preserved context") || strings.Contains(str(got, "evidence"), "legacy-credential-value") {
			t.Fatal("repaired evidence did not preserve safe context and redact credentials")
		}
	}
}

func TestFindingLegacyEvidenceRepairBeforeStartup(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	_, err := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data,updated_at) SELECT 'legacy-'||n,'findings','system',jsonb_build_object('title','Legacy','status','candidate','evidence',CASE n%4 WHEN 0 THEN jsonb_build_object('password','legacy-private','context','safe context') WHEN 1 THEN '["safe array"]'::jsonb WHEN 2 THEN '42'::jsonb ELSE 'true'::jsonb END),now()-interval '1 day' FROM generate_series(1,105) n`)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := New(ctx, "repair-test", fstest.MapFS{"index.html": {Data: []byte("test")}})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	var remaining, repaired, batches int
	if err = a.DB.QueryRow(ctx, `SELECT count(*) FILTER(WHERE jsonb_typeof(data->'evidence')<>'string'),count(*) FILTER(WHERE data->>'evidence_encrypted'='true' AND updated_at>now()-interval '1 hour') FROM resources WHERE id LIKE 'legacy-%'`).Scan(&remaining, &repaired); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 || repaired != 105 {
		t.Fatalf("startup did not finish all repairs: remaining=%d repaired=%d", remaining, repaired)
	}
	if err = a.DB.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='finding.evidence_repaired'`).Scan(&batches); err != nil {
		t.Fatal(err)
	}
	if batches != 3 {
		t.Fatalf("repair was not committed in 50-row batches: %d", batches)
	}
	var raw []byte
	if err = a.DB.QueryRow(ctx, `SELECT jsonb_agg(data) FROM resources WHERE id LIKE 'legacy-%'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("legacy-private")) || bytes.Contains(raw, []byte("safe context")) {
		t.Fatal("repair retained plaintext evidence")
	}
	if err = a.repairLegacyFindingEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	var again int
	if err = a.DB.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='finding.evidence_repaired'`).Scan(&again); err != nil || again != batches {
		t.Fatal("repair was not idempotent")
	}
}

func TestFindingLegacyEvidenceRepairDoesNotIgnoreLockedRows(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	_, err := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES('locked-legacy','findings','system','{"evidence":{"password":"private-before-repair"}}')`)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM resources WHERE id='locked-legacy' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if err = a.repairLegacyFindingEvidence(short); err == nil {
		t.Fatal("repair reported complete while a plaintext row remained locked")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = a.repairLegacyFindingEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err = a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resources WHERE `+legacyEvidencePredicate+`)`).Scan(&exists); err != nil || exists {
		t.Fatal("unlocked row was not repaired")
	}
}

func bulkTestFinding(t *testing.T, s *httptest.Server, credential, sid, title string) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": title, "service_id": sid, "severity": "high", "evidence": "original private evidence", "assignee": "Before"}, credential, 200)
}
func bulkTestItems(findings ...map[string]any) []any {
	out := []any{}
	for _, finding := range findings {
		out = append(out, map[string]any{"id": finding["id"], "updated_at": finding["updated_at"]})
	}
	return out
}

func TestFindingBulkAtomicChangesAndAudit(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Bulk service", "environment": "staging"}, admin, 200)
	first := bulkTestFinding(t, s, admin, str(service, "id"), "First")
	second := bulkTestFinding(t, s, admin, str(service, "id"), "Second")
	var ciphertext string
	if err := a.DB.QueryRow(context.Background(), `SELECT data->>'evidence' FROM resources WHERE id=$1`, str(first, "id")).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	due := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	out := mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(first, second), "patch": map[string]any{"assignee": " Next owner ", "due_date": due, "status": "in_progress"}}, admin, 200)
	if number(out, "updated", 0) != 2 || len(array(out["items"])) != 2 || str(out, "operation_id") == "" {
		t.Fatalf("bulk response incomplete: %v", out)
	}
	for _, input := range []map[string]any{first, second} {
		got := mustRequest(t, s, "GET", "/api/findings/"+str(input, "id"), nil, admin, 200)
		if str(got, "assignee") != "Next owner" || str(got, "status") != "in_progress" || str(got, "due_date") != due || str(got, "source") != "manual" || str(got, "fingerprint") != str(input, "fingerprint") {
			t.Fatalf("bulk changed incorrect fields: %v", got)
		}
		activity := mustRequest(t, s, "GET", "/api/findings/"+str(input, "id")+"/activity", nil, admin, 200)
		found := false
		for _, entry := range array(activity["items"]) {
			item := object(entry)
			if str(item, "action") == "finding.bulk_update" {
				fields := object(object(item["details"])["fields"])
				if str(object(fields["assignee"]), "before") != "Before" || str(object(fields["assignee"]), "after") != "Next owner" {
					t.Fatalf("field diff missing: %v", fields)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("bulk change absent from activity")
		}
	}
	var stored, audit []byte
	if err := a.DB.QueryRow(context.Background(), `SELECT data FROM resources WHERE id=$1`, str(first, "id")).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stored, []byte(ciphertext)) || bytes.Contains(stored, []byte("original private evidence")) {
		t.Fatal("bulk update changed encrypted evidence")
	}
	if err := a.DB.QueryRow(context.Background(), `SELECT jsonb_agg(detail) FROM audit_logs WHERE action='finding.bulk_update'`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(ciphertext)) || bytes.Contains(audit, []byte("original private evidence")) {
		t.Fatal("audit retained evidence")
	}
	current := object(array(out["items"])[0])
	nothing := mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(current), "patch": map[string]any{"assignee": "Next owner"}}, admin, 200)
	if number(nothing, "updated", -1) != 0 {
		t.Fatal("no-op claimed a change")
	}
	cleared := mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(current), "patch": map[string]any{"due_date": nil, "assignee": ""}}, admin, 200)
	if item := object(array(cleared["items"])[0]); item["due_date"] != nil || str(item, "assignee") != "" {
		t.Fatal("explicit clearing failed")
	}
}

func TestFindingBulkRejectsInvalidScopesRevisionsAndPartialChanges(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	user := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "bulk-analyst", "name": "Analyst", "role": "analyst", "password": "test-password-1234"}, admin, 201)
	analyst := loginTest(t, s, "bulk-analyst", "test-password-1234")
	ownedService := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Owned", "environment": "staging"}, analyst, 200)
	otherService := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Other", "environment": "staging"}, admin, 200)
	owned := bulkTestFinding(t, s, analyst, str(ownedService, "id"), "Owned")
	other := bulkTestFinding(t, s, admin, str(otherService, "id"), "Other")
	valid := map[string]any{"items": bulkTestItems(owned), "patch": map[string]any{"assignee": "After"}}
	for _, patch := range []map[string]any{{}, {"title": "Forbidden"}, {"evidence": "secret"}, {"owner_id": str(user, "id")}, {"service_id": str(otherService, "id")}, {"verification": map[string]any{}}, {"status": "resolved"}, {"status": "accepted"}, {"status": "false_positive"}, {"assignee": nil}, {"assignee": []any{"bad"}}, {"assignee": strings.Repeat("한", 67)}, {"due_date": 42}, {"due_date": "2026-09-13"}} {
		mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(owned), "patch": patch}, analyst, 400)
	}
	for _, items := range []any{[]any{}, bulkTestItems(owned, owned), []any{map[string]any{"id": owned["id"]}}, []any{map[string]any{"id": owned["id"], "updated_at": "bad"}}} {
		mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": items, "patch": valid["patch"]}, analyst, 400)
	}
	tooMany := []any{}
	for i := 0; i < 101; i++ {
		tooMany = append(tooMany, map[string]any{"id": fmt.Sprint(i), "updated_at": owned["updated_at"]})
	}
	mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": tooMany, "patch": valid["patch"]}, analyst, 400)
	mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(owned, other), "patch": valid["patch"]}, analyst, 404)
	missing := map[string]any{"id": newID(), "updated_at": owned["updated_at"]}
	mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(owned, missing), "patch": valid["patch"]}, admin, 404)
	stale := map[string]any{"id": other["id"], "updated_at": time.Now().Add(-time.Hour).Format(time.RFC3339Nano)}
	mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(owned, stale), "patch": valid["patch"]}, admin, 409)
	for _, scopes := range [][]string{{"findings:read"}, {"findings:write"}} {
		key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "bulk-key", "scopes": scopes, "expires_days": 1}, admin, 201)
		mustRequest(t, s, "POST", "/api/findings/bulk", valid, str(key, "token"), 403)
	}
	var count int
	if err := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE action='finding.bulk_update'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("rejected batch left an audit change")
	}
	unchanged := mustRequest(t, s, "GET", "/api/findings/"+str(owned, "id"), nil, analyst, 200)
	if str(unchanged, "assignee") != "Before" || str(unchanged, "updated_at") != str(owned, "updated_at") {
		t.Fatal("rejected batch partially changed a valid row")
	}
	accepted := mustRequest(t, s, "PUT", "/api/findings/"+str(owned, "id"), map[string]any{"status": "accepted", "decision_reason": "Reviewed", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)}, analyst, 200)
	mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(accepted), "patch": map[string]any{"status": "candidate"}}, admin, 409)
	mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(accepted), "patch": map[string]any{"assignee": "Reviewed owner"}}, admin, 200)
}

func TestFindingBulkAuditFailureRollsBackWholeTransaction(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Rollback", "environment": "staging"}, admin, 200)
	first := bulkTestFinding(t, s, admin, str(service, "id"), "First")
	second := bulkTestFinding(t, s, admin, str(service, "id"), "Second")
	_, err := a.DB.Exec(context.Background(), `CREATE FUNCTION reject_bulk_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='finding.bulk_update' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_bulk_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_bulk_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	mustRequest(t, s, "POST", "/api/findings/bulk", map[string]any{"items": bulkTestItems(first, second), "patch": map[string]any{"assignee": "Should roll back"}}, admin, 500)
	for _, f := range []map[string]any{first, second} {
		got := mustRequest(t, s, "GET", "/api/findings/"+str(f, "id"), nil, admin, 200)
		if str(got, "assignee") != "Before" || str(got, "updated_at") != str(f, "updated_at") {
			t.Fatal("audit failure retained a partial row update")
		}
	}
}

func TestFindingBulkRechecksKeyAfterLockWait(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Lock wait", "environment": "staging"}, admin, 200)
	finding := bulkTestFinding(t, s, admin, str(service, "id"), "Locked finding")
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "bulk-current-key", "scopes": []string{"findings:read", "findings:write"}, "expires_days": 1}, admin, 201)
	var uid string
	if err := a.DB.QueryRow(context.Background(), `SELECT id FROM users WHERE username='admin'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	initial := User{ID: uid, Role: "admin", KeyID: str(object(key["key"]), "id"), Scopes: []string{"findings:read", "findings:write"}}
	tx, err := a.DB.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var blocker int
	if err = tx.QueryRow(context.Background(), `SELECT pg_backend_pid() FROM resources WHERE id=$1 FOR UPDATE`, str(finding, "id")).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, e := a.applyFindingBulk(context.Background(), initial, findingBulkRequest{Items: []findingBulkItem{{ID: str(finding, "id"), UpdatedAt: str(finding, "updated_at")}}, Patch: map[string]any{"assignee": "Not allowed"}})
		done <- e
	}()
	deadline := time.Now().Add(3 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		if err = a.DB.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("bulk request did not wait for the selected row")
	}
	if _, err = a.DB.Exec(context.Background(), `UPDATE api_keys SET revoked_at=now() WHERE id=$1`, initial.KeyID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if problem, ok := err.(findingBulkError); !ok || problem.Status != 403 {
			t.Fatalf("revoked key committed after lock wait: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bulk request did not finish")
	}
	got := mustRequest(t, s, "GET", "/api/findings/"+str(finding, "id"), nil, admin, 200)
	if str(got, "assignee") != "Before" {
		t.Fatal("revoked key changed finding")
	}
}

func TestFindingBulkCurrentTeamAndRoleOverrideStalePrincipal(t *testing.T) {
	a, s := testApp(t)
	ctx := context.Background()
	admin := loginTest(t, s, "admin", "test-password-1234")
	created := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "bulk-lead", "name": "Lead", "role": "lead", "team": "red", "password": "test-password-1234"}, admin, 201)
	uid := str(created, "id")
	if uid == "" {
		if err := a.DB.QueryRow(ctx, `SELECT id FROM users WHERE username='bulk-lead'`).Scan(&uid); err != nil {
			t.Fatal(err)
		}
	}
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Current access", "environment": "staging", "team": "red"}, admin, 200)
	finding := bulkTestFinding(t, s, admin, str(service, "id"), "Access finding")
	initial := User{ID: uid, Role: "lead", Team: "red", Scopes: []string{"findings:read", "findings:write"}}
	in := findingBulkRequest{Items: []findingBulkItem{{ID: str(finding, "id"), UpdatedAt: str(finding, "updated_at")}}, Patch: map[string]any{"assignee": "Forbidden"}}
	for _, test := range []struct {
		sql    string
		args   []any
		status int
	}{
		{`UPDATE resources SET data=data||'{"team":"blue"}' WHERE id=$1`, []any{service["id"]}, 404},
		{`UPDATE users SET team='blue' WHERE id=$1`, []any{uid}, 404},
		{`UPDATE users SET role='viewer' WHERE id=$1`, []any{uid}, 403},
		{`UPDATE users SET disabled=true WHERE id=$1`, []any{uid}, 403},
	} {
		if _, err := a.DB.Exec(ctx, `UPDATE resources SET data=data||'{"team":"red"}' WHERE id=$1`, service["id"]); err != nil {
			t.Fatal(err)
		}
		if _, err := a.DB.Exec(ctx, `UPDATE users SET team='red',role='lead',disabled=false WHERE id=$1`, uid); err != nil {
			t.Fatal(err)
		}
		if _, err := a.DB.Exec(ctx, test.sql, test.args...); err != nil {
			t.Fatal(err)
		}
		_, err := a.applyFindingBulk(ctx, initial, in)
		problem, ok := err.(findingBulkError)
		if !ok || problem.Status != test.status {
			t.Fatalf("stale principal bypassed current access, expected %d got %v", test.status, err)
		}
	}
	got := mustRequest(t, s, "GET", "/api/findings/"+str(finding, "id"), nil, admin, 200)
	if str(got, "assignee") != "Before" {
		t.Fatal("stale principal changed finding")
	}
}

func TestResourceExpectedRevisionPreservesConcurrentBrowserEdits(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Original", "environment": "staging"}, admin, 200)
	id, revision := str(service, "id"), str(service, "updated_at")
	newer := mustRequest(t, s, "PUT", "/api/services/"+id, map[string]any{"name": "First editor", "expected_updated_at": revision}, admin, 200)
	status, _, _ := request(t, s, "PUT", "/api/services/"+id, map[string]any{"name": "Stale editor", "expected_updated_at": revision}, admin, true)
	if status != 409 {
		t.Errorf("stale browser revision returned HTTP %d, wanted 409", status)
	}
	current := mustRequest(t, s, "GET", "/api/services/"+id, nil, admin, 200)
	if str(current, "name") != "First editor" {
		t.Error("stale form overwrote a prior edit")
	}
	if _, exists := current["expected_updated_at"]; exists {
		t.Error("client revision became resource data")
	}
	mustRequest(t, s, "PUT", "/api/services/"+id, map[string]any{"name": "Latest editor", "expected_updated_at": newer["updated_at"]}, admin, 200)
	for _, bad := range []any{nil, 42, "", "not-a-date"} {
		status, _, _ := request(t, s, "PUT", "/api/services/"+id, map[string]any{"expected_updated_at": bad}, admin, true)
		if status != 400 {
			t.Errorf("invalid revision returned HTTP %d", status)
		}
	}
}
