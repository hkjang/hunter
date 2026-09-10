package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeScopeEnforcement(t *testing.T) {
	u, _ := url.Parse("https://service.internal/api")
	p := probePolicy{Target: u, Hosts: []string{"service.internal"}, Paths: []string{"/api"}, BlockedPaths: []string{"/api/delete"}, ExpiresAt: time.Now().Add(time.Hour)}
	for _, test := range []struct {
		url     string
		allowed bool
	}{{"https://service.internal/api", true}, {"https://service.internal/api/items", true}, {"https://service.internal/api2", false}, {"https://other.internal/api", false}, {"http://service.internal/api", false}, {"https://service.internal/api/delete/42", false}, {"https://service.internal/api/%2e%2e/admin", false}, {"https://service.internal/api/%252e%252e/admin", false}, {"https://service.internal/api%5cadmin", false}, {"https://service.internal:8443/api", false}} {
		target, _ := url.Parse(test.url)
		if got := p.validateURL(target) == nil; got != test.allowed {
			t.Errorf("scope %s allowed=%v want=%v", test.url, got, test.allowed)
		}
	}
	for _, raw := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1"} {
		if validateProbeIP(netip.MustParseAddr(raw), nil) == nil {
			t.Errorf("dangerous IP accepted: %s", raw)
		}
	}
	if validateProbeIP(netip.MustParseAddr("10.1.2.3"), []string{"10.1.0.0/16"}) != nil {
		t.Fatal("approved private network rejected")
	}
	if validateProbeIP(netip.MustParseAddr("10.2.2.3"), []string{"10.1.0.0/16"}) == nil {
		t.Fatal("CIDR escape accepted")
	}
	p.ExpiresAt = time.Now().Add(-time.Second)
	if p.validateURL(u) == nil {
		t.Fatal("expired scope accepted")
	}
}

func TestScannerNormalizationAndSecretExclusion(t *testing.T) {
	fixtures := []struct {
		format, body string
		count        int
	}{
		{"trivy", `{"Results":[{"Target":"image","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-1","PkgName":"lib","InstalledVersion":"1","FixedVersion":"2","Severity":"HIGH"}],"Secrets":[{"RuleID":"api","Title":"API key","Severity":"HIGH","Match":"raw-secret-value"}]}]}`, 2},
		{"nuclei", `[{"template-id":"missing-header","matched-at":"https://svc/api?token=secret","info":{"name":"Header","severity":"low"},"request":"Authorization: Bearer raw-secret-value"}]`, 1},
		{"zap", `{"site":[{"alerts":[{"name":"Header","riskcode":"2","pluginid":"1","instances":[{"uri":"https://svc/","method":"GET","param":"x"}]}]}]}`, 1},
		{"sarif", `{"runs":[{"tool":{"driver":{"name":"Semgrep"}},"results":[{"ruleId":"RULE","level":"error","message":{"text":"unsafe"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.go"},"region":{"startLine":10}}}]}]}]}`, 1},
		{"gitleaks", `[{"RuleID":"api","Description":"Secret","File":"app.env","StartLine":1,"Secret":"raw-secret-value","Match":"raw-secret-value"}]`, 1},
		{"generic", `[{"title":"Finding","severity":"critical","evidence":"Authorization: Bearer raw-secret-value","status":"resolved","verification":{"result":"pass"}}]`, 1},
	}
	for _, f := range fixtures {
		t.Run(f.format, func(t *testing.T) {
			var raw any
			if json.Unmarshal([]byte(f.body), &raw) != nil {
				t.Fatal("fixture")
			}
			out, err := normalizeImport(f.format, raw)
			if err != nil || len(out) != f.count {
				t.Fatalf("normalize %d %v", len(out), err)
			}
			b, _ := json.Marshal(out)
			if bytes.Contains(b, []byte("raw-secret-value")) || bytes.Contains(b, []byte(`"status":"resolved"`)) {
				t.Fatalf("unsafe result: %s", b)
			}
		})
	}
	if _, err := normalizeImport("trivy", map[string]any{}); err == nil {
		t.Fatal("invalid scanner result reported successful")
	}
	for _, q := range []string{"DELETE FROM assets", "SELECT * FROM assets; DROP TABLE assets", "SELECT pg_read_file('/etc/passwd')", "SELECT * FROM assets -- comment"} {
		if validateReadQuery(q) == nil {
			t.Errorf("unsafe SQL accepted %s", q)
		}
	}
	if validateReadQuery("SELECT name, url FROM service_catalog") != nil {
		t.Fatal("normal read query rejected")
	}
	if !containsNestedSecret(map[string]any{"headers": map[string]any{"Authorization": "Bearer secret"}}) {
		t.Fatal("nested secret allowed")
	}
}

func TestDomainOwnershipEncryptionAndImports(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	for _, input := range []map[string]any{{"username": "alice", "team": "red", "role": "analyst"}, {"username": "lead-red", "team": "red", "role": "lead"}, {"username": "lead-blue", "team": "blue", "role": "lead"}} {
		input["name"] = input["username"]
		input["password"] = "test-password-1234"
		mustRequest(t, s, "POST", "/api/users", input, admin, 201)
	}
	alice := loginTest(t, s, "alice", "test-password-1234")
	red := loginTest(t, s, "lead-red", "test-password-1234")
	blue := loginTest(t, s, "lead-blue", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Owned", "url": "https://owned.internal", "environment": "staging", "team": "red"}, alice, 200)
	sid := str(service, "id")
	mustRequest(t, s, "GET", "/api/services/"+sid, nil, red, 200)
	mustRequest(t, s, "GET", "/api/services/"+sid, nil, blue, 404)
	status, b, _ := request(t, s, "GET", "/api/services", nil, blue, true)
	if status != 200 || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("cross-team list leaked: %d %s", status, b)
	}
	status, b, _ = request(t, s, "GET", "/api/services", nil, red, true)
	if status != 200 || !bytes.Contains(b, []byte(sid)) {
		t.Fatalf("own team missing: %d %s", status, b)
	}
	mustRequest(t, s, "PUT", "/api/services/"+sid, map[string]any{"approved": true}, alice, 400)
	f := mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "Manual finding", "service_id": sid, "severity": "high", "evidence": "private-evidence-text\nAuthorization: Bearer sensitive-token", "source": "http-baseline", "status": "candidate"}, alice, 200)
	if str(f, "source") != "manual" {
		t.Fatal("user forged scanner provenance")
	}
	if !strings.Contains(str(f, "evidence"), "private-evidence-text") || strings.Contains(str(f, "evidence"), "sensitive-token") {
		t.Fatal("evidence masked incorrectly")
	}
	var raw []byte
	if err := a.DB.QueryRow(context.Background(), `SELECT data FROM resources WHERE id=$1`, str(f, "id")).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private-evidence-text")) || bytes.Contains(raw, []byte("sensitive-token")) {
		t.Fatal("plaintext evidence stored")
	}
	mustRequest(t, s, "PUT", "/api/findings/"+str(f, "id"), map[string]any{"status": "resolved"}, alice, 400)
	mustRequest(t, s, "GET", "/api/findings/"+str(f, "id"), nil, blue, 404)
	payload := map[string]any{"format": "generic", "service_id": sid, "results": []any{map[string]any{"title": "Imported", "severity": "high", "rule_id": "RULE", "location": "/api", "status": "resolved", "evidence": "scanner-evidence"}}}
	first := mustRequest(t, s, "POST", "/api/imports", payload, alice, 200)
	second := mustRequest(t, s, "POST", "/api/imports", payload, alice, 200)
	if number(first, "created", 0) != 1 || number(second, "updated", 0) != 1 {
		t.Fatalf("dedup failed %v %v", first, second)
	}
	var imported map[string]any
	if err := a.DB.QueryRow(context.Background(), `SELECT data FROM resources WHERE kind='findings' AND data->>'rule_id'='RULE'`).Scan(&imported); err != nil {
		t.Fatal(err)
	}
	if str(imported, "status") != "candidate" || len(array(imported["observations"])) != 2 {
		t.Fatal("import lifecycle corrupt")
	}
	if str(imported, "evidence") == "scanner-evidence" {
		t.Fatal("import evidence unencrypted")
	}
}

func domainTarget(t *testing.T, h http.Handler) (string, func()) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	host := ""
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() {
			host = ip.String()
			break
		}
	}
	if host == "" {
		t.Skip("nonloopback interface required for real bounded worker test")
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go server.Serve(ln)
	return "http://" + net.JoinHostPort(host, strings.Split(ln.Addr().String(), ":")[len(strings.Split(ln.Addr().String(), ":"))-1]), func() { server.Close() }
}

func TestRealWorkerRetestAndWorkflow(t *testing.T) {
	a, s := testApp(t)
	domainEnableWorker(t, a, "test-worker", "")
	admin := loginTest(t, s, "admin", "test-password-1234")
	var fixed atomic.Bool
	var requests atomic.Int32
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if fixed.Load() {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		}
		io.WriteString(w, "synthetic page")
	}))
	defer closeTarget()
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Target", "url": target, "environment": "staging", "approved": true}, admin, 200)
	sid := str(service, "id")
	mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid, "profile": "http-baseline"}, admin, 400)
	u, _ := url.Parse(target)
	scope := mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "Approved scope", "service_id": sid, "allowed_hosts": []string{u.Host}, "allowed_paths": []string{"/"}, "approved": true, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339), "max_requests": 4, "timeout_seconds": 10, "max_rps": 2}, admin, 200)
	first := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid, "profile": "http-baseline", "scope_id": str(scope, "id")}, admin, 201)
	id, err := a.claimScan(context.Background(), "test-worker")
	if err != nil || id != str(first, "id") {
		t.Fatalf("claim failed %s %v", id, err)
	}
	a.executeScan(context.Background(), "test-worker", id)
	scan := mustRequest(t, s, "GET", "/api/scans/"+id, nil, admin, 200)
	if str(scan, "status") != "completed" || requests.Load() != 1 {
		t.Fatalf("real worker failed: %v requests=%d", scan, requests.Load())
	}
	var fid string
	if err = a.DB.QueryRow(context.Background(), `SELECT id FROM resources WHERE kind='findings' AND data->>'service_id'=$1 AND data->>'rule_id'='x-content-type-options'`, sid).Scan(&fid); err != nil {
		t.Fatal(err)
	}
	fixed.Store(true)
	retest := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid, "profile": "http-baseline", "finding_id": fid}, admin, 201)
	id, err = a.claimScan(context.Background(), "test-worker")
	if err != nil || id != str(retest, "id") {
		t.Fatal("retest claim failed")
	}
	a.executeScan(context.Background(), "test-worker", id)
	finding := mustRequest(t, s, "GET", "/api/findings/"+fid, nil, admin, 200)
	if str(finding, "status") != "resolved" || object(finding["verification"])["scan_id"] != id {
		t.Fatalf("verified resolution failed %v", finding)
	}
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]any{"approval_enabled": true}, admin, 200)
	pending := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, admin, 201)
	if str(pending, "status") != "pending_approval" {
		t.Fatal("workflow omitted")
	}
	if id, _ := a.claimScan(context.Background(), "test-worker"); id != "" {
		t.Fatal("unapproved job claimed")
	}
	mustRequest(t, s, "POST", "/api/scans/"+str(pending, "id")+"/approve", map[string]any{"decision": "approved", "reason": "검증 승인"}, admin, 200)
	mustRequest(t, s, "POST", "/api/emergency-stop", map[string]any{"enabled": true, "reason": "테스트 중지"}, admin, 200)
	if id, _ := a.claimScan(context.Background(), "test-worker"); id != "" {
		t.Fatal("emergency job claimed")
	}
	stopped := mustRequest(t, s, "GET", "/api/scans/"+str(pending, "id"), nil, admin, 200)
	if str(stopped, "status") != "cancelled" {
		t.Fatal("queue not stopped")
	}
	mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, admin, 400)
	mustRequest(t, s, "POST", "/api/emergency-stop", map[string]any{"enabled": false, "reason": "테스트 재개"}, admin, 200)
	bypassed := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, admin, 201)
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]any{"approval_enabled": false}, admin, 200)
	a.releaseDisabledApprovals(context.Background())
	id, err = a.claimScan(context.Background(), "test-worker")
	if err != nil || id != str(bypassed, "id") {
		t.Fatal("disabled review did not release queue")
	}
}

func TestRESTDiscoveryIsNeverAutomaticallyApproved(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer integration-secret" {
			t.Error("connector authentication missing")
		}
		io.WriteString(w, `{"data":{"services":[{"service_name":"Imported asset","endpoint":"https://internal.example/api","owner_team":"red"}]}}`)
	}))
	defer upstream.Close()
	integration := mustRequest(t, s, "POST", "/api/integrations", map[string]any{"name": "Inventory", "type": "rest", "endpoint": upstream.URL, "secret": "integration-secret", "config": map[string]any{"items_path": "data.services", "mapping": map[string]any{"name": "service_name", "url": "endpoint", "team": "owner_team"}}}, admin, 200)
	if str(integration, "secret") != "" || !boolean(integration, "secret_configured") {
		t.Fatal("connector secret exposed")
	}
	result := mustRequest(t, s, "POST", "/api/integrations/"+str(integration, "id")+"/sync", nil, admin, 200)
	if number(result, "candidates", 0) != 1 {
		t.Fatal("mapping failed")
	}
	_, body, _ := request(t, s, "GET", "/api/discovery", nil, admin, true)
	var candidates []map[string]any
	json.Unmarshal(body, &candidates)
	if len(candidates) != 1 {
		t.Fatalf("candidates %s", body)
	}
	service := mustRequest(t, s, "POST", "/api/discovery/"+str(candidates[0], "id")+"/register", nil, admin, 201)
	if boolean(service, "approved") {
		t.Fatal("discovery auto-approved target")
	}
	mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": str(service, "id")}, admin, 400)
}

func TestAuthorizationControlsDetectExposureAndExpiredSession(t *testing.T) {
	a, s := testApp(t)
	domainEnableWorker(t, a, "auth-worker", "")
	admin := loginTest(t, s, "admin", "test-password-1234")
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "Bearer expired" {
			w.WriteHeader(403)
			io.WriteString(w, "login required")
			return
		}
		if r.URL.Path == "/own" && token == "Bearer comparison" {
			io.WriteString(w, "SYNTHETIC-OWN")
			return
		}
		if r.URL.Path == "/private" && (token == "Bearer authorized" || token == "Bearer comparison") {
			io.WriteString(w, "SYNTHETIC-PRIVATE")
			return
		}
		w.WriteHeader(404)
	}))
	defer closeTarget()
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Authorization target", "url": target, "environment": "staging", "approved": true}, admin, 200)
	sid := str(service, "id")
	u, _ := url.Parse(target)
	mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "Authorization scope", "service_id": sid, "allowed_hosts": []string{u.Host}, "allowed_paths": []string{"/"}, "approved": true, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339), "max_requests": 4, "timeout_seconds": 10, "max_rps": 5}, admin, 200)
	authorized := mustRequest(t, s, "POST", "/api/auth-profiles", map[string]any{"name": "Authorized role", "service_id": sid, "type": "bearer", "token": "authorized"}, admin, 200)
	comparison := mustRequest(t, s, "POST", "/api/auth-profiles", map[string]any{"name": "Comparison role", "service_id": sid, "type": "bearer", "token": "comparison"}, admin, 200)
	scenario := mustRequest(t, s, "POST", "/api/scenarios", map[string]any{"name": "Cross-user test", "service_id": sid, "path": "/private", "marker": "SYNTHETIC-PRIVATE", "authorized_profile_id": str(authorized, "id"), "unauthorized_profile_id": str(comparison, "id"), "unauthorized_control_path": "/own", "unauthorized_control_marker": "SYNTHETIC-OWN"}, admin, 200)
	input := map[string]any{"service_id": sid, "profile": "authorization", "scenario_id": str(scenario, "id")}
	mustRequest(t, s, "POST", "/api/scans", input, admin, 201)
	id, err := a.claimScan(context.Background(), "auth-worker")
	if err != nil || id == "" {
		t.Fatal(err)
	}
	a.executeScan(context.Background(), "auth-worker", id)
	scan := mustRequest(t, s, "GET", "/api/scans/"+id, nil, admin, 200)
	if str(scan, "status") != "completed" || !boolean(object(scan["result"]), "synthetic_marker_exposed") {
		t.Fatalf("authorization exposure missed: %v", scan)
	}
	var count int
	if err = a.DB.QueryRow(context.Background(), `SELECT count(*) FROM resources WHERE kind='findings' AND data->>'source'='authorization' AND data->>'status'='confirmed'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("authorization finding missing")
	}
	mustRequest(t, s, "PUT", "/api/auth-profiles/"+str(comparison, "id"), map[string]any{"token": "expired"}, admin, 200)
	mustRequest(t, s, "POST", "/api/scans", input, admin, 201)
	id, err = a.claimScan(context.Background(), "auth-worker")
	if err != nil || id == "" {
		t.Fatal(err)
	}
	a.executeScan(context.Background(), "auth-worker", id)
	scan = mustRequest(t, s, "GET", "/api/scans/"+id, nil, admin, 200)
	if str(scan, "status") != "inconclusive" {
		t.Fatalf("expired comparison session reported success: %v", scan)
	}
}

func TestQueueLeaseRecoveryIsBounded(t *testing.T) {
	a, _ := testApp(t)
	for _, id := range []string{"worker-one", "worker-two", "worker-three"} {
		domainEnableWorker(t, a, id, "")
	}
	ctx := context.Background()
	id := newID()
	serviceID := newID()
	if _, err := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'services','test','{}')`, serviceID); err != nil {
		t.Fatal(err)
	}
	_, err := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'scans','test',jsonb_build_object('status','queued','service_id',$2::text));`, id, serviceID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO scan_jobs(scan_id) VALUES($1)`, id)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := a.claimScan(ctx, "worker-one")
	if err != nil || claimed != id {
		t.Fatal("first claim failed")
	}
	claimed, err = a.claimScan(ctx, "worker-two")
	if err != nil || claimed != "" {
		t.Fatal("live lease claimed twice")
	}
	_, err = a.DB.Exec(ctx, `UPDATE scan_jobs SET lease_until=now()-interval '1 second' WHERE scan_id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = a.claimScan(ctx, "worker-two")
	if err != nil || claimed != id {
		t.Fatal("expired lease was not recovered")
	}
	_, err = a.DB.Exec(ctx, `UPDATE scan_jobs SET lease_until=now()-interval '1 second' WHERE scan_id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = a.claimScan(ctx, "worker-three")
	if err != nil || claimed != "" {
		t.Fatal("retry limit ignored")
	}
	scan, err := a.resource(ctx, "scans", id)
	if err != nil || str(scan.Data, "status") != "inconclusive" {
		t.Fatalf("exhausted scan did not become inconclusive: %v %v", scan, err)
	}
}

func TestPostgresConnectorUsesReadOnlyBoundedQueries(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	_, err := a.DB.Exec(context.Background(), `CREATE TABLE source_catalog(name text,url text); INSERT INTO source_catalog VALUES('DB discovered','https://db-discovered.internal');`)
	if err != nil {
		t.Fatal(err)
	}
	integration := mustRequest(t, s, "POST", "/api/integrations", map[string]any{"name": "DB inventory", "type": "postgres", "secret": a.DB.Config().ConnConfig.ConnString(), "config": map[string]any{"query": "SELECT name,url FROM source_catalog"}}, admin, 200)
	result := mustRequest(t, s, "POST", "/api/integrations/"+str(integration, "id")+"/sync", nil, admin, 200)
	if number(result, "candidates", 0) != 1 {
		t.Fatalf("Postgres mapping failed: %v", result)
	}
	v, err := a.resource(context.Background(), "integrations", str(integration, "id"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := a.integrationDB(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err = conn.Exec(context.Background(), `INSERT INTO source_catalog VALUES('forbidden','https://example.internal')`); err == nil {
		t.Fatal("connector database connection permitted a write")
	}
}

func TestConcurrentChangeEventReplayCreatesOneScan(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Event source", "environment": "staging"}, admin, 200)
	body := map[string]any{"service_id": str(service, "id"), "event_type": "deploy", "reference": "deployment-123", "profile": "import-only"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, b, _ := request(t, s, "POST", "/api/events", body, admin, true)
			if status != 200 && status != 201 {
				t.Errorf("event replay %d %s", status, b)
			}
		}()
	}
	wg.Wait()
	for _, kind := range []string{"scans", "events"} {
		var count int
		if err := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM resources WHERE kind=$1`, kind).Scan(&count); err != nil || count != 1 {
			t.Fatalf("replayed %s count=%d err=%v", kind, count, err)
		}
	}
}
