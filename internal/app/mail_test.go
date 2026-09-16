package app

import (
	"context"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMailSettingsDefaultOffAndValidated(t *testing.T) {
	v := defaultSettings()[mailSettingsGroup]
	if asBool(v["enabled"]) || asInt(v["smtp_port"]) != 25 || v["security"] != "auto" || asBool(v["skip_tls_verify"]) || v["username"] != "" || v["password"] != "" || asInt(v["timeout_seconds"]) != 10 {
		t.Fatalf("defaults %+v", v)
	}
	for _, e := range mailEvents {
		if on, ok := v["notify_"+e.Key].(bool); !ok || !on {
			t.Fatalf("event switch %s default", e.Key)
		}
	}
	if err := validateSettings(mailSettingsGroup, v); err != nil {
		t.Fatalf("empty default rejected: %v", err)
	}
	if !strings.Contains(secretFields[mailSettingsGroup][0], "password") {
		t.Fatal("password is not a secret field")
	}
	good := defaultSettings()[mailSettingsGroup]
	good["enabled"], good["smtp_host"], good["from_address"], good["smtp_port"], good["base_url"] = true, " relay.corp.local ", "hunter@corp.local", float64(587), "https://hunter.intra/"
	if err := validateSettings(mailSettingsGroup, good); err != nil || good["smtp_host"] != "relay.corp.local" || good["smtp_port"] != 587 {
		t.Fatalf("valid rejected: %v %+v", err, good)
	}
	for name, patch := range map[string]map[string]any{
		"enabled without host": {"enabled": true, "from_address": "hunter@corp.local"},
		"enabled without from": {"enabled": true, "smtp_host": "relay.corp.local"},
		"bad port":             {"smtp_port": float64(70000)},
		"fractional port":      {"smtp_port": 25.5},
		"bad security":         {"security": "ssl"},
		"host with path":       {"smtp_host": "smtp://relay"},
		"bad from":             {"from_address": "not-an-address"},
		"bad base url":         {"base_url": "relay.corp.local"},
		"timeout":              {"timeout_seconds": float64(0)},
		"newline":              {"from_name": "Hunter\r\nBcc: x"},
		"switch not bool":      {"notify_scan_failed": "yes"},
	} {
		v := defaultSettings()[mailSettingsGroup]
		for k, val := range patch {
			v[k] = val
		}
		if validateSettings(mailSettingsGroup, v) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func mailTestRelay(t *testing.T, s *httptest.Server, admin string, relay *notificationSMTPMock, enabled bool, extra map[string]any) {
	t.Helper()
	host, port, _ := net.SplitHostPort(relay.address)
	body := map[string]any{"enabled": enabled, "smtp_host": host, "smtp_port": port, "security": "none", "from_address": "hunter@corp.local", "from_name": "Hunter", "timeout_seconds": 3}
	for k, v := range extra {
		body[k] = v
	}
	if p, ok := body["smtp_port"].(string); ok {
		body["smtp_port"], _ = strconv.Atoi(p)
	}
	mustRequest(t, s, "PUT", "/api/settings/"+mailSettingsGroup, body, admin, 200)
}

func mailRows(t *testing.T, a *App) []map[string]any {
	t.Helper()
	rows, err := a.DB.Query(context.Background(), `SELECT event,recipient,recipient_user_id,actor_id,status,attempts,detail,body_encrypted<>'' AS has_body FROM mail_deliveries ORDER BY created_at,id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var event, recipient, userID, actor, status, detail string
		var attempts int
		var hasBody bool
		if err = rows.Scan(&event, &recipient, &userID, &actor, &status, &attempts, &detail, &hasBody); err != nil {
			t.Fatal(err)
		}
		out = append(out, map[string]any{"event": event, "recipient": recipient, "user": userID, "actor": actor, "status": status, "attempts": attempts, "detail": detail, "has_body": hasBody})
	}
	return out
}

// mailText decodes the quoted-printable body of a captured message.
func mailText(t *testing.T, msg string) string {
	t.Helper()
	_, body, _ := strings.Cut(strings.ReplaceAll(msg, "\r\n", "\n"), "\n\n")
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
}

func mailDrain(t *testing.T, a *App) {
	t.Helper()
	if _, err := a.DB.Exec(context.Background(), `UPDATE mail_deliveries SET available_at=now() WHERE status='queued'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		worked, err := a.mailDeliver(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			return
		}
	}
}

func TestMailNotificationsAreOffByDefaultBackgroundAndRecorded(t *testing.T) {
	a, s := testApp(t)
	previous := mailCoalesceWindow
	mailCoalesceWindow = 0
	t.Cleanup(func() { mailCoalesceWindow = previous })
	admin := loginTest(t, s, "admin", "test-password-1234")
	// Off by default: the settings API shows the switch off and never a password.
	settings := mustRequest(t, s, "GET", "/api/settings", nil, admin, 200)
	m := object(settings[mailSettingsGroup])
	if asBool(m["enabled"]) || m["password"] != "" || asBool(m["password_configured"]) {
		t.Fatalf("default mail settings %+v", m)
	}
	mustRequest(t, s, "POST", "/api/admin/mail/test", map[string]any{"to": "someone@corp.local"}, admin, 409)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer target.Close()
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "결제 API", "url": target.URL, "environment": "staging", "team": "blue", "approved": true}, admin, 200)
	sid := str(service, "id")
	mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "scope", "service_id": sid, "allowed_hosts": []string{strings.TrimPrefix(target.URL, "http://")}, "allowed_paths": []string{"/"}, "approved": true, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339), "max_requests": 4, "timeout_seconds": 10, "max_rps": 2}, admin, 200)
	mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "lead@corp.local", "name": "Blue Lead", "role": "lead", "team": "blue", "password": "test-password-1234"}, admin, 201)
	mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "red-lead@corp.local", "name": "Red Lead", "role": "lead", "team": "red", "password": "test-password-1234"}, admin, 201)
	// The requester is a second lead of the same team: leads may request scans for team services,
	// and the requester must never be among the approvers told about their own request.
	analystUser := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "analyst", "name": "분석가", "role": "lead", "team": "blue", "password": "test-password-1234"}, admin, 201)
	analyst := loginTest(t, s, "analyst", "test-password-1234")
	lead := loginTest(t, s, "lead@corp.local", "test-password-1234")
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]any{"approval_enabled": true}, admin, 200)

	// Disabled: a review request queues nothing, and the request itself is unaffected.
	first := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, analyst, 201)
	if rows := mailRows(t, a); len(rows) != 0 {
		t.Fatalf("mail queued while disabled: %+v", rows)
	}

	relay := newNotificationSMTPMock(t, "none", "")
	mailTestRelay(t, s, admin, relay, true, map[string]any{"password": "test-password", "username": "test-user"})
	saved := object(mustRequest(t, s, "GET", "/api/settings", nil, admin, 200)[mailSettingsGroup])
	if saved["password"] != "" || !asBool(saved["password_configured"]) || saved["username"] != "test-user" {
		t.Fatalf("password readable or lost: %+v", saved)
	}
	var stored string
	if err := a.DB.QueryRow(context.Background(), `SELECT value->>'password' FROM settings WHERE key=$1`, mailSettingsGroup).Scan(&stored); err != nil || stored == "test-password" || stored == "" {
		t.Fatalf("password stored in clear: %q %v", stored, err)
	}
	var n int
	if err := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE action='settings.update' AND target=$1 AND detail->>'password'='[REDACTED]'`, mailSettingsGroup).Scan(&n); err != nil || n != 1 {
		t.Fatalf("password not redacted in audit: %d %v", n, err)
	}

	// A review request reaches the team lead and administrators with an address, never the requester or another team.
	second := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, analyst, 201)
	rows := mailRows(t, a)
	if len(rows) != 1 || rows[0]["event"] != "approval_requested" || rows[0]["recipient"] != "lead@corp.local" || rows[0]["status"] != "queued" || rows[0]["actor"] != str(analystUser, "id") || rows[0]["has_body"] != true {
		t.Fatalf("approval mail rows %+v", rows)
	}
	mailDrain(t, a)
	select {
	case msg := <-relay.messages:
		if text := mailText(t, msg); !strings.Contains(msg, "To: <lead@corp.local>") || !strings.Contains(text, "바로 가기: http://localhost:8080/approvals") || !strings.Contains(text, "분석가 님이") {
			t.Fatalf("message %q", text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no message delivered")
	}
	rows = mailRows(t, a)
	if rows[0]["status"] != "sent" || rows[0]["attempts"] != 1 || rows[0]["has_body"] != false {
		t.Fatalf("sent row %+v", rows)
	}
	// The decision goes back to the requester (the analyst has no address, so nothing is queued);
	// the reviewer is not told about their own decision.
	mustRequest(t, s, "POST", "/api/scans/"+str(second, "id")+"/approve", map[string]any{"decision": "rejected", "reason": "범위 확인 필요"}, lead, 200)
	if rows = mailRows(t, a); len(rows) != 1 {
		t.Fatalf("decision without address queued %+v", rows)
	}
	// Give the analyst an address through the existing contact directory and decide the first request.
	directory := defaultNotificationAutomation()
	directory.Contacts = []notificationContact{{UserID: str(analystUser, "id"), Email: "analyst@corp.local", Verified: true}}
	notificationAutoSave(t, s, admin, directory)
	mustRequest(t, s, "POST", "/api/scans/"+str(first, "id")+"/approve", map[string]any{"decision": "approved", "reason": "확인"}, lead, 200)
	rows = mailRows(t, a)
	if len(rows) != 2 || rows[1]["event"] != "approval_decided" || rows[1]["recipient"] != "analyst@corp.local" {
		t.Fatalf("decision rows %+v", rows)
	}
	mailDrain(t, a)
	select {
	case msg := <-relay.messages:
		if text := mailText(t, msg); !strings.Contains(msg, "To: <analyst@corp.local>") || !strings.Contains(text, "/scans?item="+str(first, "id")) || !strings.Contains(text, "승인됨") {
			t.Fatalf("decision message %q", text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("decision not delivered")
	}

	// Two requests in one burst become one message; each row still records its own outcome.
	mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, analyst, 201)
	mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, analyst, 201)
	mailDrain(t, a)
	select {
	case msg := <-relay.messages:
		if text := mailText(t, msg); !strings.Contains(msg, "To: <lead@corp.local>") || strings.Count(text, "바로 가기: http://localhost:8080/approvals") != 2 || !strings.Contains(msg, "_2=EA=B1=B4?=") {
			t.Fatalf("bundle message %q", text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bundle not delivered")
	}
	select {
	case msg := <-relay.messages:
		t.Fatalf("bundle sent twice: %q", msg)
	case <-time.After(200 * time.Millisecond):
	}
	rows = mailRows(t, a)
	if len(rows) != 4 || rows[2]["status"] != "sent" || rows[3]["status"] != "sent" || !strings.HasPrefix(str(rows[3], "detail"), "2건 묶음") {
		t.Fatalf("bundle rows %+v", rows)
	}

	// An event switch stops only its own event.
	mailTestRelay(t, s, admin, relay, true, map[string]any{"notify_approval_requested": false})
	mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, analyst, 201)
	if rows = mailRows(t, a); len(rows) != 4 {
		t.Fatalf("switched-off event queued %+v", rows)
	}
	mailTestRelay(t, s, admin, relay, true, map[string]any{"notify_approval_requested": true})

	// The test button sends one real message and records the attempt.
	result := mustRequest(t, s, "POST", "/api/admin/mail/test", map[string]any{"to": "ops@corp.local"}, admin, 200)
	if result["state"] != "sent" || result["recipient"] != "ops@corp.local" {
		t.Fatalf("test send %+v", result)
	}
	<-relay.messages
	if code, _, _ := request(t, s, "POST", "/api/admin/mail/test", map[string]any{"to": "ops@corp.local"}, admin, false); code != 403 {
		t.Fatalf("csrf %d", code)
	}
	mustRequest(t, s, "POST", "/api/admin/mail/test", map[string]any{"to": "ops@corp.local"}, analyst, 403)
	mustRequest(t, s, "POST", "/api/admin/mail/test", map[string]any{"to": ""}, admin, 400) // admin has no address

	// A dead relay never fails the request: the row retries once, then is recorded as failed.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	mailTestRelay(t, s, admin, relay, true, map[string]any{"smtp_port": closedPort})
	mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": sid}, analyst, 201)
	if worked, err := a.mailDeliver(context.Background()); err != nil || !worked {
		t.Fatalf("first attempt %v %v %+v", worked, err, mailRows(t, a))
	}
	rows = mailRows(t, a)
	last := rows[len(rows)-1]
	if last["status"] != "queued" || last["attempts"] != 1 || last["has_body"] != true {
		t.Fatalf("retry row %+v", last)
	}
	mailDrain(t, a)
	rows = mailRows(t, a)
	last = rows[len(rows)-1]
	if last["status"] != "failed" || last["attempts"] != 2 || last["has_body"] != false || last["detail"] == "" {
		t.Fatalf("failed row %+v", last)
	}
	failed := mustRequest(t, s, "POST", "/api/admin/mail/test", map[string]any{"to": "ops@corp.local"}, admin, 200)
	if failed["state"] != "failed" {
		t.Fatalf("test send against dead relay %+v", failed)
	}

	// History shows successes and failures alike, without bodies, to administrators only.
	history := mustRequest(t, s, "GET", "/api/admin/mail/deliveries", nil, admin, 200)
	items, _ := history["items"].([]any)
	status := object(object(history["summary"])["status"])
	if len(items) != 7 || asInt(status["sent"]) != 5 || asInt(status["failed"]) != 2 {
		t.Fatalf("history %+v", history)
	}
	for _, item := range items {
		if _, ok := object(item)["body"]; ok {
			t.Fatal("history exposes body")
		}
	}
	mustRequest(t, s, "GET", "/api/admin/mail/deliveries", nil, analyst, 403)
}

func TestMailScanAndAgentEventsReachTheRequester(t *testing.T) {
	a, s := testApp(t)
	previous := mailCoalesceWindow
	mailCoalesceWindow = 0
	t.Cleanup(func() { mailCoalesceWindow = previous })
	admin := loginTest(t, s, "admin", "test-password-1234")
	relay := newNotificationSMTPMock(t, "none", "")
	mailTestRelay(t, s, admin, relay, true, map[string]any{"base_url": "https://hunter.intra"})
	owner := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "owner@corp.local", "name": "Owner", "role": "lead", "team": "blue", "password": "test-password-1234"}, admin, 201)
	ownerID := str(owner, "id")
	ctx := context.Background()
	for i, extra := range []string{`"agent_run_id":"run-1"`, `"schedule_id":"sch-1"`} {
		id := "scan-" + strconv.Itoa(i)
		if _, err := a.DB.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'scans',$2,('{"name":"야간 진단","service_name":"결제 API","status":"inconclusive","requested_by":"'||$2||'",'||$3||'}')::jsonb)`, id, ownerID, extra); err != nil {
			t.Fatal(err)
		}
		a.mailScanFailed(ctx, a.DB, id, "inconclusive")
	}
	// The agent-started scan stays quiet; the scheduled one reaches its requester.
	rows := mailRows(t, a)
	if len(rows) != 1 || rows[0]["event"] != "scan_failed" || rows[0]["recipient"] != "owner@corp.local" || rows[0]["user"] != ownerID {
		t.Fatalf("scan rows %+v", rows)
	}
	run := agentRun{ID: "run-9", OwnerID: ownerID, ServiceName: "결제 API", Title: "인증 우회 점검"}
	a.mailAgentRun(ctx, a.DB, run, "agent_waiting", "waiting_input", "대상 계정의 2차 인증 코드를 입력하세요")
	a.mailAgentRun(ctx, a.DB, run, "agent_failed", "failed", "모델 연결이 끊어졌습니다 token=sk-secret-value")
	mailDrain(t, a)
	texts := map[string]string{}
	for i := 0; i < 3; i++ {
		select {
		case msg := <-relay.messages:
			text := mailText(t, msg)
			switch {
			case strings.Contains(text, "진단이 완료되지 못했습니다"):
				texts["scan"] = text
			case strings.Contains(text, "추가 입력을 기다리며"):
				texts["waiting"] = text
			case strings.Contains(text, "완료되지 못하고 멈췄습니다"):
				texts["failed"] = text
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("messages %d", len(texts))
		}
	}
	if !strings.Contains(texts["scan"], "https://hunter.intra/scans?item=scan-1") || !strings.Contains(texts["scan"], "결과 미확정") {
		t.Fatalf("scan text %q", texts["scan"])
	}
	if !strings.Contains(texts["waiting"], "https://hunter.intra/agents/run-9") || !strings.Contains(texts["waiting"], "2차 인증 코드") {
		t.Fatalf("waiting text %q", texts["waiting"])
	}
	if !strings.Contains(texts["failed"], "인증 우회 점검") || strings.Contains(texts["failed"], "sk-secret-value") {
		t.Fatalf("failed text leaks or misses: %q", texts["failed"])
	}
	for _, r := range mailRows(t, a) {
		if r["status"] != "sent" || r["has_body"] != false {
			t.Fatalf("row %+v", r)
		}
	}
}
