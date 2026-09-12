package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func notificationTestChannel(t *testing.T, s *httptest.Server, admin, endpoint string, enabled bool) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/notification-channels", map[string]any{"name": "합성 HTTP 알림", "type": "webhook", "enabled": enabled, "config": map[string]any{"endpoint": endpoint, "auth": "bearer", "timeout_seconds": 3}, "secret": "synthetic-notification-credential"}, admin, 201)
}
func notificationTestRule(t *testing.T, s *httptest.Server, admin, channelID string, events []string, recipients []string) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/notification-rules", map[string]any{"name": "합성 규칙", "channel_id": channelID, "enabled": true, "events": events, "recipients": recipients}, admin, 201)
}
func notificationTestService(t *testing.T, s *httptest.Server, admin string) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "알림 합성 서비스", "url": "https://notify.example.internal", "environment": "staging", "team": "보안팀"}, admin, 200)
}
func notificationTestFinding(t *testing.T, s *httptest.Server, admin, serviceID string) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "합성 알림 대상", "service_id": serviceID, "severity": "high", "description": "외부 발송 금지 설명", "evidence": "Authorization: Bearer private-evidence-value"}, admin, 200)
}
func notificationDrainOutbox(t *testing.T, a *App) {
	t.Helper()
	for i := 0; i < 50; i++ {
		n, e := a.processNotificationOutbox(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if n == 0 {
			return
		}
	}
	t.Fatal("outbox failed to drain")
}
func notificationCount(t *testing.T, a *App, query string, args ...any) int {
	t.Helper()
	var n int
	if e := a.DB.QueryRow(context.Background(), query, args...).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func notificationState(t *testing.T, a *App, id string) string {
	t.Helper()
	var status string
	if e := a.DB.QueryRow(context.Background(), `SELECT status FROM notification_deliveries WHERE id=$1`, id).Scan(&status); e != nil {
		t.Fatal(e)
	}
	return status
}
func notificationExec(t *testing.T, a *App, query string, args ...any) {
	t.Helper()
	if _, e := a.DB.Exec(context.Background(), query, args...); e != nil {
		t.Fatal(e)
	}
}

func TestNotificationDomainAdminSettingsAndRevision(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	result := mustRequest(t, s, "GET", "/api/notification-channels", nil, admin, 200)
	if len(result["items"].([]any)) != 0 {
		t.Fatal("channels enabled by default")
	}
	c := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/unused", false)
	id := asString(c["id"])
	if c["secret"] != "" || !asBool(c["secret_configured"]) {
		t.Fatal("secret output mismatch")
	}
	var config, secret string
	if e := a.DB.QueryRow(context.Background(), `SELECT config_encrypted,secret_encrypted FROM notification_channels WHERE id=$1`, id).Scan(&config, &secret); e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(config, "enc:v1:") || strings.Contains(config, "127.0.0.1") || strings.Contains(secret, "synthetic-notification-credential") {
		t.Fatal("configuration not encrypted")
	}
	edit := map[string]any{"name": "변경 채널", "type": "webhook", "enabled": false, "config": c["config"], "expected_updated_at": c["updated_at"]}
	updated := mustRequest(t, s, "PUT", "/api/notification-channels/"+id, edit, admin, 200)
	if !asBool(updated["secret_configured"]) {
		t.Fatal("empty secret did not keep credential")
	}
	mustRequest(t, s, "PUT", "/api/notification-channels/"+id, edit, admin, 409)
	edit["expected_updated_at"] = updated["updated_at"]
	edit["clear_secret"] = true
	cleared := mustRequest(t, s, "PUT", "/api/notification-channels/"+id, edit, admin, 200)
	if asBool(cleared["secret_configured"]) {
		t.Fatal("clear secret failed")
	}
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "알림 제한 키", "scopes": []string{"services:read"}, "expires_days": 1}, admin, 201)
	token := asString(key["token"])
	for _, route := range []string{"/api/notification-channels", "/api/notification-rules", "/api/notification-deliveries"} {
		mustRequest(t, s, "GET", route, nil, token, 403)
	}
	mustRequest(t, s, "POST", "/api/notification-channels/"+id+"/test", map[string]any{"recipient": "private-recipient"}, token, 403)
	mustRequest(t, s, "POST", "/api/notification-rules", map[string]any{"name": "bad", "channel_id": id, "events": []string{"finding.created"}, "recipients": []string{"same", "same"}}, admin, 400)
	rule := notificationTestRule(t, s, admin, id, []string{"finding.created"}, []string{"recipient-only-in-cipher"})
	mustRequest(t, s, "DELETE", "/api/notification-channels/"+id, nil, admin, 409)
	var sealedRule string
	_ = a.DB.QueryRow(context.Background(), `SELECT config_encrypted FROM notification_rules WHERE id=$1`, rule["id"]).Scan(&sealedRule)
	if strings.Contains(sealedRule, "recipient-only-in-cipher") {
		t.Fatal("recipient stored in plaintext")
	}
	preview := mustRequest(t, s, "POST", "/api/notification-rules/preview", map[string]any{"name": "미리보기", "channel_id": id, "events": []string{"finding.created"}, "recipients": []string{"recipient-only-in-cipher"}}, admin, 200)
	if !asBool(preview["sample"]) || !strings.Contains(asString(preview["subject"]), "발견 건 등록") {
		t.Fatal("Korean preview missing")
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries`) != 0 {
		t.Fatal("preview sent a message")
	}
}

func TestNotificationDomainTransactionalOutboxAndRealHTTP(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	var lock sync.Mutex
	received := []map[string]any{}
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-notification-credential" {
			t.Error("gateway auth mismatch")
		}
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		lock.Lock()
		received = append(received, payload)
		lock.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"mock-receipt"}`)
	}))
	defer gateway.Close()
	c := notificationTestChannel(t, s, admin, gateway.URL, true)
	_ = notificationTestRule(t, s, admin, asString(c["id"]), []string{"finding.created", "finding.updated"}, []string{"recipient-one", "recipient-two"})
	service := notificationTestService(t, s, admin)
	tx, e := a.DB.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(context.Background(), `INSERT INTO resources(id,kind,owner_id,data) VALUES('rolled-back-notification','findings','synthetic',jsonb_build_object('service_id',$1::text,'title','rollback','status','candidate','severity','high'))`, service["id"])
	if e != nil {
		t.Fatal(e)
	}
	_ = tx.Rollback(context.Background())
	if notificationCount(t, a, `SELECT count(*) FROM notification_events`) != 0 {
		t.Fatal("rolled back event escaped transaction")
	}
	finding := notificationTestFinding(t, s, admin, asString(service["id"]))
	if notificationCount(t, a, `SELECT count(*) FROM notification_events`) != 1 {
		t.Fatal("committed event missing")
	}
	var raw string
	_ = a.DB.QueryRow(context.Background(), `SELECT metadata::text FROM notification_events LIMIT 1`).Scan(&raw)
	if strings.Contains(raw, "합성 알림 대상") || strings.Contains(raw, "private-evidence") {
		t.Fatal("outbox captured sensitive source payload")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := a.processNotificationOutbox(context.Background()); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries`) != 2 {
		t.Fatal("fanout duplicated or omitted recipient")
	}
	notificationDrainOutbox(t, a)
	for i := 0; i < 2; i++ {
		worked, err := a.processNotificationDelivery(context.Background())
		if err != nil || !worked {
			t.Fatalf("delivery failed: %v", err)
		}
	}
	lock.Lock()
	defer lock.Unlock()
	if len(received) != 2 {
		t.Fatalf("got %d receiver calls", len(received))
	}
	for _, payload := range received {
		body := asString(payload["message"])
		if !strings.Contains(body, "/findings?item="+asString(finding["id"])) || strings.Contains(body, "private-evidence") || strings.Contains(body, "외부 발송 금지 설명") {
			t.Fatal("message link or evidence boundary failed")
		}
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE status='sent'`) != 2 {
		t.Fatal("accepted messages not recorded")
	}
	// Reconstructing the control object and rerunning fanout must not resend durable work.
	restarted := &App{DB: a.DB, Key: a.Key}
	notificationDrainOutbox(t, restarted)
	if worked, err := restarted.processNotificationDelivery(context.Background()); err != nil || worked {
		t.Fatal("restart resent accepted delivery")
	}
	history := mustRequest(t, s, "GET", "/api/notification-deliveries?q=합성&sort=attempts&dir=desc", nil, admin, 200)
	if asInt(history["total"]) != 2 {
		t.Fatal("history search mismatch")
	}
	rawJSON, _ := json.Marshal(history)
	if strings.Contains(string(rawJSON), "recipient-one") || strings.Contains(string(rawJSON), "synthetic-notification-credential") {
		t.Fatal("history leaked recipient or credential")
	}
}

func TestNotificationDomainRetryUncertaintyAndCancellation(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	var status atomic.Int64
	status.Store(429)
	var calls atomic.Int64
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
		io.WriteString(w, `{"id":"mock"}`)
	}))
	defer gateway.Close()
	c := notificationTestChannel(t, s, admin, gateway.URL, false)
	queued := mustRequest(t, s, "POST", "/api/notification-channels/"+asString(c["id"])+"/test", map[string]any{"recipient": "test-receiver"}, admin, 201)
	id := asString(queued["id"])
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notificationState(t, a, id) != "retry" {
		t.Fatal("429 was not safely scheduled")
	}
	if worked, err := a.processNotificationDelivery(context.Background()); err != nil || worked {
		t.Fatal("backoff not respected")
	}
	notificationExec(t, a, `UPDATE notification_deliveries SET available_at=now() WHERE id=$1`, id)
	status.Store(200)
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notificationState(t, a, id) != "sent" || calls.Load() != 2 {
		t.Fatal("safe retry failed")
	}
	status.Store(503)
	uncertain := mustRequest(t, s, "POST", "/api/notification-channels/"+asString(c["id"])+"/test", map[string]any{"recipient": "uncertain-receiver"}, admin, 201)
	uid := asString(uncertain["id"])
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notificationState(t, a, uid) != "uncertain" {
		t.Fatal("unconfirmed provider response automatically retryable")
	}
	before := calls.Load()
	if worked, err := a.processNotificationDelivery(context.Background()); err != nil || worked || calls.Load() != before {
		t.Fatal("uncertain message resent")
	}
	mustRequest(t, s, "POST", "/api/notification-deliveries/"+uid+"/retry", map[string]any{}, admin, 400)
	mustRequest(t, s, "POST", "/api/notification-deliveries/"+uid+"/retry", map[string]any{"confirm_duplicate_risk": true, "reason": "모의 게이트웨이 확인 완료"}, admin, 200)
	status.Store(200)
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancelItem := mustRequest(t, s, "POST", "/api/notification-channels/"+asString(c["id"])+"/test", map[string]any{"recipient": "cancel-receiver"}, admin, 201)
	claim, err := a.claimNotification(context.Background())
	if err != nil || claim == nil {
		t.Fatal("claim failed", err)
	}
	mustRequest(t, s, "POST", "/api/notification-deliveries/"+asString(cancelItem["id"])+"/cancel", nil, admin, 200)
	if err = a.finishNotification(context.Background(), claim, NotificationSendResult{State: "retryable", Detail: "접수 전 취소"}); err != nil {
		t.Fatal(err)
	}
	if notificationState(t, a, claim.ID) != "cancelled" {
		t.Fatal("cancelled in-flight attempt became retry")
	}
	if worked, err := a.processNotificationDelivery(context.Background()); err != nil || worked {
		t.Fatal("cancelled delivery resent")
	}
	abandoned := mustRequest(t, s, "POST", "/api/notification-channels/"+asString(c["id"])+"/test", map[string]any{"recipient": "lost-worker"}, admin, 201)
	claim, err = a.claimNotification(context.Background())
	if err != nil || claim == nil {
		t.Fatal(err)
	}
	notificationExec(t, a, `UPDATE notification_deliveries SET lease_until=now()-interval '1 second' WHERE id=$1`, abandoned["id"])
	if worked, err := a.processNotificationDelivery(context.Background()); err != nil || worked {
		t.Fatal("expired sending lease reclaimed")
	}
	if notificationState(t, a, claim.ID) != "uncertain" {
		t.Fatal("lease expiry lost uncertainty")
	}
}

func TestNotificationDomainCurrentAuthorityAndConfig(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	var calls atomic.Int64
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer gateway.Close()
	channel := notificationTestChannel(t, s, admin, gateway.URL, true)
	cid := asString(channel["id"])
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "알림 테스트 권한", "scopes": []string{"admin:manage"}, "expires_days": 1}, admin, 201)
	token := asString(key["token"])
	test := mustRequest(t, s, "POST", "/api/notification-channels/"+cid+"/test", map[string]any{"recipient": "key-scoped"}, token, 201)
	notificationExec(t, a, `UPDATE api_keys SET revoked_at=now() WHERE id=$1`, key["key"].(map[string]any)["id"])
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notificationState(t, a, asString(test["id"])) != "failed" || calls.Load() != 0 {
		t.Fatal("revoked test credential still dispatched")
	}
	rule := notificationTestRule(t, s, admin, cid, []string{"finding.created"}, []string{"original-receiver"})
	service := notificationTestService(t, s, admin)
	finding := notificationTestFinding(t, s, admin, asString(service["id"]))
	notificationDrainOutbox(t, a)
	notificationExec(t, a, `UPDATE resources SET data=jsonb_set(data,'{team}','"다른팀"') WHERE id=$1`, service["id"])
	// A rule change cancels previously rendered recipients; a stale editor cannot undo it.
	edit := map[string]any{"name": rule["name"], "channel_id": cid, "enabled": true, "events": []string{"finding.created"}, "recipients": []string{"new-receiver"}, "expected_updated_at": rule["updated_at"]}
	mustRequest(t, s, "PUT", "/api/notification-rules/"+asString(rule["id"]), edit, admin, 200)
	mustRequest(t, s, "PUT", "/api/notification-rules/"+asString(rule["id"]), edit, admin, 409)
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE entity_id=$1 AND status='cancelled'`, finding["id"]) != 1 {
		t.Fatal("old rule recipient snapshot remained sendable")
	}
	if worked, err := a.processNotificationDelivery(context.Background()); err != nil || worked || calls.Load() != 0 {
		t.Fatal("changed rule sent stale snapshot")
	}
}

func TestNotificationDomainDueAndApprovalCurrentPolicy(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	channel := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/unused", true)
	_ = notificationTestRule(t, s, admin, asString(channel["id"]), []string{"finding.due", "approval.pending"}, []string{"policy-recipient"})
	service := notificationTestService(t, s, admin)
	finding := notificationTestFinding(t, s, admin, asString(service["id"]))
	notificationExec(t, a, `UPDATE resources SET created_at=now()-interval '2 days' WHERE id=$1`, finding["id"])
	sla := defaultSettings()["sla"]
	sla["enabled"] = true
	sla["high_days"] = 1
	mustRequest(t, s, "PUT", "/api/settings/sla", sla, admin, 200)
	if n, err := a.captureNotificationDue(context.Background()); err != nil || n != 1 {
		t.Fatal("due capture failed", n, err)
	}
	if n, err := a.captureNotificationDue(context.Background()); err != nil || n != 0 {
		t.Fatal("daily due duplicate", n, err)
	}
	notificationDrainOutbox(t, a)
	sla["enabled"] = false
	mustRequest(t, s, "PUT", "/api/settings/sla", sla, admin, 200)
	if worked, err := a.processNotificationDelivery(context.Background()); err != nil || worked {
		t.Fatal("disabled SLA delivery claimed")
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE status='cancelled'`) != 1 {
		t.Fatal("stale SLA reminder not cancelled")
	}
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]bool{"approval_enabled": true}, admin, 200)
	notificationExec(t, a, `INSERT INTO resources(id,kind,owner_id,data) VALUES('notification-approval','approvals','synthetic',jsonb_build_object('service_id',$1::text,'status','pending','name','합성 승인'))`, service["id"])
	notificationDrainOutbox(t, a)
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]bool{"approval_enabled": false}, admin, 200)
	if worked, err := a.processNotificationDelivery(context.Background()); err != nil || worked {
		t.Fatal("disabled approval flow delivery claimed")
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE status='cancelled'`) != 2 {
		t.Fatal("stale approval reminder not cancelled")
	}
	// Re-enabling SLA with an extended future deadline must also stop an old queued reminder.
	entity, err := a.resource(context.Background(), "findings", asString(finding["id"]))
	if err != nil {
		t.Fatal(err)
	}
	sla["enabled"] = true
	sla["high_days"] = 10
	mustRequest(t, s, "PUT", "/api/settings/sla", sla, admin, 200)
	valid, err := notificationEventCurrent(context.Background(), a.DB, "finding.due", entity, time.Now())
	if err != nil || valid {
		t.Fatal("future SLA deadline remained due")
	}
}

func TestNotificationDomainBoundedFanoutAndSourceFailure(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	channel := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/unused", true)
	for i := 0; i < 6; i++ {
		notificationTestRule(t, s, admin, asString(channel["id"]), []string{"finding.created"}, []string{"cursor-one", "cursor-two"})
	}
	service := notificationTestService(t, s, admin)
	finding := notificationTestFinding(t, s, admin, asString(service["id"]))
	var original []byte
	_ = a.DB.QueryRow(context.Background(), `SELECT data FROM resources WHERE id=$1`, finding["id"]).Scan(&original)
	notificationExec(t, a, `UPDATE resources SET data='"unexpected legacy shape"'::jsonb WHERE id=$1`, finding["id"])
	if _, err := a.processNotificationOutbox(context.Background()); err == nil {
		t.Fatal("source read failure was swallowed")
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_events WHERE status='pending'`) != 1 {
		t.Fatal("source failure lost durable event")
	}
	notificationExec(t, a, `UPDATE resources SET data=$2 WHERE id=$1`, finding["id"], original)
	if _, err := a.processNotificationOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries`) != 10 {
		t.Fatal("first bounded fanout exceeded five rules")
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_events WHERE status='pending'`) != 1 {
		t.Fatal("fanout cursor prematurely completed")
	}
	notificationDrainOutbox(t, a)
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries`) != 12 {
		t.Fatal("fanout cursor omitted or duplicated recipients")
	}
	first := a.notificationHash("01012345678")
	other := (&App{Key: []byte("different key")}).notificationHash("01012345678")
	if first == other {
		t.Fatal("recipient fingerprint not keyed")
	}
}
