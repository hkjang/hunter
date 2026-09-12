package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func notificationAutoSave(t *testing.T, s *httptest.Server, admin string, cfg notificationAutomation) map[string]any {
	t.Helper()
	v := mustRequest(t, s, "GET", "/api/notification-automation", nil, admin, 200)
	return mustRequest(t, s, "PUT", "/api/notification-automation", map[string]any{"config": cfg, "expected_updated_at": v["updated_at"]}, admin, 200)
}
func notificationAutoFinding(t *testing.T, s *httptest.Server, admin, serviceID string) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "합성 독립 알림", "service_id": serviceID, "severity": "high", "location": newID()}, admin, 200)
}
func notificationAutoAdminID(t *testing.T, a *App) string {
	t.Helper()
	var id string
	if e := a.DB.QueryRow(context.Background(), `SELECT id FROM users WHERE username='admin'`).Scan(&id); e != nil {
		t.Fatal(e)
	}
	return id
}
func notificationAutoRule(t *testing.T, s *httptest.Server, admin, channel string, events, sources []string) map[string]any {
	t.Helper()
	return mustRequest(t, s, "POST", "/api/notification-rules", map[string]any{"name": "자동화 합성 규칙", "channel_id": channel, "events": events, "recipient_sources": sources, "recipients": []string{}, "enabled": true}, admin, 201)
}
func notificationAutoFinish(t *testing.T, a *App) *notificationClaim {
	t.Helper()
	c, e := a.claimNotification(context.Background())
	if e != nil || c == nil {
		t.Fatalf("claim unavailable: %v", e)
	}
	if e = a.finishNotification(context.Background(), c, NotificationSendResult{State: "sent", ProviderID: "synthetic-receipt"}); e != nil {
		t.Fatal(e)
	}
	return c
}
func notificationAutoTick(t *testing.T, a *App, now time.Time) map[string]int64 {
	t.Helper()
	v, e := a.processNotificationAutomation(context.Background(), now)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func notificationAutoResetTick(t *testing.T, a *App) {
	notificationExec(t, a, `DELETE FROM notification_automation_ticks WHERE key='jobs'`)
}
func TestNotificationAutomationConfigAndBusinessCalendar(t *testing.T) {
	cfg := defaultNotificationAutomation()
	cfg.Calendar.Holidays = []string{"2026-09-14"}
	friday := time.Date(2026, 9, 11, 9, 0, 0, 0, time.FixedZone("KST", 9*3600))
	tuesday := friday.AddDate(0, 0, 4)
	if got := notificationBusinessDays(cfg, friday, tuesday); got != 1 {
		t.Fatalf("weekend/holiday calculation=%d", got)
	}
	cfg.Timezone = "America/New_York"
	cfg.Calendar.Holidays = nil
	start := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	if got := notificationBusinessDays(cfg, start, start.AddDate(0, 0, 3)); got != 1 {
		t.Fatalf("DST business days=%d", got)
	}
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	cfg = defaultNotificationAutomation()
	cfg.Enabled = true
	cfg.Contacts = []notificationContact{{UserID: notificationAutoAdminID(t, a), Email: "synthetic-contact@example.internal", Verified: true}}
	saved := notificationAutoSave(t, s, admin, cfg)
	if notificationCount(t, a, `SELECT count(*) FROM notification_automation WHERE config_encrypted LIKE '%synthetic-contact%'`) != 0 {
		t.Fatal("contact plaintext stored")
	}
	mustRequest(t, s, "PUT", "/api/notification-automation", map[string]any{"config": cfg, "expected_updated_at": "2000-01-01T00:00:00Z"}, admin, 409)
	cfg.Calendar.Weekdays = []int{1, 1}
	mustRequest(t, s, "PUT", "/api/notification-automation", map[string]any{"config": cfg, "expected_updated_at": saved["updated_at"]}, admin, 400)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "제한 키", "scopes": []string{"services:read"}, "expires_days": 1}, admin, 201)
	mustRequest(t, s, "GET", "/api/notification-automation", nil, key["token"].(string), 403)
}
func TestNotificationAutomationDigestAndCurrentRecipient(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	uid := notificationAutoAdminID(t, a)
	cfg := defaultNotificationAutomation()
	cfg.Enabled = true
	cfg.Grouping.Enabled = true
	cfg.Acknowledgement.Enabled = true
	cfg.Contacts = []notificationContact{{UserID: uid, WebhookID: "registered-admin", Verified: true}}
	notificationAutoSave(t, s, admin, cfg)
	channel := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/mock", true)
	notificationAutoRule(t, s, admin, channel["id"].(string), []string{"finding.created"}, []string{"service_owner"})
	service := notificationTestService(t, s, admin)
	for _, title := range []string{"첫 번째 합성 원인", "두 번째 합성 원인"} {
		mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": title, "service_id": service["id"], "severity": "high", "cve": "CVE-2026-12345", "component": "shared-library", "location": newID()}, admin, 200)
	}
	notificationDrainOutbox(t, a)
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries`) != 1 || notificationCount(t, a, `SELECT count(*) FROM notification_delivery_members`) != 2 {
		t.Fatal("digest failed to group exact common cause")
	}
	if c, e := a.claimNotification(context.Background()); e != nil || c != nil {
		t.Fatal("group window sent too early")
	}
	notificationExec(t, a, `UPDATE notification_deliveries SET available_at=now()-interval '1 second'`)
	c := notificationAutoFinish(t, a)
	if c.MemberCount != 2 || !strings.Contains(c.Message.Body, "첫 번째") || !strings.Contains(c.Message.Body, "두 번째") {
		t.Fatal("digest omitted members")
	}
	inbox := mustRequest(t, s, "GET", "/api/my-notifications?status=pending", nil, admin, 200)
	if inbox["total"].(float64) != 1 {
		t.Fatal("dynamic personal item absent")
	}
	serviceOnly := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "서비스만", "scopes": []string{"services:read"}, "expires_days": 1}, admin, 201)
	hidden := mustRequest(t, s, "GET", "/api/my-notifications", nil, serviceOnly["token"].(string), 200)
	if hidden["total"].(float64) != 0 {
		t.Fatal("finding data escaped key scope")
	}
	mustRequest(t, s, "POST", "/api/my-notifications/"+c.ID+"/ack", map[string]any{}, serviceOnly["token"].(string), 404)
	mustRequest(t, s, "POST", "/api/my-notifications/"+c.ID+"/ack", map[string]any{}, admin, 200)
	if notificationCount(t, a, `SELECT count(*) FROM resources WHERE kind='findings' AND data->>'status'='candidate'`) != 2 {
		t.Fatal("work acknowledgement changed finding status")
	}
	// A role loses team authorization after enqueue. The original recipient must not receive it.
	lead := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "lead-auto", "name": "합성 팀장", "role": "lead", "team": "보안팀", "password": "test-password-1234"}, admin, 201)
	cfg.Contacts = append(cfg.Contacts, notificationContact{UserID: lead["id"].(string), WebhookID: "lead-address", Verified: true})
	cfg.OnCall = []notificationOnCall{{Team: "보안팀", UserID: lead["id"].(string), StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}}
	notificationAutoSave(t, s, admin, cfg)
	notificationAutoRule(t, s, admin, channel["id"].(string), []string{"finding.updated"}, []string{"on_call"})
	var findingID string
	a.DB.QueryRow(context.Background(), `SELECT id FROM resources WHERE kind='findings' LIMIT 1`).Scan(&findingID)
	mustRequest(t, s, "PUT", "/api/findings/"+findingID, map[string]any{"title": "변경 알림", "service_id": service["id"], "severity": "critical"}, admin, 200)
	notificationDrainOutbox(t, a)
	notificationExec(t, a, `UPDATE users SET role='viewer' WHERE id=$1`, lead["id"])
	notificationExec(t, a, `UPDATE notification_deliveries SET available_at=now() WHERE status='queued'`)
	if c, e := a.claimNotification(context.Background()); e != nil || c != nil {
		t.Fatalf("revoked team access was sent: %v", e)
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE recipient_user_id=$1 AND status='cancelled'`, lead["id"]) != 1 {
		t.Fatal("queued stale recipient not cancelled")
	}
}
func TestNotificationAutomationEmergencyRateAndSimulation(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	cfg := defaultNotificationAutomation()
	cfg.Enabled = true
	cfg.Grouping.Enabled = true
	cfg.Grouping.RecipientHourlyLimit = 1
	notificationAutoSave(t, s, admin, cfg)
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/mock", true)
	rule := notificationTestRule(t, s, admin, ch["id"].(string), []string{"finding.created"}, []string{"static-target"})
	service := notificationTestService(t, s, admin)
	notificationAutoFinding(t, s, admin, service["id"].(string))
	notificationDrainOutbox(t, a)
	notificationExec(t, a, `UPDATE notification_deliveries SET available_at=now()`)
	notificationAutoFinish(t, a)
	notificationAutoFinding(t, s, admin, service["id"].(string))
	notificationDrainOutbox(t, a)
	notificationExec(t, a, `UPDATE notification_deliveries SET available_at=now() WHERE status='queued'`)
	if c, e := a.claimNotification(context.Background()); e != nil || c != nil {
		t.Fatal("recipient rate cap not applied")
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE status='queued' AND available_at>now()+interval '30 minutes'`) != 1 {
		t.Fatal("rate-limited delivery lost rather than deferred")
	}
	mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "치명적 긴급", "service_id": service["id"], "severity": "critical"}, admin, 200)
	notificationDrainOutbox(t, a)
	c := notificationAutoFinish(t, a)
	if c.Message.Variables["finding.severity"] != "critical" {
		t.Fatal("emergency exception failed")
	}
	before := notificationCount(t, a, `SELECT count(*) FROM notification_deliveries`)
	sim := mustRequest(t, s, "POST", "/api/notification-automation/simulate", map[string]any{"rule_id": rule["id"], "from": time.Now().Add(-time.Hour), "to": time.Now().Add(time.Hour), "limit": 100}, admin, 200)
	if sim["matched"].(float64) != 3 || notificationCount(t, a, `SELECT count(*) FROM notification_deliveries`) != before {
		t.Fatal("simulation sent or omitted retained events")
	}
	raw, _ := json.Marshal(sim)
	if strings.Contains(string(raw), "static-target") {
		t.Fatal("simulation persisted raw recipient")
	}
}
func TestNotificationAutomationReminderFollowupAndWeekly(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	cfg := defaultNotificationAutomation()
	cfg.Enabled = true
	cfg.Calendar.Enabled = true
	cfg.Calendar.Weekdays = []int{0, 1, 2, 3, 4, 5, 6}
	cfg.Acknowledgement.Enabled = true
	cfg.Weekly.Enabled = true
	now := time.Now()
	loc, _ := time.LoadLocation(cfg.Timezone)
	cfg.Weekly.Weekday = int(now.In(loc).Weekday())
	cfg.Weekly.Hour = now.In(loc).Hour()
	cfg.Contacts = []notificationContact{{UserID: notificationAutoAdminID(t, a), WebhookID: "admin-weekly", Verified: true}}
	notificationAutoSave(t, s, admin, cfg)
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/mock", true)
	notificationAutoRule(t, s, admin, ch["id"].(string), []string{"finding.created", "finding.due_soon", "finding.unacknowledged"}, []string{"service_owner"})
	weekly := notificationAutoRule(t, s, admin, ch["id"].(string), []string{"team.weekly"}, []string{"service_owner"})
	service := notificationTestService(t, s, admin)
	f := mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "기한예고 합성", "service_id": service["id"], "severity": "high", "due_date": now.Add(24 * time.Hour).UTC().Format(time.RFC3339)}, admin, 200)
	notificationDrainOutbox(t, a)
	c := notificationAutoFinish(t, a)
	notificationExec(t, a, `UPDATE notification_deliveries SET ack_due_at=now()-interval '1 minute' WHERE id=$1`, c.ID)
	stats := notificationAutoTick(t, a, now.Add(time.Second))
	if stats["due_soon"] != 1 || stats["followups"] != 1 || stats["weekly"] != 1 {
		t.Fatalf("automation counts: %+v", stats)
	}
	notificationAutoResetTick(t, a)
	stats = notificationAutoTick(t, a, now.Add(2*time.Second))
	if stats["due_soon"] != 0 || stats["followups"] != 0 || stats["weekly"] != 0 {
		t.Fatal("repeat tick duplicated events")
	}
	mustRequest(t, s, "POST", "/api/my-notifications/"+c.ID+"/ack", map[string]any{}, admin, 200)
	notificationDrainOutbox(t, a)
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE event_type='finding.unacknowledged'`) != 0 {
		t.Fatal("acknowledged work still escalated")
	}
	var sawWeekly bool
	for i := 0; i < 3; i++ {
		c, e := a.claimNotification(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if c == nil {
			break
		}
		if c.EventType == "team.weekly" {
			sawWeekly = true
			if c.Message.Variables["summary.total"] != "1" || !strings.Contains(c.Message.Body, "현재 미조치: 1") {
				t.Fatal("weekly metrics missing")
			}
		}
		if e = a.finishNotification(context.Background(), c, NotificationSendResult{State: "sent"}); e != nil {
			t.Fatal(e)
		}
	}
	if !sawWeekly {
		t.Fatal("weekly message missing")
	}
	_ = weekly
	_ = f
}
func TestNotificationAutomationRetentionKeepsUncertainAndDedup(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	cfg := defaultNotificationAutomation()
	cfg.Enabled = true
	cfg.Retention.Enabled = true
	cfg.Retention.PayloadDays = 1
	notificationAutoSave(t, s, admin, cfg)
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/mock", true)
	notificationTestRule(t, s, admin, ch["id"].(string), []string{"finding.created"}, []string{"static-retained"})
	service := notificationTestService(t, s, admin)
	for i := 0; i < 4; i++ {
		notificationAutoFinding(t, s, admin, service["id"].(string))
	}
	notificationDrainOutbox(t, a)
	ids := []string{}
	for i := 0; i < 4; i++ {
		c := notificationAutoFinish(t, a)
		ids = append(ids, c.ID)
	}
	notificationExec(t, a, `UPDATE notification_deliveries SET updated_at=now()-interval '2 days'`)
	notificationExec(t, a, `UPDATE notification_deliveries SET status='uncertain' WHERE id=$1`, ids[1])
	notificationExec(t, a, `UPDATE notification_deliveries SET retention_hold=true WHERE id=$1`, ids[2])
	notificationExec(t, a, `UPDATE notification_deliveries SET status='queued' WHERE id=$1`, ids[3])
	stats := notificationAutoTick(t, a, time.Now())
	if stats["purged"] != 1 {
		t.Fatalf("retention exclusion counts %+v", stats)
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE payload_purged_at IS NOT NULL AND payload_encrypted=''`) != 1 || notificationCount(t, a, `SELECT count(*) FROM notification_delivery_members`) != 4 {
		t.Fatal("retention erased dedup identity or protected payload")
	}
	v := mustRequest(t, s, "GET", "/api/notification-deliveries/"+ids[0], nil, admin, 200)
	if v["can_retry"].(bool) || v["payload_purged_at"] == nil {
		t.Fatal("purged history not represented")
	}
	notificationExec(t, a, `UPDATE notification_events SET status='pending',rule_cursor=''`)
	notificationDrainOutbox(t, a)
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries`) != 4 {
		t.Fatal("purge caused duplicate send")
	}
}

func TestNotificationAutomationInboxChecksEveryDigestMember(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	member := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "member-auto", "name": "합성 담당자", "role": "analyst", "team": "보안팀", "password": "test-password-1234"}, admin, 201)
	uid := member["id"].(string)
	cfg := defaultNotificationAutomation()
	cfg.Enabled = true
	cfg.Grouping.Enabled = true
	cfg.Acknowledgement.Enabled = true
	cfg.Contacts = []notificationContact{{UserID: uid, WebhookID: "member-address", Verified: true}}
	notificationAutoSave(t, s, admin, cfg)
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/mock", true)
	notificationAutoRule(t, s, admin, ch["id"].(string), []string{"finding.created"}, []string{"assignee"})
	service := notificationTestService(t, s, admin)
	ids := []string{}
	for _, name := range []string{"개인 소유 A", "개인 소유 B"} {
		f := mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": name, "service_id": service["id"], "severity": "high", "assignee": uid, "cve": "CVE-2026-99999", "component": "shared", "location": name}, admin, 200)
		id := f["id"].(string)
		ids = append(ids, id)
		notificationExec(t, a, `UPDATE resources SET owner_id=$2 WHERE id=$1`, id, uid)
	}
	notificationDrainOutbox(t, a)
	notificationExec(t, a, `UPDATE notification_deliveries SET available_at=now()`)
	c := notificationAutoFinish(t, a)
	personal := loginTest(t, s, "member-auto", "test-password-1234")
	before := mustRequest(t, s, "GET", "/api/my-notifications", nil, personal, 200)
	if before["total"].(float64) != 1 {
		t.Fatal("owned digest hidden before permission change")
	}
	changed := ids[0]
	if changed == c.EntityID {
		changed = ids[1]
	}
	notificationExec(t, a, `UPDATE resources SET owner_id=$2 WHERE id=$1`, changed, notificationAutoAdminID(t, a))
	after := mustRequest(t, s, "GET", "/api/my-notifications", nil, personal, 200)
	if after["total"].(float64) != 0 {
		t.Fatal("nonrepresentative member leaked via inbox count/page")
	}
	mustRequest(t, s, "POST", "/api/my-notifications/"+c.ID+"/ack", map[string]any{}, personal, 404)
}
func TestNotificationAutomationWeeklySnapshotScopeAndRetentionCursor(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	lead := mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "weekly-lead", "name": "주간 팀장", "role": "lead", "team": "보안팀", "password": "test-password-1234"}, admin, 201)
	uid := lead["id"].(string)
	cfg := defaultNotificationAutomation()
	cfg.Enabled = true
	cfg.Weekly.Enabled = true
	cfg.Retention.Enabled = true
	cfg.Retention.PayloadDays = 1
	loc, _ := time.LoadLocation(cfg.Timezone)
	now := time.Now()
	cfg.Weekly.Weekday = int(now.In(loc).Weekday())
	cfg.Weekly.Hour = now.In(loc).Hour()
	cfg.Contacts = []notificationContact{{UserID: uid, WebhookID: "weekly-lead", Verified: true}}
	notificationAutoSave(t, s, admin, cfg)
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/mock", true)
	notificationAutoRule(t, s, admin, ch["id"].(string), []string{"team.weekly"}, []string{"team"})
	s1 := notificationTestService(t, s, admin)
	s2 := notificationTestService(t, s, admin)
	notificationAutoFinding(t, s, admin, s1["id"].(string))
	notificationAutoFinding(t, s, admin, s2["id"].(string))
	notificationAutoTick(t, a, time.Now())
	notificationDrainOutbox(t, a)
	c := notificationAutoFinish(t, a)
	if c.Message.Variables["summary.total"] != "2" || notificationCount(t, a, `SELECT count(*) FROM notification_delivery_scope WHERE delivery_id=$1`, c.ID) != 2 {
		t.Fatal("weekly service envelope missing")
	}
	personal := loginTest(t, s, "weekly-lead", "test-password-1234")
	before := mustRequest(t, s, "GET", "/api/my-notifications", nil, personal, 200)
	if before["total"].(float64) != 1 {
		t.Fatal("weekly inbox missing")
	}
	other := s1["id"].(string)
	if other == c.ServiceID {
		other = s2["id"].(string)
	}
	notificationExec(t, a, `UPDATE resources SET data=jsonb_set(data,'{team}','"다른팀"') WHERE id=$1`, other)
	after := mustRequest(t, s, "GET", "/api/my-notifications", nil, personal, 200)
	if after["total"].(float64) != 0 {
		t.Fatal("past aggregate leaked after contributing service moved teams")
	}
	// Older receipt-blocked rows must not starve the eligible 101st row.
	notificationExec(t, a, `UPDATE notification_deliveries SET updated_at=now()-interval '2 days' WHERE id=$1`, c.ID)
	notificationExec(t, a, `INSERT INTO notification_deliveries(id,event_type,channel_id,channel_name,channel_type,channel_revision,payload_encrypted,recipient_hash,status,created_at,updated_at) SELECT 'blocked-'||i,'manual.test',channel_id,channel_name,channel_type,channel_revision,payload_encrypted,recipient_hash,'sent',now()-interval '4 days',now()-interval '3 days' FROM notification_deliveries CROSS JOIN generate_series(1,100) i WHERE id=$1`, c.ID)
	notificationExec(t, a, `INSERT INTO notification_receipts(delivery_id,channel_id,config_revision,channel_revision,state,provider_id) SELECT id,channel_id,(SELECT updated_at FROM notification_operations_config),channel_revision,'pending','synthetic-id' FROM notification_deliveries WHERE id LIKE 'blocked-%'`)
	notificationExec(t, a, `INSERT INTO notification_receipts(delivery_id,channel_id,config_revision,channel_revision,state,provider_id) SELECT id,channel_id,(SELECT updated_at FROM notification_operations_config),channel_revision,'delivered','retention-provider-marker' FROM notification_deliveries WHERE id=$1`, c.ID)
	notificationAutoResetTick(t, a)
	stats := notificationAutoTick(t, a, now.Add(time.Minute))
	if stats["purged"] != 1 || notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE id=$1 AND payload_purged_at IS NOT NULL`, c.ID) != 1 {
		t.Fatal("blocked retention candidates starved eligible row")
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_receipts WHERE delivery_id=$1 AND provider_id='' AND state='delivered'`, c.ID) != 1 {
		t.Fatal("terminal receipt identifier retained after payload purge")
	}
}

func TestNotificationAutomationRecipientOverflowDoesNotBlockQueue(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	notificationExec(t, a, `INSERT INTO users(id,username,name,role,team) SELECT 'routing-'||i,'routing-'||i,'합성 수신자','lead','보안팀' FROM generate_series(1,101) i`)
	cfg := defaultNotificationAutomation()
	cfg.Enabled = true
	for i := 1; i <= 101; i++ {
		id := "routing-" + strconv.Itoa(i)
		cfg.Contacts = append(cfg.Contacts, notificationContact{UserID: id, WebhookID: id, Verified: true})
	}
	notificationAutoSave(t, s, admin, cfg)
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/mock", true)
	notificationAutoRule(t, s, admin, ch["id"].(string), []string{"finding.created"}, []string{"team"})
	notificationTestRule(t, s, admin, ch["id"].(string), []string{"finding.created"}, []string{"valid-static"})
	service := notificationTestService(t, s, admin)
	notificationAutoFinding(t, s, admin, service["id"].(string))
	notificationDrainOutbox(t, a)
	if notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE status='cancelled' AND attempts=0 AND last_error LIKE '%100%'`) != 1 || notificationCount(t, a, `SELECT count(*) FROM notification_deliveries WHERE status='queued'`) != 1 || notificationCount(t, a, `SELECT count(*) FROM notification_events WHERE status='pending'`) != 0 {
		t.Fatal("overloaded rule stalled other authorized recipients")
	}
	c := notificationAutoFinish(t, a)
	notificationExec(t, a, `UPDATE notification_deliveries SET status='uncertain' WHERE id=$1`, c.ID)
	notificationExec(t, a, `INSERT INTO notification_receipts(delivery_id,channel_id,config_revision,channel_revision,state) SELECT id,channel_id,(SELECT updated_at FROM notification_operations_config),channel_revision,'unavailable' FROM notification_deliveries WHERE id=$1`, c.ID)
	detail := mustRequest(t, s, "GET", "/api/notification-deliveries/"+c.ID, nil, admin, 200)
	if detail["can_retry"].(bool) || detail["retry_block_reason"] == "" {
		t.Fatal("history did not mirror receipt retry rejection")
	}
	mustRequest(t, s, "POST", "/api/notification-deliveries/"+c.ID+"/retry", map[string]any{"confirm_duplicate_risk": true, "reason": "합성 중복 확인 사유"}, admin, 409)
}
