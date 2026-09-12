package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func notificationOperationsSave(t *testing.T, s *httptest.Server, admin string, c notificationOperationsConfig) map[string]any {
	t.Helper()
	old := mustRequest(t, s, "GET", "/api/notification-operations", nil, admin, 200)
	return mustRequest(t, s, "PUT", "/api/notification-operations", map[string]any{"config": c, "expected_updated_at": old["updated_at"]}, admin, 200)
}
func notificationOperationsPolicy(id string) notificationChannelPolicy {
	return notificationChannelPolicy{ChannelID: id, Tracking: notificationTracking{Method: "GET", StatePath: "status", PollIntervalSeconds: 60, MaxChecks: 3, DeliveredValues: []string{"delivered"}, FailedValues: []string{"failed"}, PendingValues: []string{"pending"}}, Protection: notificationProtection{ConsecutiveFailures: 2, OpenSeconds: 30}}
}
func notificationOperationsDelivery(t *testing.T, a *App, s *httptest.Server, admin, channelID string) string {
	t.Helper()
	notificationTestRule(t, s, admin, channelID, []string{"finding.created"}, []string{"synthetic-internal-recipient"})
	service := notificationTestService(t, s, admin)
	finding := notificationTestFinding(t, s, admin, asString(service["id"]))
	notificationDrainOutbox(t, a)
	var id string
	if err := a.DB.QueryRow(context.Background(), `SELECT id FROM notification_deliveries WHERE entity_id=$1`, finding["id"]).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
func notificationOperationsCallback(t *testing.T, s *httptest.Server, channel, secret string, in notificationReceiptInput, want int) {
	t.Helper()
	raw, _ := json.Marshal(in)
	stamp := fmt.Sprint(time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stamp + "\n"))
	mac.Write(raw)
	req, _ := http.NewRequest("POST", s.URL+"/api/notification-receipts/"+channel, bytes.NewReader(raw))
	req.Header.Set("X-Hunter-Timestamp", stamp)
	req.Header.Set("X-Hunter-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("callback got %d want %d: %v", resp.StatusCode, want, body)
	}
}
func TestNotificationOperationsSafeLookupAndTransitions(t *testing.T) {
	spec := notificationTracking{Endpoint: "https://gateway.internal/results/{{provider_id}}", Query: map[string]string{"delivery": "{{delivery_id}}"}}
	u, err := notificationTrackingURL(spec, "id/a?b#c", "one&admin=true")
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "gateway.internal" || u.EscapedPath() != "/results/id%2Fa%3Fb%23c" || u.Query().Get("delivery") != "one&admin=true" || u.Query().Has("admin") {
		t.Fatalf("unsafe interpolation: %s", u)
	}
	for _, endpoint := range []string{"https://{{provider_id}}/x", "https://gateway.internal/x?id={{provider_id}}", "https://user:pass@gateway.internal/x", "file:///x", "https://gateway.internal/{{unknown}}"} {
		spec.Endpoint = endpoint
		if _, err := notificationTrackingURL(spec, "id", "delivery"); err == nil {
			t.Fatalf("accepted unsafe endpoint %s", endpoint)
		}
	}
	spec.BodyTemplate = map[string]any{"id": "{{provider_id}}", "nested": []any{map[string]any{"delivery": "{{delivery_id}}"}}}
	raw, err := notificationTrackingBody(spec, `quote"\value`, "d")
	var decoded map[string]any
	if err != nil || json.Unmarshal(raw, &decoded) != nil || decoded["id"] != `quote"\value` {
		t.Fatal("JSON interpolation lost boundaries")
	}
	old := time.Now()
	for _, v := range []struct {
		prev, next, want string
		at               time.Time
	}{{"delivered", "pending", "delivered", old.Add(time.Hour)}, {"delivery_failed", "delivered", "conflict", old.Add(-time.Hour)}, {"pending", "delivered", "pending", old.Add(-time.Hour)}, {"conflict", "delivered", "conflict", old.Add(time.Hour)}} {
		got, _ := notificationReceiptTransition(v.prev, v.next, &old, v.at)
		if got != v.want {
			t.Errorf("%s + %s = %s", v.prev, v.next, got)
		}
	}
	if notificationConfirmedFailure(NotificationSendResult{State: "retryable", Code: "503"}, "failed") || notificationConfirmedFailure(NotificationSendResult{State: "uncertain", Code: "500"}, "failed") || notificationConfirmedFailure(NotificationSendResult{State: "failed"}, "failed") {
		t.Fatal("ambiguous failure eligible for fallback")
	}
}
func TestNotificationOperationsConfigurationAuthorizationAndSecrets(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	c := notificationTestChannel(t, s, admin, "http://127.0.0.1:12345/send", true)
	p := notificationOperationsPolicy(asString(c["id"]))
	p.Tracking.CallbackEnabled = true
	p.Tracking.CallbackSecret = strings.Repeat("callback-secret-", 3)
	saved := notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	raw, _ := json.Marshal(saved)
	if strings.Contains(string(raw), p.Tracking.CallbackSecret) || !strings.Contains(string(raw), `"callback_secret_configured":true`) {
		t.Fatal("callback secret exposed or missing flag")
	}
	var cipher string
	_ = a.DB.QueryRow(context.Background(), `SELECT config_encrypted FROM notification_operations_config`).Scan(&cipher)
	if !strings.HasPrefix(cipher, "enc:v1:") || strings.Contains(cipher, p.Tracking.CallbackSecret) {
		t.Fatal("unsealed operations settings")
	}
	p.Tracking.CallbackSecret = ""
	cfg := notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}}
	notificationOperationsSave(t, s, admin, cfg)
	current, _, err := a.notificationOperationsConfig(context.Background(), a.DB)
	if err != nil || current.Channels[0].Tracking.CallbackSecret == "" {
		t.Fatal("empty secret replaced current")
	}
	mustRequest(t, s, "PUT", "/api/notification-operations", map[string]any{"config": cfg, "expected_updated_at": saved["updated_at"]}, admin, 409)
	latest := mustRequest(t, s, "GET", "/api/notification-operations", nil, admin, 200)
	cfg.Channels[0].Tracking.Enabled = true
	cfg.Channels[0].Tracking.Endpoint = "https://different.internal/results/{{delivery_id}}"
	mustRequest(t, s, "PUT", "/api/notification-operations", map[string]any{"config": cfg, "expected_updated_at": latest["updated_at"]}, admin, 400)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "운영 조회 제한", "scopes": []string{"services:read"}, "expires_days": 1}, admin, 201)
	for _, path := range []string{"/api/notification-operations", "/api/notification-operations/status"} {
		mustRequest(t, s, "GET", path, nil, asString(key["token"]), 403)
	}
}
func TestNotificationOperationsReceiptPollingAndSignedCallbacks(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	var sends, lookups atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-notification-credential" {
			t.Error("missing channel authentication")
		}
		if r.Method == "GET" {
			lookups.Add(1)
			if r.URL.Query().Get("delivery") == "" {
				t.Error("missing delivery correlation")
			}
			fmt.Fprint(w, `{"status":"delivered"}`)
		} else {
			sends.Add(1)
			fmt.Fprint(w, `{}`)
		}
	}))
	defer gateway.Close()
	ch := notificationTestChannel(t, s, admin, gateway.URL+"/send", true)
	p := notificationOperationsPolicy(asString(ch["id"]))
	p.Tracking.Enabled = true
	p.Tracking.Endpoint = gateway.URL + "/receipt"
	p.Tracking.Query = map[string]string{"delivery": "{{delivery_id}}"}
	p.Tracking.CallbackEnabled = true
	p.Tracking.CallbackSecret = strings.Repeat("callback-", 5)
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	id := notificationOperationsDelivery(t, a, s, admin, p.ChannelID)
	if done, err := a.processNotificationDelivery(context.Background()); err != nil || !done {
		t.Fatalf("send %v %v", done, err)
	}
	notificationExec(t, a, `UPDATE notification_receipts SET next_check_at=now() WHERE delivery_id=$1`, id)
	if _, err := a.processNotificationOperations(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_receipts WHERE delivery_id=$1 AND state='delivered'`, id) != 1 || sends.Load() != 1 || lookups.Load() != 1 {
		t.Fatal("receipt did not confirm one accepted delivery")
	}
	input := notificationReceiptInput{EventID: "late-pending", DeliveryID: id, Status: "pending", OccurredAt: time.Now()}
	notificationOperationsCallback(t, s, p.ChannelID, "wrong-secret", input, 401)
	privateID := input
	privateID.EventID = "recipient-is-not-provider-id"
	privateID.ProviderID = "synthetic-internal-recipient"
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, privateID, 400)
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 200)
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 200)
	input.Status = "delivery_failed"
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 409)
	input.EventID = "contradiction"
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 200)
	if notificationCount(t, a, `SELECT count(*) FROM notification_receipts WHERE delivery_id=$1 AND state='conflict'`, id) != 1 {
		t.Fatal("contradictory terminal receipt was trusted")
	}
	allowed, err := a.notificationRetentionAllowed(context.Background(), a.DB, id)
	if err != nil || allowed {
		t.Fatal("conflicting evidence became purgeable")
	}
	if sends.Load() != 1 {
		t.Fatal("callback unexpectedly transmitted a message")
	}
}
func TestNotificationOperationsConfirmedFallbackIsSingleAndCurrent(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	var primary, secondary atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { primary.Add(1); w.WriteHeader(422) }))
	defer source.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { secondary.Add(1); fmt.Fprint(w, `{}`) }))
	defer target.Close()
	ch := notificationTestChannel(t, s, admin, source.URL, true)
	fallback := notificationTestChannel(t, s, admin, target.URL, true)
	p := notificationOperationsPolicy(asString(ch["id"]))
	p.FallbackChannelID = asString(fallback["id"])
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	id := notificationOperationsDelivery(t, a, s, admin, p.ChannelID)
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- a.createNotificationFallback(context.Background(), id) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_fallbacks WHERE parent_id=$1`, id) != 1 {
		t.Fatal("fallback duplicated")
	}
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if primary.Load() != 1 || secondary.Load() != 1 {
		t.Fatalf("send counts %d/%d", primary.Load(), secondary.Load())
	}
	tx, _ := a.DB.Begin(context.Background())
	allowed, err := a.notificationRetryPermitted(context.Background(), tx, id)
	tx.Rollback(context.Background())
	if err != nil || allowed {
		t.Fatal("original delivery could race an existing fallback")
	}
	// A later configuration change revokes the alternative channel mapping.
	var child string
	_ = a.DB.QueryRow(context.Background(), `SELECT child_id FROM notification_fallbacks WHERE parent_id=$1`, id).Scan(&child)
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: false, Channels: []notificationChannelPolicy{p}})
	allowed, err = a.notificationDeliveryChannelAllowed(context.Background(), a.DB, child, p.ChannelID, p.FallbackChannelID)
	if err != nil || allowed {
		t.Fatal("disabled policy kept fallback authorized")
	}
}
func TestNotificationOperationsAmbiguousAcceptanceNeverFallsBack(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(503)
		} else {
			fmt.Fprint(w, `{"status":"unknown"}`)
		}
	}))
	defer gateway.Close()
	ch := notificationTestChannel(t, s, admin, gateway.URL+"/send", true)
	fallback := notificationTestChannel(t, s, admin, gateway.URL+"/fallback", true)
	p := notificationOperationsPolicy(asString(ch["id"]))
	p.FallbackChannelID = asString(fallback["id"])
	p.Tracking.Enabled = true
	p.Tracking.Endpoint = gateway.URL + "/lookup/{{delivery_id}}"
	p.Tracking.MaxChecks = 1
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	id := notificationOperationsDelivery(t, a, s, admin, p.ChannelID)
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notificationState(t, a, id) != "uncertain" {
		t.Fatal("ambiguous HTTP accepted as failure")
	}
	notificationExec(t, a, `UPDATE notification_receipts SET next_check_at=now() WHERE delivery_id=$1`, id)
	if _, err := a.processNotificationOperations(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_fallbacks`) != 0 || notificationCount(t, a, `SELECT count(*) FROM notification_receipts WHERE state='unavailable'`) != 1 {
		t.Fatal("unknown result created fallback")
	}
}
func TestNotificationOperationsCircuitSerializesRecovery(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/unused", true)
	p := notificationOperationsPolicy(asString(ch["id"]))
	p.Protection.Enabled = true
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	for i := 0; i < 2; i++ {
		tx, _ := a.DB.Begin(context.Background())
		allowed, _, err := a.notificationBeforeClaim(context.Background(), tx, p.ChannelID)
		if err != nil || !allowed {
			t.Fatalf("claim %v %v", allowed, err)
		}
		c := &notificationClaim{Channel: NotificationChannel{ID: p.ChannelID}, IsTest: true}
		if err = a.notificationAfterAttempt(context.Background(), tx, c, NotificationSendResult{State: "failed", Code: "422"}, "failed"); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	tx, _ := a.DB.Begin(context.Background())
	allowed, retry, err := a.notificationBeforeClaim(context.Background(), tx, p.ChannelID)
	tx.Rollback(context.Background())
	if err != nil || allowed || !retry.After(time.Now()) {
		t.Fatal("circuit did not open")
	}
	notificationExec(t, a, `UPDATE notification_channel_health SET open_until=now()-interval '1 second' WHERE channel_id=$1`, p.ChannelID)
	var probes atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, e := a.DB.Begin(context.Background())
			if e != nil {
				errs <- e
				return
			}
			defer tx.Rollback(context.Background())
			ok, _, e := a.notificationBeforeClaim(context.Background(), tx, p.ChannelID)
			if e == nil {
				e = tx.Commit(context.Background())
				if ok && e == nil {
					probes.Add(1)
				}
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if probes.Load() != 1 {
		t.Fatalf("recovery reserved %d probes", probes.Load())
	}
}

func TestNotificationOperationsConflictingCallbackStopsQueuedFallback(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	var sends atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sends.Add(1); fmt.Fprint(w, `{}`) }))
	defer gateway.Close()
	ch := notificationTestChannel(t, s, admin, gateway.URL+"/send", true)
	fallback := notificationTestChannel(t, s, admin, gateway.URL+"/fallback", true)
	p := notificationOperationsPolicy(asString(ch["id"]))
	p.FallbackChannelID = asString(fallback["id"])
	p.Tracking.CallbackEnabled = true
	p.Tracking.CallbackSecret = strings.Repeat("callback-", 5)
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	id := notificationOperationsDelivery(t, a, s, admin, p.ChannelID)
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	input := notificationReceiptInput{EventID: "provider-rejected", DeliveryID: id, Status: "delivery_failed", OccurredAt: time.Now()}
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 200)
	if err := a.createNotificationFallback(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	input.EventID = "provider-delivered"
	input.Status = "delivered"
	input.OccurredAt = time.Now()
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 200)
	if notificationCount(t, a, `SELECT count(*) FROM notification_fallbacks f JOIN notification_deliveries d ON d.id=f.child_id WHERE f.parent_id=$1 AND d.status='cancelled'`, id) != 1 {
		t.Fatal("conflicting confirmation left alternate delivery active")
	}
	if _, err := a.processNotificationDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 1 {
		t.Fatal("contradictory provider confirmation sent a second message")
	}
}

func TestFindingDuplicateReportsConflictWithoutCreatingNotification(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	channel := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/unused", true)
	notificationTestRule(t, s, admin, asString(channel["id"]), []string{"finding.created"}, []string{"synthetic-recipient"})
	service := notificationTestService(t, s, admin)
	input := map[string]any{"title": "동일한 합성 취약점", "service_id": service["id"], "severity": "high", "cve": "CVE-2026-12345", "component": "synthetic", "location": "/duplicate-test"}
	mustRequest(t, s, "POST", "/api/findings", input, admin, 200)
	mustRequest(t, s, "POST", "/api/findings", input, admin, 409)
	if notificationCount(t, a, `SELECT count(*) FROM notification_events WHERE event_type='finding.created'`) != 1 {
		t.Fatal("rejected duplicate left an outbox event")
	}
}

func TestNotificationOperationsExpiredAttemptUsesReceiptWithoutResend(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	var queries, posts atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			queries.Add(1)
		} else {
			posts.Add(1)
		}
		fmt.Fprint(w, `{"status":"delivered"}`)
	}))
	defer gateway.Close()
	ch := notificationTestChannel(t, s, admin, gateway.URL+"/send", true)
	p := notificationOperationsPolicy(asString(ch["id"]))
	p.Tracking.Enabled = true
	p.Tracking.Endpoint = gateway.URL + "/receipt/{{delivery_id}}"
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	id := notificationOperationsDelivery(t, a, s, admin, p.ChannelID)
	claim, err := a.claimNotification(context.Background())
	if err != nil || claim == nil {
		t.Fatalf("initial claim %v", err)
	}
	notificationExec(t, a, `UPDATE notification_deliveries SET lease_until=now()-interval '1 minute' WHERE id=$1`, id)
	claim, err = a.claimNotification(context.Background())
	if err != nil || claim != nil {
		t.Fatal("expired attempt was automatically reclaimed")
	}
	if _, err = a.processNotificationOperations(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if notificationState(t, a, id) != "uncertain" || notificationCount(t, a, `SELECT count(*) FROM notification_receipts WHERE delivery_id=$1 AND state='delivered'`, id) != 1 || queries.Load() != 1 || posts.Load() != 0 {
		t.Fatal("expired acceptance did not reconcile through read-only result lookup")
	}
}

func TestNotificationOperationsCallbackBeforeSendResponsePreservesProof(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/unused", true)
	p := notificationOperationsPolicy(asString(ch["id"]))
	p.Tracking.CallbackEnabled = true
	p.Tracking.CallbackSecret = strings.Repeat("callback-", 5)
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	id := notificationOperationsDelivery(t, a, s, admin, p.ChannelID)
	input := notificationReceiptInput{EventID: "too-early", DeliveryID: id, Status: "delivered", ProviderID: "provider-early", OccurredAt: time.Now()}
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 409)
	claim, err := a.claimNotification(context.Background())
	if err != nil || claim == nil {
		t.Fatal(err)
	}
	input.EventID = "while-response-pending"
	input.OccurredAt = time.Now()
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 200)
	if err = a.finishNotification(context.Background(), claim, NotificationSendResult{State: "sent", Code: "200", ProviderID: "provider-early"}); err != nil {
		t.Fatal(err)
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_receipts WHERE delivery_id=$1 AND state='delivered'`, id) != 1 {
		t.Fatal("transport acceptance overwrote earlier delivery proof")
	}
}

func TestNotificationOperationsEarlyFailureDefersFallbackUntilAttemptFinishes(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	ch := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/unused", true)
	fallback := notificationTestChannel(t, s, admin, "http://127.0.0.1:1/fallback", true)
	p := notificationOperationsPolicy(asString(ch["id"]))
	p.FallbackChannelID = asString(fallback["id"])
	p.Tracking.CallbackEnabled = true
	p.Tracking.CallbackSecret = strings.Repeat("callback-", 5)
	notificationOperationsSave(t, s, admin, notificationOperationsConfig{Enabled: true, Channels: []notificationChannelPolicy{p}})
	id := notificationOperationsDelivery(t, a, s, admin, p.ChannelID)
	claim, err := a.claimNotification(context.Background())
	if err != nil || claim == nil {
		t.Fatal(err)
	}
	input := notificationReceiptInput{EventID: "early-failed", DeliveryID: id, Status: "delivery_failed", OccurredAt: time.Now()}
	notificationOperationsCallback(t, s, p.ChannelID, p.Tracking.CallbackSecret, input, 200)
	if err = a.createNotificationFallback(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_receipts WHERE delivery_id=$1 AND fallback_checked`, id) != 0 || notificationCount(t, a, `SELECT count(*) FROM notification_fallbacks WHERE parent_id=$1`, id) != 0 {
		t.Fatal("unfinished attempt consumed or created fallback")
	}
	if err = a.finishNotification(context.Background(), claim, NotificationSendResult{State: "sent", Code: "200"}); err != nil {
		t.Fatal(err)
	}
	if err = a.createNotificationFallback(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if notificationCount(t, a, `SELECT count(*) FROM notification_fallbacks WHERE parent_id=$1`, id) != 1 {
		t.Fatal("confirmed failure lost after acceptance response")
	}
}
