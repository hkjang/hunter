package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type notificationReceiptInput struct {
	EventID    string    `json:"event_id"`
	DeliveryID string    `json:"delivery_id"`
	ProviderID string    `json:"provider_id"`
	Status     string    `json:"status"`
	OccurredAt time.Time `json:"occurred_at"`
}

func notificationReceiptTransition(previous, next string, previousAt *time.Time, at time.Time) (string, bool) {
	if previous == "conflict" {
		return "conflict", false
	}
	if previous == "delivered" || previous == "delivery_failed" {
		if next != "pending" && next != previous {
			return "conflict", true
		}
		return previous, false
	}
	if previousAt != nil && at.Before(*previousAt) {
		return previous, false
	}
	return next, true
}
func (a *App) notificationReceiptCallback(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(raw) > 65536 {
		fail(w, 400, "콜백 크기를 확인하세요")
		return
	}
	stamp := r.Header.Get("X-Hunter-Timestamp")
	seconds, err := strconv.ParseInt(stamp, 10, 64)
	now := time.Now()
	if err != nil || seconds < now.Unix()-300 || seconds > now.Unix()+300 {
		fail(w, 401, "콜백 인증 실패")
		return
	}
	cfg, rev, err := a.notificationOperationsConfig(r.Context(), a.DB)
	p, ok := cfg.channel(r.PathValue("channelID"))
	if err != nil || !cfg.Enabled || !ok || !p.Tracking.CallbackEnabled || p.Tracking.CallbackSecret == "" {
		fail(w, 401, "콜백 인증 실패")
		return
	}
	signature, err := hex.DecodeString(r.Header.Get("X-Hunter-Signature"))
	mac := hmac.New(sha256.New, []byte(p.Tracking.CallbackSecret))
	mac.Write([]byte(stamp + "\n"))
	mac.Write(raw)
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		fail(w, 401, "콜백 인증 실패")
		return
	}
	var in notificationReceiptInput
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF || !notificationReceiptID.MatchString(in.EventID) || !notificationReceiptID.MatchString(in.DeliveryID) || (!hasString([]string{"pending", "delivered", "delivery_failed"}, in.Status)) || in.OccurredAt.IsZero() || in.OccurredAt.After(now.Add(5*time.Minute)) {
		fail(w, 400, "콜백 식별자·상태·발생 시각을 확인하세요")
		return
	}
	ch, err := a.notificationChannel(r.Context(), a.DB, p.ChannelID)
	if err != nil || in.ProviderID != "" && (!notificationSafeReceipt(in.ProviderID, ch, NotificationMessage{}) || strings.Contains(in.ProviderID, p.Tracking.CallbackSecret)) {
		fail(w, 400, "공급자 식별자를 확인하세요")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "콜백 처리 시작 실패")
		return
	}
	defer tx.Rollback(r.Context())
	var previous, provider, payloadCipher string
	var previousAt *time.Time
	var receiptRev, channelRev, createdAt time.Time
	// A gateway can confirm delivery before its send HTTP response reaches us.
	// The signed callback may attach to this already leased attempt, but never to
	// a queued delivery or a historical attempt made before this policy existed.
	_, err = tx.Exec(r.Context(), `INSERT INTO notification_receipts(delivery_id,channel_id,config_revision,channel_revision,state,last_code)
 SELECT d.id,d.channel_id,$3,d.channel_revision,'pending','callback_before_send_response'
 FROM notification_deliveries d WHERE d.id=$1 AND d.channel_id=$2 AND d.channel_revision=$4 AND d.status='sending' AND NOT d.is_test
 AND EXISTS(SELECT 1 FROM notification_attempts t WHERE t.delivery_id=d.id AND t.started_at>=$3 AND t.finished_at IS NULL)
 ON CONFLICT(delivery_id) DO NOTHING`, in.DeliveryID, p.ChannelID, rev, ch.UpdatedAt)
	if err != nil {
		fail(w, 500, "콜백 연결 실패")
		return
	}
	err = tx.QueryRow(r.Context(), `SELECT r.state,r.provider_id,r.occurred_at,r.config_revision,r.channel_revision,d.created_at,d.payload_encrypted FROM notification_receipts r JOIN notification_deliveries d ON d.id=r.delivery_id WHERE r.delivery_id=$1 AND r.channel_id=$2 FOR UPDATE OF r`, in.DeliveryID, p.ChannelID).Scan(&previous, &provider, &previousAt, &receiptRev, &channelRev, &createdAt, &payloadCipher)
	if err != nil || !receiptRev.Equal(rev) || !channelRev.Equal(ch.UpdatedAt) || in.OccurredAt.Before(createdAt.Add(-5*time.Minute)) || (provider != "" && provider != in.ProviderID) {
		fail(w, 409, "현재 전달 이력·설정·공급자 식별자와 일치하지 않습니다")
		return
	}
	// Refresh the payload after the receipt row lock. A retention transaction
	// might have committed while this callback waited on that row.
	if tx.QueryRow(r.Context(), `SELECT payload_encrypted FROM notification_deliveries WHERE id=$1 AND payload_purged_at IS NULL`, in.DeliveryID).Scan(&payloadCipher) != nil {
		fail(w, 409, "본문이 파기된 전달 이력입니다")
		return
	}
	// Apply the same recipient/credential redaction boundary as the send transport.
	var message NotificationMessage
	plain, decodeErr := a.decrypt(payloadCipher)
	if decodeErr != nil || json.Unmarshal([]byte(plain), &message) != nil {
		fail(w, 409, "본문이 파기되었거나 확인할 수 없는 전달 이력입니다")
		return
	}
	if !notificationSafeReceipt(in.EventID, ch, message) || strings.Contains(in.EventID, p.Tracking.CallbackSecret) || in.ProviderID != "" && !notificationSafeReceipt(in.ProviderID, ch, message) {
		fail(w, 400, "콜백에는 수신자·비밀값이 포함되지 않은 식별자를 사용하세요")
		return
	}
	// A concurrent setting update cannot accept a callback under a revoked secret.
	var currentRev time.Time
	if tx.QueryRow(r.Context(), `SELECT updated_at FROM notification_operations_config WHERE id FOR SHARE`).Scan(&currentRev) != nil || !currentRev.Equal(rev) {
		fail(w, 409, "콜백 설정이 변경되었습니다")
		return
	}
	canonical, _ := json.Marshal(in)
	digest := sha256.Sum256(canonical)
	hash := hex.EncodeToString(digest[:])
	var oldHash string
	e := tx.QueryRow(r.Context(), `SELECT payload_hash FROM notification_receipt_events WHERE channel_id=$1 AND event_id=$2`, p.ChannelID, in.EventID).Scan(&oldHash)
	if e == nil {
		if oldHash != hash {
			fail(w, 409, "동일한 콜백 이벤트의 내용이 다릅니다")
			return
		}
		jsonResponse(w, 200, map[string]any{"ok": true, "duplicate": true})
		return
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		fail(w, 500, "콜백 중복 확인 실패")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO notification_receipt_events(channel_id,event_id,delivery_id,payload_hash,state,occurred_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, p.ChannelID, in.EventID, in.DeliveryID, hash, in.Status, in.OccurredAt)
	if err != nil {
		fail(w, 500, "콜백 기록 실패")
		return
	}
	// Check the winning insert as channel-wide event IDs may race on different deliveries.
	if tx.QueryRow(r.Context(), `SELECT payload_hash FROM notification_receipt_events WHERE channel_id=$1 AND event_id=$2`, p.ChannelID, in.EventID).Scan(&oldHash) != nil || oldHash != hash {
		fail(w, 409, "콜백 이벤트 식별자가 이미 사용되었습니다")
		return
	}
	state, changed := notificationReceiptTransition(previous, in.Status, previousAt, in.OccurredAt)
	if changed {
		_, err = tx.Exec(r.Context(), `UPDATE notification_receipts SET state=$2,provider_id=CASE WHEN provider_id='' THEN $3 ELSE provider_id END,occurred_at=$4,last_code='signed_callback',lease_token=NULL,lease_until=NULL,updated_at=now() WHERE delivery_id=$1`, in.DeliveryID, state, in.ProviderID, in.OccurredAt)
	}
	if err == nil && changed {
		err = a.cancelNotificationFallbackOnReceipt(r.Context(), tx, in.DeliveryID, state)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "콜백 반영 실패")
		return
	}
	jsonResponse(w, 200, map[string]any{"ok": true, "state": state})
}
func (a *App) cancelNotificationFallbackOnReceipt(ctx context.Context, tx pgx.Tx, id, state string) error {
	if state != "delivered" && state != "conflict" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET cancel_requested=true,status=CASE WHEN status IN('queued','retry') THEN 'cancelled' ELSE status END,updated_at=now() WHERE id IN(SELECT child_id FROM notification_fallbacks WHERE parent_id=$1) AND status IN('queued','retry','sending')`, id)
	return err
}
func notificationTrackingBody(t notificationTracking, providerID, deliveryID string) ([]byte, error) {
	var walk func(any) (any, error)
	walk = func(v any) (any, error) {
		switch x := v.(type) {
		case string:
			for k, value := range map[string]string{"provider_id": providerID, "delivery_id": deliveryID} {
				if strings.Contains(x, "{{"+k+"}}") && value == "" {
					return nil, errors.New("missing identifier")
				}
				x = strings.ReplaceAll(x, "{{"+k+"}}", value)
			}
			if strings.Contains(x, "{{") {
				return nil, errors.New("unknown variable")
			}
			return x, nil
		case map[string]any:
			out := map[string]any{}
			for k, val := range x {
				next, e := walk(val)
				if e != nil {
					return nil, e
				}
				out[k] = next
			}
			return out, nil
		case []any:
			out := []any{}
			for _, val := range x {
				next, e := walk(val)
				if e != nil {
					return nil, e
				}
				out = append(out, next)
			}
			return out, nil
		default:
			return v, nil
		}
	}
	value, err := walk(t.BodyTemplate)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
func (a *App) pollNotificationReceipt(ctx context.Context, ch NotificationChannel, t notificationTracking, providerID, deliveryID string) (string, string) {
	endpoint, err := notificationTrackingURL(t, providerID, deliveryID)
	origin, e := url.Parse(str(ch.Config, "endpoint"))
	if err != nil || e != nil || endpoint.Scheme != origin.Scheme || !strings.EqualFold(endpoint.Host, origin.Host) {
		return "unavailable", "lookup_endpoint"
	}
	body, err := notificationTrackingBody(t, providerID, deliveryID)
	if err != nil {
		return "unavailable", "lookup_identifier"
	}
	if t.Method == "GET" {
		body = nil
	}
	req, err := http.NewRequestWithContext(ctx, t.Method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return "unavailable", "lookup_endpoint"
	}
	req.GetBody = nil
	headers, err := notificationHeaders(ch.Config["headers"])
	if err != nil {
		return "unavailable", "lookup_headers"
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	if t.Method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	if applyNotificationHTTPAuth(req, ch) != nil {
		return "unavailable", "lookup_credentials"
	}
	client, err := a.outboundClient(ctx, notificationTimeout(ch.Config))
	if err != nil {
		return "unavailable", "lookup_ca"
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return "pending", "lookup_connection"
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "pending", "lookup_http_" + strconv.Itoa(resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	var value any
	if err != nil || len(raw) > 65536 || json.Unmarshal(raw, &value) != nil {
		return "pending", "lookup_response"
	}
	field, ok := notificationResponseValue(value, t.StatePath)
	if !ok {
		return "pending", "lookup_missing_state"
	}
	s := fmt.Sprint(field)
	if hasString(t.DeliveredValues, s) {
		return "delivered", "provider_confirmed"
	}
	if hasString(t.FailedValues, s) {
		return "delivery_failed", "provider_confirmed"
	}
	if hasString(t.PendingValues, s) {
		return "pending", "provider_pending"
	}
	return "pending", "lookup_unknown_state"
}
func (a *App) processOneNotificationReceipt(ctx context.Context, now time.Time) (bool, error) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id, channel, provider string
	var receiptRev, channelRev time.Time
	var checks int
	err = tx.QueryRow(ctx, `SELECT delivery_id,channel_id,provider_id,config_revision,channel_revision,checks FROM notification_receipts WHERE state='pending' AND next_check_at<=$1 AND (lease_until IS NULL OR lease_until<$1) ORDER BY next_check_at LIMIT 1 FOR UPDATE SKIP LOCKED`, now).Scan(&id, &channel, &provider, &receiptRev, &channelRev, &checks)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	cfg, rev, err := a.notificationOperationsConfig(ctx, tx)
	if err != nil {
		return false, err
	}
	p, ok := cfg.channel(channel)
	ch, readErr := a.notificationChannel(ctx, tx, channel)
	if !cfg.Enabled || !ok || !p.Tracking.Enabled || !receiptRev.Equal(rev) || readErr != nil || !ch.UpdatedAt.Equal(channelRev) || checks >= p.Tracking.MaxChecks {
		_, err = tx.Exec(ctx, `UPDATE notification_receipts SET state='unavailable',next_check_at=NULL,last_code='lookup_inactive_or_exhausted',updated_at=now() WHERE delivery_id=$1`, id)
		if err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}
	token := newID()
	_, err = tx.Exec(ctx, `UPDATE notification_receipts SET lease_token=$2,lease_until=$3,checks=checks+1 WHERE delivery_id=$1`, id, token, now.Add(2*time.Minute))
	if err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, notificationTimeout(ch.Config))
	state, code := a.pollNotificationReceipt(queryCtx, ch, p.Tracking, provider, id)
	cancel()
	// Exhausted or indeterminate lookups never create delivery-failure evidence.
	if state == "pending" && checks+1 >= p.Tracking.MaxChecks {
		state = "unavailable"
		code = "lookup_exhausted"
	}
	finish, err := a.DB.Begin(ctx)
	if err != nil {
		return true, err
	}
	defer finish.Rollback(ctx)
	var latestRev time.Time
	if err = finish.QueryRow(ctx, `SELECT updated_at FROM notification_operations_config WHERE id FOR SHARE`).Scan(&latestRev); err != nil {
		return true, err
	}
	var latestChannelRev time.Time
	if err = finish.QueryRow(ctx, `SELECT updated_at FROM notification_channels WHERE id=$1`, channel).Scan(&latestChannelRev); err != nil {
		return true, err
	}
	if !latestRev.Equal(rev) || !latestChannelRev.Equal(channelRev) {
		state = "unavailable"
		code = "lookup_configuration_changed"
	}
	tag, err := finish.Exec(ctx, `UPDATE notification_receipts SET state=$3,last_code=$4,next_check_at=$5,occurred_at=now(),lease_token=NULL,lease_until=NULL,updated_at=now() WHERE delivery_id=$1 AND lease_token=$2 AND state='pending'`, id, token, state, code, time.Now().Add(time.Duration(p.Tracking.PollIntervalSeconds)*time.Second))
	if err != nil {
		return true, err
	}
	if tag.RowsAffected() > 0 {
		if err = a.cancelNotificationFallbackOnReceipt(ctx, finish, id, state); err != nil {
			return true, err
		}
	}
	return true, finish.Commit(ctx)
}
func (a *App) processNotificationOperations(ctx context.Context, now time.Time) (map[string]int64, error) {
	counts := map[string]int64{"receipt_checks": 0, "fallback_checks": 0}
	if err := a.recoverNotificationReceipts(ctx, now); err != nil {
		return counts, err
	}
	for i := 0; i < 4; i++ {
		processed, err := a.processOneNotificationReceipt(ctx, now)
		if err != nil {
			return counts, err
		}
		if !processed {
			break
		}
		counts["receipt_checks"]++
	}
	rows, err := a.DB.Query(ctx, `SELECT delivery_id FROM notification_receipts WHERE state='delivery_failed' AND NOT fallback_checked ORDER BY updated_at LIMIT 20`)
	if err != nil {
		return counts, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err != nil {
		return counts, err
	}
	if rows.Err() != nil {
		return counts, rows.Err()
	}
	for _, id := range ids {
		if err = a.createNotificationFallback(ctx, id); err != nil {
			return counts, err
		}
		counts["fallback_checks"]++
	}
	return counts, nil
}

// A process can disappear after a provider accepts a request but before the
// finish transaction records it. Reconcile the existing delivery identifier;
// never convert the expired attempt into a new outbound send.
func (a *App) recoverNotificationReceipts(ctx context.Context, now time.Time) error {
	cfg, rev, err := a.notificationOperationsConfig(ctx, a.DB)
	if err != nil || !cfg.Enabled {
		return err
	}
	for _, p := range cfg.Channels {
		if !p.Tracking.Enabled && !p.Tracking.CallbackEnabled {
			continue
		}
		var next any
		if p.Tracking.Enabled {
			next = now
		}
		_, err = a.DB.Exec(ctx, `INSERT INTO notification_receipts(delivery_id,channel_id,config_revision,channel_revision,state,provider_id,next_check_at,last_code)
 SELECT d.id,d.channel_id,$2,d.channel_revision,'pending',d.provider_id,$3,'expired_attempt_reconciliation'
 FROM notification_deliveries d JOIN notification_channels c ON c.id=d.channel_id AND c.updated_at=d.channel_revision
 WHERE d.channel_id=$1 AND d.status='uncertain' AND NOT d.is_test AND NOT d.cancel_requested AND d.payload_purged_at IS NULL
 AND EXISTS(SELECT 1 FROM notification_attempts t WHERE t.delivery_id=d.id AND t.started_at>=$2)
 AND NOT EXISTS(SELECT 1 FROM notification_receipts r WHERE r.delivery_id=d.id)
 ORDER BY d.updated_at LIMIT 20 ON CONFLICT(delivery_id) DO NOTHING`, p.ChannelID, rev, next)
		if err != nil {
			return err
		}
	}
	return nil
}
