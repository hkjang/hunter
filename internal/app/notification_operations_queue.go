package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// A circuit reserves only an existing authorized delivery. It never creates a
// synthetic probe message or replays a delivery whose acceptance is unknown.
func (a *App) notificationBeforeClaim(ctx context.Context, tx pgx.Tx, channelID string) (bool, time.Time, error) {
	cfg, rev, err := a.notificationOperationsConfig(ctx, tx)
	if err != nil {
		return false, time.Time{}, err
	}
	p, ok := cfg.channel(channelID)
	if !cfg.Enabled || !ok || !p.Protection.Enabled {
		return true, time.Time{}, nil
	}
	now := time.Now()
	_, err = tx.Exec(ctx, `INSERT INTO notification_channel_health(channel_id,config_revision) VALUES($1,$2) ON CONFLICT(channel_id) DO UPDATE SET config_revision=EXCLUDED.config_revision,state='closed',consecutive_failures=0,open_until=NULL,next_allowed_at=NULL,updated_at=now() WHERE notification_channel_health.config_revision<>EXCLUDED.config_revision`, channelID, rev)
	if err != nil {
		return false, time.Time{}, err
	}
	var state string
	var open, next *time.Time
	err = tx.QueryRow(ctx, `SELECT state,open_until,next_allowed_at FROM notification_channel_health WHERE channel_id=$1 FOR UPDATE`, channelID).Scan(&state, &open, &next)
	if err != nil {
		return false, time.Time{}, err
	}
	retry := now
	if next != nil && next.After(retry) {
		retry = *next
	}
	if (state == "open" || state == "half_open") && open != nil && open.After(retry) {
		retry = *open
	}
	if retry.After(now) {
		return false, retry, nil
	}
	var until any
	if state != "closed" {
		state = "half_open"
		until = now.Add(2 * time.Minute)
	}
	_, err = tx.Exec(ctx, `UPDATE notification_channel_health SET state=$2,open_until=$3,next_allowed_at=$4,updated_at=now() WHERE channel_id=$1`, channelID, state, until, now.Add(time.Duration(p.Protection.MinIntervalSeconds)*time.Second))
	return err == nil, time.Time{}, err
}
func notificationConfirmedFailure(result NotificationSendResult, finalState string) bool {
	code, err := strconv.Atoi(result.Code)
	// Retry exhaustion and unknown acceptance are never evidence of rejection.
	return finalState == "failed" && result.State == "failed" && err == nil && code >= 200 && code <= 599
}
func (a *App) notificationAfterAttempt(ctx context.Context, tx pgx.Tx, c *notificationClaim, result NotificationSendResult, finalState string) error {
	cfg, rev, err := a.notificationOperationsConfig(ctx, tx)
	if err != nil {
		return err
	}
	p, ok := cfg.channel(c.Channel.ID)
	if !cfg.Enabled || !ok {
		return nil
	}
	if p.Protection.Enabled && result.Code != "" && finalState != "cancelled" {
		success := finalState == "sent"
		var state string
		var n int
		err = tx.QueryRow(ctx, `SELECT state,consecutive_failures FROM notification_channel_health WHERE channel_id=$1 AND config_revision=$2 FOR UPDATE`, c.Channel.ID, rev).Scan(&state, &n)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			var until any
			if success {
				n = 0
				state = "closed"
			} else {
				n++
				if state == "half_open" || n >= p.Protection.ConsecutiveFailures {
					state = "open"
					until = time.Now().Add(time.Duration(p.Protection.OpenSeconds) * time.Second)
				}
			}
			if _, err = tx.Exec(ctx, `UPDATE notification_channel_health SET state=$2,consecutive_failures=$3,open_until=$4,updated_at=now() WHERE channel_id=$1`, c.Channel.ID, state, n, until); err != nil {
				return err
			}
		}
	}
	if c.IsTest {
		return nil
	}
	state := "pending"
	code := "awaiting_receipt"
	if notificationConfirmedFailure(result, finalState) {
		state = "delivery_failed"
		code = "transport_rejected"
	} else if finalState != "sent" && finalState != "uncertain" {
		return nil
	}
	if !p.Tracking.Enabled && !p.Tracking.CallbackEnabled && p.FallbackChannelID == "" {
		return nil
	}
	if state == "pending" && !p.Tracking.Enabled && !p.Tracking.CallbackEnabled {
		state = "unavailable"
		code = "tracking_disabled"
	}
	var next any
	if state == "pending" && p.Tracking.Enabled {
		next = time.Now().Add(time.Duration(p.Tracking.PollIntervalSeconds) * time.Second)
	}
	_, err = tx.Exec(ctx, `INSERT INTO notification_receipts(delivery_id,channel_id,config_revision,channel_revision,state,provider_id,next_check_at,last_code,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()) ON CONFLICT(delivery_id) DO UPDATE SET
 state=CASE WHEN notification_receipts.provider_id<>'' AND EXCLUDED.provider_id<>'' AND notification_receipts.provider_id<>EXCLUDED.provider_id THEN 'conflict'
 WHEN notification_receipts.state='delivered' AND EXCLUDED.state='delivery_failed' THEN 'conflict'
 WHEN notification_receipts.state IN('delivered','delivery_failed','conflict') THEN notification_receipts.state ELSE EXCLUDED.state END,
 provider_id=CASE WHEN notification_receipts.provider_id='' THEN EXCLUDED.provider_id ELSE notification_receipts.provider_id END,
 next_check_at=EXCLUDED.next_check_at,updated_at=now()
 WHERE notification_receipts.config_revision=EXCLUDED.config_revision AND notification_receipts.channel_revision=EXCLUDED.channel_revision`, c.ID, c.Channel.ID, rev, c.Channel.UpdatedAt, state, result.ProviderID, next, code)
	return err
}
func (a *App) notificationDeliveryChannelAllowed(ctx context.Context, q notificationQuerier, deliveryID, ruleChannelID, actualChannelID string) (bool, error) {
	if ruleChannelID == actualChannelID {
		return true, nil
	}
	cfg, rev, err := a.notificationOperationsConfig(ctx, q)
	if err != nil {
		return false, err
	}
	p, ok := cfg.channel(ruleChannelID)
	if !cfg.Enabled || !ok || p.FallbackChannelID != actualChannelID {
		return false, nil
	}
	var allowed bool
	err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_fallbacks f JOIN notification_deliveries p ON p.id=f.parent_id JOIN notification_receipts r ON r.delivery_id=p.id WHERE f.child_id=$1 AND p.channel_id=$2 AND f.config_revision=$3 AND r.state='delivery_failed' AND NOT p.cancel_requested AND p.payload_purged_at IS NULL)`, deliveryID, ruleChannelID, rev).Scan(&allowed)
	return allowed, err
}
func (a *App) notificationRetryPermitted(ctx context.Context, tx pgx.Tx, id string) (bool, error) {
	var denied bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_fallbacks WHERE parent_id=$1) OR EXISTS(SELECT 1 FROM notification_receipts WHERE delivery_id=$1 AND state IN('pending','unavailable','delivered','delivery_failed','conflict'))`, id).Scan(&denied)
	return !denied, err
}
func (a *App) notificationMemberSource(ctx context.Context, q notificationQuerier, id string) (string, error) {
	var parent string
	err := q.QueryRow(ctx, `SELECT parent_id FROM notification_fallbacks WHERE child_id=$1`, id).Scan(&parent)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, nil
	}
	return parent, err
}

func (a *App) notificationOperationsStatus(w http.ResponseWriter, r *http.Request) {
	result := map[string]any{}
	for _, spec := range []struct{ key, sql string }{
		{"channels", `SELECT channel_id,state,consecutive_failures,open_until,next_allowed_at,updated_at FROM notification_channel_health ORDER BY updated_at DESC LIMIT 200`},
		{"receipts", `SELECT delivery_id,channel_id,state,checks,provider_id,last_code,next_check_at,updated_at FROM notification_receipts ORDER BY updated_at DESC LIMIT 100`},
		{"fallbacks", `SELECT parent_id,child_id,created_at FROM notification_fallbacks ORDER BY created_at DESC LIMIT 100`},
	} {
		rows, err := a.DB.Query(r.Context(), spec.sql)
		if err != nil {
			fail(w, 500, "알림 운영 상태 조회 실패")
			return
		}
		items := []map[string]any{}
		fields := rows.FieldDescriptions()
		for rows.Next() {
			values, e := rows.Values()
			if e != nil {
				err = e
				break
			}
			item := map[string]any{}
			for i, v := range values {
				item[fields[i].Name] = v
			}
			items = append(items, item)
		}
		rows.Close()
		if err != nil || rows.Err() != nil {
			fail(w, 500, "알림 운영 상태 조회 실패")
			return
		}
		result[spec.key] = items
	}
	jsonResponse(w, 200, result)
}
func (a *App) resetNotificationCircuit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if notificationDecode(r, &in) != nil || len(in.Reason) < 8 || len(in.Reason) > 1000 {
		fail(w, 400, "보호 해제 사유를 8~1000바이트로 입력하세요")
		return
	}
	tag, err := a.DB.Exec(r.Context(), `UPDATE notification_channel_health SET state='closed',consecutive_failures=0,open_until=NULL,next_allowed_at=NULL,updated_at=now() WHERE channel_id=$1`, r.PathValue("id"))
	if err != nil {
		fail(w, 500, "채널 보호 해제 실패")
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "채널 보호 상태가 없습니다")
		return
	}
	a.audit(r, "notification_circuit.reset", r.PathValue("id"), map[string]any{"reason": notificationText(in.Reason, 1000)})
	jsonResponse(w, 200, map[string]bool{"ok": true})
}
func (a *App) refreshNotificationReceipt(w http.ResponseWriter, r *http.Request) {
	cfg, rev, err := a.notificationOperationsConfig(r.Context(), a.DB)
	if err != nil {
		fail(w, 500, "운영 설정 조회 실패")
		return
	}
	var channel string
	err = a.DB.QueryRow(r.Context(), `SELECT channel_id FROM notification_receipts WHERE delivery_id=$1`, r.PathValue("id")).Scan(&channel)
	p, ok := cfg.channel(channel)
	if err != nil || !cfg.Enabled || !ok || !p.Tracking.Enabled {
		fail(w, 409, "현재 활성화된 전달 결과 조회 설정이 없습니다")
		return
	}
	tag, err := a.DB.Exec(r.Context(), `UPDATE notification_receipts SET state='pending',checks=0,next_check_at=now(),last_code='manual_refresh',updated_at=now() WHERE delivery_id=$1 AND config_revision=$2 AND state IN('pending','unavailable') AND (lease_until IS NULL OR lease_until<now())`, r.PathValue("id"), rev)
	if err != nil {
		fail(w, 500, "결과 조회 예약 실패")
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 409, "확정·충돌 결과 또는 변경된 설정의 이력은 다시 조회할 수 없습니다")
		return
	}
	a.audit(r, "notification_receipt.refresh", r.PathValue("id"), nil)
	jsonResponse(w, 202, map[string]bool{"ok": true})
}

// Fallback is durable and unique per original delivery. The original rule,
// current recipient authorization and all member checks remain in the normal
// queue path; an alternate channel never creates a new authorization grant.
func (a *App) createNotificationFallback(ctx context.Context, id string) error {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var state, channel string
	var receiptRev time.Time
	var checked bool
	err = tx.QueryRow(ctx, `SELECT state,channel_id,config_revision,fallback_checked FROM notification_receipts WHERE delivery_id=$1 FOR UPDATE`, id).Scan(&state, &channel, &receiptRev, &checked)
	if err != nil {
		return err
	}
	if checked || state != "delivery_failed" {
		return nil
	}
	cfg, rev, err := a.notificationOperationsConfig(ctx, tx)
	if err != nil {
		return err
	}
	p, ok := cfg.channel(channel)
	_, err = tx.Exec(ctx, `UPDATE notification_receipts SET fallback_checked=true WHERE delivery_id=$1`, id)
	if err != nil {
		return err
	}
	skip := !cfg.Enabled || !ok || !rev.Equal(receiptRev) || p.FallbackChannelID == ""
	var fromFallback bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_fallbacks WHERE child_id=$1 OR parent_id=$1)`, id).Scan(&fromFallback); err != nil {
		return err
	}
	if skip || fromFallback {
		return tx.Commit(ctx)
	}
	var c notificationClaim
	var cipher string
	var recipientUser string
	var autoRev, ackDue, ackAt *time.Time
	var hold bool
	var oldRevision time.Time
	err = tx.QueryRow(ctx, `SELECT rule_id,rule_revision,event_type,entity_id,service_id,payload_encrypted,channel_revision,recipient_user_id,automation_revision,ack_due_at,acknowledged_at,retention_hold FROM notification_deliveries WHERE id=$1 AND NOT is_test AND NOT cancel_requested AND payload_purged_at IS NULL AND status IN('failed','sent','uncertain') FOR UPDATE`, id).Scan(&c.RuleID, &c.RuleRevision, &c.EventType, &c.EntityID, &c.ServiceID, &cipher, &oldRevision, &recipientUser, &autoRev, &ackDue, &ackAt, &hold)
	if errors.Is(err, pgx.ErrNoRows) {
		var stillSending bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_deliveries WHERE id=$1 AND status='sending')`, id).Scan(&stillSending); e != nil {
			return e
		}
		if stillSending {
			return nil
		} // Roll back the checked flag until the send response is recorded.
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	original, err := a.notificationChannel(ctx, tx, channel)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	fallback, err := a.notificationChannel(ctx, tx, p.FallbackChannelID)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	if ackAt != nil || !original.Enabled || !fallback.Enabled || !original.UpdatedAt.Equal(oldRevision) || notificationChannelFamily(original.Type) != notificationChannelFamily(fallback.Type) {
		return tx.Commit(ctx)
	}
	rule, err := a.notificationRule(ctx, tx, c.RuleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	if !rule.Enabled || c.RuleRevision == nil || !rule.UpdatedAt.Equal(*c.RuleRevision) || rule.ChannelID != channel {
		return tx.Commit(ctx)
	}
	plain, err := a.decrypt(cipher)
	if err != nil {
		return err
	}
	var msg NotificationMessage
	if err = json.Unmarshal([]byte(plain), &msg); err != nil {
		return err
	}
	msg.DeliveryID = newID()
	raw, _ := json.Marshal(msg)
	encrypted, err := a.encrypt(string(raw))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO notification_deliveries(id,event_type,entity_id,service_id,rule_id,rule_name,rule_revision,channel_id,channel_name,channel_type,channel_revision,payload_encrypted,recipient_hash,max_attempts,recipient_user_id,automation_revision,ack_due_at,acknowledged_at,retention_hold)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, msg.DeliveryID, c.EventType, c.EntityID, c.ServiceID, rule.ID, rule.Name, rule.UpdatedAt, fallback.ID, fallback.Name, fallback.Type, fallback.UpdatedAt, encrypted, a.notificationHash(msg.Recipient), rule.MaxAttempts, recipientUser, autoRev, ackDue, ackAt, hold)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO notification_fallbacks(parent_id,child_id,config_revision) VALUES($1,$2,$3)`, id, msg.DeliveryID, rev)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Preserve pending evidence and the original member authorization source until
// every fallback has stopped. Durable callback and fallback dedupe markers stay.
func (a *App) notificationRetentionAllowed(ctx context.Context, q notificationQuerier, id string) (bool, error) {
	// Serialize terminal-evidence checks with callbacks and provider polling.
	if tx, ok := q.(pgx.Tx); ok {
		rows, err := tx.Query(ctx, `SELECT r.delivery_id FROM notification_receipts r WHERE r.delivery_id=$1 OR EXISTS(SELECT 1 FROM notification_fallbacks f WHERE f.parent_id=$1 AND f.child_id=r.delivery_id) ORDER BY r.delivery_id FOR UPDATE OF r`, id)
		if err != nil {
			return false, err
		}
		for rows.Next() {
		}
		rows.Close()
		if rows.Err() != nil {
			return false, rows.Err()
		}
	}
	var blocked bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_receipts WHERE delivery_id=$1 AND state IN('pending','unavailable','conflict')) OR EXISTS(SELECT 1 FROM notification_fallbacks f JOIN notification_deliveries d ON d.id=f.child_id LEFT JOIN notification_receipts r ON r.delivery_id=d.id WHERE f.parent_id=$1 AND (d.status IN('queued','retry','sending','uncertain') OR r.state IN('pending','unavailable','conflict')))`, id).Scan(&blocked)
	return !blocked, err
}
