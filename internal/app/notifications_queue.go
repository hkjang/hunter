package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type notificationEvent struct {
	ID                        int64
	Type, EntityID, ServiceID string
	Revision, CreatedAt       time.Time
	Metadata                  map[string]any
	RuleCursor                string
}

var errNotificationTargetChanged = errors.New("알림 대상 서비스가 변경되었습니다")

func (a *App) notificationVariablesFor(ctx context.Context, q notificationQuerier, e notificationEvent) (map[string]string, domainResource, domainResource, error) {
	entity, err := scanResource(q.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE id=$1 AND kind IN('findings','scans','approvals','services')`, e.EntityID))
	if err != nil {
		return nil, entity, domainResource{}, err
	}
	parentID := str(entity.Data, "service_id")
	if entity.Kind == "services" {
		parentID = entity.ID
	}
	service, err := scanResource(q.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind='services' AND id=$1`, parentID))
	if err != nil {
		return nil, entity, service, err
	}
	if service.ID != e.ServiceID {
		return nil, entity, service, errNotificationTargetChanged
	}
	vars := map[string]string{}
	for _, k := range notificationVariables {
		vars[k] = ""
	}
	vars["event.type"] = e.Type
	vars["event.label"] = notificationEventLabel(e.Type)
	vars["event.time"] = e.CreatedAt.UTC().Format(time.RFC3339)
	vars["service.id"] = service.ID
	vars["service.name"] = str(service.Data, "name")
	vars["service.team"] = str(service.Data, "team")
	vars["resource.id"] = entity.ID
	title := str(entity.Data, "title")
	if title == "" {
		title = str(entity.Data, "name")
	}
	vars["resource.title"] = title
	vars["resource.status"] = str(entity.Data, "status")
	prefix := strings.TrimSuffix(entity.Kind, "s")
	if e.Type == "team.weekly" {
		vars["resource.title"] = str(service.Data, "team") + " 주간 보안 현황"
	}
	for _, k := range []string{"id", "title", "name", "severity", "status", "due_date", "assignee", "cve"} {
		key := prefix + "." + k
		if _, ok := vars[key]; ok {
			if k == "id" {
				vars[key] = entity.ID
			} else {
				vars[key] = str(entity.Data, k)
			}
		}
	}
	// The status/severity that caused the event remain distinguishable from later changes.
	for _, k := range []string{"status", "severity"} {
		if value := str(e.Metadata, k); value != "" {
			if _, ok := vars[prefix+"."+k]; ok {
				vars[prefix+"."+k] = value
			}
			if k == "status" {
				vars["resource.status"] = value
			}
		}
	}
	if due := str(e.Metadata, "due_date"); due != "" {
		vars["finding.due_date"] = due
	}
	vars["resource.status_label"] = notificationStatusLabel(vars["resource.status"])
	vars["finding.severity_label"] = map[string]string{"critical": "치명적", "high": "높음", "medium": "보통", "low": "낮음", "info": "정보"}[vars["finding.severity"]]
	general, err := notificationSetting(ctx, q, "general")
	if err != nil {
		return nil, entity, service, err
	}
	base := str(general, "public_url")
	if validURL(base) {
		vars["resource.url"] = strings.TrimRight(base, "/") + "/" + entity.Kind + "?item=" + url.QueryEscape(entity.ID)
	}
	for k, v := range vars {
		vars[k] = notificationText(v, 1000)
	}
	return vars, entity, service, nil
}
func notificationMatches(rule notificationRule, entity, service domainResource) bool {
	if !rule.Enabled {
		return false
	}
	f := rule.Filters
	if len(f.ServiceIDs) > 0 && !hasString(f.ServiceIDs, service.ID) {
		return false
	}
	if len(f.Teams) > 0 && !hasString(f.Teams, str(service.Data, "team")) {
		return false
	}
	if len(f.Severities) > 0 && !hasString(f.Severities, str(entity.Data, "severity")) {
		return false
	}
	return true
}
func (a *App) notificationHash(s string) string {
	sum := hmac.New(sha256.New, a.Key)
	sum.Write([]byte("hunter-notification-recipient\x00" + strings.ToLower(s)))
	return hex.EncodeToString(sum.Sum(nil))
}
func (a *App) enqueueNotificationRaw(ctx context.Context, tx pgx.Tx, e notificationEvent, rule notificationRule, channel NotificationChannel, msg NotificationMessage, isTest bool, u User) (string, error) {
	msg.DeliveryID = newID()
	if e.ID != 0 {
		msg.EventID = strconv.FormatInt(e.ID, 10)
	}
	raw, _ := json.Marshal(msg)
	cipher, err := a.encrypt(string(raw))
	if err != nil {
		return "", err
	}
	var eventID any
	var revision any
	if e.ID != 0 {
		eventID = e.ID
	}
	if rule.ID != "" {
		revision = rule.UpdatedAt
	}
	maxAttempts := rule.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 3
	}
	tag, err := tx.Exec(ctx, `INSERT INTO notification_deliveries(id,event_id,event_type,entity_id,service_id,rule_id,rule_name,rule_revision,channel_id,channel_name,channel_type,channel_revision,payload_encrypted,recipient_hash,max_attempts,is_test,requested_by,credential_key_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT(event_id,rule_id,recipient_hash) DO NOTHING`, msg.DeliveryID, eventID, e.Type, e.EntityID, e.ServiceID, rule.ID, rule.Name, revision, channel.ID, channel.Name, channel.Type, channel.UpdatedAt, cipher, a.notificationHash(msg.Recipient), maxAttempts, isTest, u.ID, u.KeyID)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", nil
	}
	return msg.DeliveryID, nil
}

// Transactional trigger records all committed source events. This fan-out locks
// pending rows rather than using a sequence cursor, so commit order cannot skip events.
func (a *App) processNotificationOutbox(ctx context.Context) (int, error) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id,event_type,entity_id,service_id,source_revision,metadata,created_at,rule_cursor FROM notification_events WHERE status='pending' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return 0, err
	}
	events := []notificationEvent{}
	for rows.Next() {
		var e notificationEvent
		var raw []byte
		if err = rows.Scan(&e.ID, &e.Type, &e.EntityID, &e.ServiceID, &e.Revision, &raw, &e.CreatedAt, &e.RuleCursor); err != nil {
			break
		}
		if err = json.Unmarshal(raw, &e.Metadata); err != nil {
			break
		}
		events = append(events, e)
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	if rows.Err() != nil {
		return 0, rows.Err()
	}
	for _, e := range events {
		complete := true
		vars, entity, service, readErr := a.notificationVariablesFor(ctx, tx, e)
		if readErr == nil {
			eligible, checkErr := notificationEventCurrent(ctx, tx, e.Type, entity, time.Now())
			if checkErr != nil {
				return 0, checkErr
			}
			if eligible {
				eligible, checkErr = a.notificationAutomationEventCurrent(ctx, tx, e, entity)
				if checkErr != nil {
					return 0, checkErr
				}
			}
			if !eligible {
				readErr = errNotificationTargetChanged
			}
		}
		if readErr == nil {
			rr, er := tx.Query(ctx, `SELECT id FROM notification_rules WHERE enabled AND events ? $1 AND updated_at<=$2 AND id>$3 ORDER BY id LIMIT 5`, e.Type, e.CreatedAt, e.RuleCursor)
			if er != nil {
				return 0, er
			}
			ids := []string{}
			for rr.Next() {
				var id string
				if er = rr.Scan(&id); er != nil {
					break
				}
				ids = append(ids, id)
			}
			rr.Close()
			if er != nil {
				return 0, er
			}
			if rr.Err() != nil {
				return 0, rr.Err()
			}
			complete = len(ids) < 5
			for _, id := range ids {
				e.RuleCursor = id
				rule, er := a.notificationRule(ctx, tx, id)
				if er != nil {
					return 0, er
				}
				if !notificationMatches(rule, entity, service) {
					continue
				}
				channel, er := a.notificationChannel(ctx, tx, rule.ChannelID)
				if er != nil {
					return 0, er
				}
				if !channel.Enabled || channel.UpdatedAt.After(e.CreatedAt) {
					continue
				}
				cfg, _, er := a.notificationAutomationConfig(ctx, tx)
				if er != nil {
					return 0, er
				}
				targets, er := a.notificationTargets(ctx, tx, cfg, rule, channel, entity, service, time.Now())
				if errors.Is(er, errNotificationRecipientLimit) {
					// A bad rule must not stall later durable events. Record an explicit,
					// never-send cancellation with zero recipients instead of partial fanout.
					id, recordErr := a.enqueueNotificationRaw(ctx, tx, e, rule, channel, NotificationMessage{Subject: "수신자 한도 초과로 발송 취소", Body: er.Error(), Variables: vars}, false, User{})
					if recordErr != nil {
						return 0, recordErr
					}
					if id != "" {
						if _, recordErr = tx.Exec(ctx, `UPDATE notification_deliveries SET status='cancelled',last_error=$2,updated_at=now() WHERE id=$1`, id, er.Error()); recordErr != nil {
							return 0, recordErr
						}
					}
					continue
				}
				if er != nil {
					return 0, er
				}
				for _, target := range targets {
					message := NotificationMessage{RecipientUserID: target.UserID, Recipient: target.Address, Subject: notificationRender(rule.SubjectTemplate, vars, 200), Body: notificationRender(rule.BodyTemplate, vars, 16000), Variables: vars}
					if _, er = a.enqueueNotification(ctx, tx, e, rule, channel, message, false, User{}); er != nil {
						return 0, er
					}
				}
			}
		} else if !errors.Is(readErr, pgx.ErrNoRows) && !errors.Is(readErr, errNotificationTargetChanged) {
			return 0, readErr
		}
		if _, err = tx.Exec(ctx, `UPDATE notification_events SET rule_cursor=$2,status=CASE WHEN $3 THEN 'processed' ELSE 'pending' END,processed_at=CASE WHEN $3 THEN now() ELSE NULL END WHERE id=$1`, e.ID, e.RuleCursor, complete); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(events), nil
}

// Daily reminders cover explicit deadlines and enabled SLA-derived deadlines.
// A unique resource+effective deadline+UTC day key makes repeated ticks/restarts safe.
func (a *App) captureNotificationDue(ctx context.Context) (int64, error) {
	cfg, err := a.setting(ctx, "sla")
	if err != nil {
		return 0, err
	}
	raw, _ := json.Marshal(cfg)
	tag, err := a.DB.Exec(ctx, `WITH candidates AS(
 SELECT r.*,COALESCE(hunter_finding_timestamp(r.data->>'due_date'),CASE WHEN coalesce(($1::jsonb->>'enabled')::boolean,false) AND coalesce(r.data->>'due_date','')='' AND coalesce(($1::jsonb->>(coalesce(r.data->>'severity','info')||'_days'))::integer,0)>0 THEN r.created_at+make_interval(days=>($1::jsonb->>(coalesce(r.data->>'severity','info')||'_days'))::integer) END) AS due
 FROM resources r WHERE r.kind='findings' AND r.data->>'status' NOT IN('resolved','false_positive')
 AND (r.data->>'status'<>'accepted' OR hunter_finding_timestamp(r.data->>'expires_at')<=now())
 AND EXISTS(SELECT 1 FROM notification_rules WHERE enabled AND events ? 'finding.due')
),ready AS(
 SELECT *, 'due:'||id||':'||due::text||':'||to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD') AS event_key FROM candidates WHERE due<=now()
) INSERT INTO notification_events(event_key,event_type,entity_id,service_id,source_revision,metadata)
 SELECT event_key,'finding.due',id,coalesce(data->>'service_id',''),updated_at,jsonb_build_object('status',data->>'status','severity',data->>'severity','due_date',to_char(due AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'))
 FROM ready WHERE NOT EXISTS(SELECT 1 FROM notification_events e WHERE e.event_key=ready.event_key) ORDER BY due,id LIMIT 500 ON CONFLICT(event_key) DO NOTHING`, raw)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

type notificationClaim struct {
	ID, Token                              string
	Channel                                NotificationChannel
	Message                                NotificationMessage
	RuleID, EntityID, ServiceID, EventType string
	RuleRevision                           *time.Time
	IsTest                                 bool
	RequestedBy, KeyID                     string
	RecipientUserID                        string
	AutomationRevision                     *time.Time
	MemberCount                            int
	Attempt                                int
	MaxAttempts                            int
}

func (a *App) notificationTestAuthority(ctx context.Context, userID, keyID string) bool {
	var role string
	var disabled bool
	if a.DB.QueryRow(ctx, `SELECT role,disabled FROM users WHERE id=$1`, userID).Scan(&role, &disabled) != nil || disabled || !hasString(a.roleScopes(ctx, role), "admin:manage") {
		return false
	}
	if keyID != "" {
		var scopes []byte
		if a.DB.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, keyID, userID).Scan(&scopes) != nil {
			return false
		}
		var allowed []string
		if json.Unmarshal(scopes, &allowed) != nil || !hasString(allowed, "admin:manage") {
			return false
		}
	}
	return true
}
func (a *App) claimNotification(ctx context.Context) (*notificationClaim, error) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// A worker can disappear after the receiver accepted the message. Never reclaim sending.
	_, err = tx.Exec(ctx, `WITH expired AS(UPDATE notification_deliveries SET status='uncertain',last_error='발송 중 워커 임대가 만료되었습니다. 수신 시스템 결과를 확인하세요',lease_token='',lease_until=NULL,updated_at=now() WHERE status='sending' AND lease_until<=now() RETURNING id)
 UPDATE notification_attempts SET status='uncertain',detail='발송 결과를 확인할 수 없습니다',finished_at=now() WHERE delivery_id IN(SELECT id FROM expired) AND finished_at IS NULL`)
	if err != nil {
		return nil, err
	}
	var c notificationClaim
	var channelID, payload string
	var channelRevision time.Time
	err = tx.QueryRow(ctx, `SELECT id,channel_id,channel_revision,payload_encrypted,rule_id,rule_revision,entity_id,service_id,event_type,is_test,requested_by,credential_key_id,max_attempts,recipient_user_id,automation_revision FROM notification_deliveries WHERE status IN('queued','retry') AND NOT cancel_requested AND available_at<=now() ORDER BY available_at,created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&c.ID, &channelID, &channelRevision, &payload, &c.RuleID, &c.RuleRevision, &c.EntityID, &c.ServiceID, &c.EventType, &c.IsTest, &c.RequestedBy, &c.KeyID, &c.MaxAttempts, &c.RecipientUserID, &c.AutomationRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, err
	}
	plain, err := a.decrypt(payload)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(plain), &c.Message); err != nil {
		return nil, err
	}
	allowed, retryAt, err := a.notificationBeforeClaim(ctx, tx, channelID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		if retryAt.IsZero() {
			retryAt = time.Now().Add(time.Minute)
		}
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET available_at=$2,updated_at=now() WHERE id=$1`, c.ID, retryAt)
		if err != nil {
			return nil, err
		}
		return nil, tx.Commit(ctx)
	}
	channel, err := a.notificationChannel(ctx, tx, channelID)
	valid := err == nil && channel.UpdatedAt.Equal(channelRevision) && (channel.Enabled || c.IsTest)
	c.Channel = channel
	if valid && !c.IsTest {
		rule, e := a.notificationRule(ctx, tx, c.RuleID)
		valid = e == nil && c.RuleRevision != nil && rule.UpdatedAt.Equal(*c.RuleRevision) && rule.Enabled && hasString(rule.Events, c.EventType)
		if valid {
			valid, e = a.notificationDeliveryChannelAllowed(ctx, tx, c.ID, rule.ChannelID, channelID)
			if e != nil {
				return nil, e
			}
		}
		if valid {
			_, entity, service, e := a.notificationVariablesFor(ctx, tx, notificationEvent{EntityID: c.EntityID, ServiceID: c.ServiceID})
			valid = e == nil && notificationMatches(rule, entity, service)
			if valid {
				var currentErr error
				valid, currentErr = notificationEventCurrent(ctx, tx, c.EventType, entity, time.Now())
				if currentErr != nil {
					return nil, currentErr
				}
			}
		}
	}
	if !valid {
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET status='cancelled',last_error='현재 채널·규칙·서비스 조건과 일치하지 않습니다',updated_at=now() WHERE id=$1`, c.ID)
		if err != nil {
			return nil, err
		}
		return nil, tx.Commit(ctx)
	}
	ready, err := a.notificationAutomationClaim(ctx, tx, &c)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, tx.Commit(ctx)
	}
	c.Token = newID()
	err = tx.QueryRow(ctx, `UPDATE notification_deliveries SET status='sending',attempts=attempts+1,lease_token=$2,lease_until=now()+interval '2 minutes',updated_at=now(),cancel_requested=false WHERE id=$1 RETURNING attempts`, c.ID, c.Token).Scan(&c.Attempt)
	if err != nil {
		return nil, err
	}
	// Attempt numbers continue across explicit retry cycles.
	var number int
	err = tx.QueryRow(ctx, `SELECT coalesce(max(attempt),0)+1 FROM notification_attempts WHERE delivery_id=$1`, c.ID).Scan(&number)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO notification_attempts(delivery_id,attempt,status) VALUES($1,$2,'sending')`, c.ID, number)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}
func notificationSetting(ctx context.Context, q notificationQuerier, group string) (map[string]any, error) {
	cfg := defaultSettings()[group]
	var raw []byte
	err := q.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, group).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	var saved map[string]any
	if err = json.Unmarshal(raw, &saved); err != nil {
		return nil, err
	}
	for k, v := range saved {
		cfg[k] = v
	}
	return cfg, nil
}
func notificationEventCurrent(ctx context.Context, q notificationQuerier, eventType string, e domainResource, now time.Time) (bool, error) {
	if eventType == "approval.pending" {
		cfg, err := notificationSetting(ctx, q, "workflow")
		return err == nil && str(e.Data, "status") == "pending" && asBool(cfg["approval_enabled"]), err
	}
	if eventType != "finding.due" {
		return true, nil
	}
	status := str(e.Data, "status")
	if hasString([]string{"resolved", "false_positive"}, status) {
		return false, nil
	}
	if status == "accepted" {
		expires, err := time.Parse(time.RFC3339, str(e.Data, "expires_at"))
		if err != nil || expires.After(now) {
			return false, nil
		}
	}
	if value := str(e.Data, "due_date"); value != "" {
		due, err := time.Parse(time.RFC3339, value)
		return err == nil && !due.After(now), nil
	}
	cfg, err := notificationSetting(ctx, q, "sla")
	if err != nil {
		return false, err
	}
	days := asInt(cfg[str(e.Data, "severity")+"_days"])
	return asBool(cfg["enabled"]) && days > 0 && !e.CreatedAt.Add(time.Duration(days)*24*time.Hour).After(now), nil
}
func (a *App) notificationClaimCurrent(ctx context.Context, c *notificationClaim) bool {
	var valid bool
	err := a.DB.QueryRow(ctx, `SELECT d.status='sending' AND d.lease_token=$2 AND d.lease_until>now() AND NOT d.cancel_requested AND c.updated_at=d.channel_revision AND (c.enabled OR d.is_test)
 AND (d.is_test OR EXISTS(SELECT 1 FROM notification_rules r WHERE r.id=d.rule_id AND r.enabled AND r.updated_at=d.rule_revision))
 FROM notification_deliveries d JOIN notification_channels c ON c.id=d.channel_id WHERE d.id=$1`, c.ID, c.Token).Scan(&valid)
	if err != nil || !valid {
		return false
	}
	if c.IsTest {
		return a.notificationTestAuthority(ctx, c.RequestedBy, c.KeyID)
	}
	rule, err := a.notificationRule(ctx, a.DB, c.RuleID)
	if err != nil {
		return false
	}
	_, entity, service, err := a.notificationVariablesFor(ctx, a.DB, notificationEvent{EntityID: c.EntityID, ServiceID: c.ServiceID})
	if err != nil || !notificationMatches(rule, entity, service) {
		return false
	}
	valid, err = a.notificationDeliveryChannelAllowed(ctx, a.DB, c.ID, rule.ChannelID, c.Channel.ID)
	if err != nil || !valid {
		return false
	}
	if !a.notificationDynamicCurrent(ctx, a.DB, c, entity, service) || !a.notificationGroupCurrent(ctx, a.DB, c, false) {
		return false
	}
	valid, err = notificationEventCurrent(ctx, a.DB, c.EventType, entity, time.Now())
	return err == nil && valid
}
func (a *App) finishNotification(ctx context.Context, c *notificationClaim, result NotificationSendResult) error {
	state := result.State
	if !hasString([]string{"sent", "retryable", "failed", "uncertain"}, state) {
		state = "uncertain"
	}
	if state == "retryable" {
		state = "retry"
		if c.Attempt >= c.MaxAttempts {
			state = "failed"
		}
	}
	wait := time.Duration(1<<min(c.Attempt, 8)) * 15 * time.Second
	if result.RetryAfter > wait {
		wait = result.RetryAfter
	}
	if wait > 24*time.Hour {
		wait = 24 * time.Hour
	}
	detail := notificationText(result.Detail, 1000)
	providerID := notificationText(result.ProviderID, 200)
	code := notificationText(result.Code, 100)
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var cancelRequested bool
	if err = tx.QueryRow(ctx, `SELECT cancel_requested FROM notification_deliveries WHERE id=$1 AND status='sending' AND lease_token=$2 AND lease_until>now() FOR UPDATE`, c.ID, c.Token).Scan(&cancelRequested); err != nil {
		return err
	}
	if cancelRequested && hasString([]string{"failed", "retry"}, state) {
		state = "cancelled"
		detail = "관리자의 취소 요청으로 발송을 중단했습니다"
	}
	tag, err := tx.Exec(ctx, `UPDATE notification_deliveries SET status=$3,last_error=$4,provider_id=$5,lease_token='',lease_until=NULL,available_at=now()+make_interval(secs=>$6),sent_at=CASE WHEN $3='sent' THEN now() ELSE NULL END,updated_at=now() WHERE id=$1 AND status='sending' AND lease_token=$2 AND lease_until>now()`, c.ID, c.Token, state, detail, providerID, wait.Seconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("알림 발송 임대가 변경되었습니다")
	}
	_, err = tx.Exec(ctx, `UPDATE notification_attempts SET status=$2,code=$3,detail=$4,provider_id=$5,finished_at=now() WHERE delivery_id=$1 AND finished_at IS NULL`, c.ID, state, code, detail, providerID)
	if err != nil {
		return err
	}
	if err = a.notificationAutomationAfterAttempt(ctx, tx, c, state); err != nil {
		return err
	}
	if err = a.notificationAfterAttempt(ctx, tx, c, result, state); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// One invocation attempts at most one delivery; concurrent instances claim different rows.
func (a *App) processNotificationDelivery(ctx context.Context) (bool, error) {
	c, err := a.claimNotification(ctx)
	if err != nil || c == nil {
		return false, err
	}
	if !a.notificationClaimCurrent(ctx, c) {
		result := NotificationSendResult{State: "failed", Detail: "현재 알림 발송 권한 또는 설정을 확인할 수 없습니다"}
		return true, a.finishNotification(ctx, c, result)
	}
	sending, cancel := context.WithTimeout(ctx, 45*time.Second)
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-sending.Done():
				return
			case <-ticker.C:
				if !a.notificationClaimCurrent(sending, c) {
					cancel()
					return
				}
			}
		}
	}()
	result := a.sendNotification(sending, c.Channel, c.Message)
	cancel()
	<-done
	finish, cancelFinish := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFinish()
	return true, a.finishNotification(finish, c, result)
}
func (a *App) StartNotifications(ctx context.Context) { go a.notificationLoop(ctx) }

func (a *App) notificationLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	lastDue := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if time.Since(lastDue) > time.Minute {
			if _, err := a.captureNotificationDue(ctx); err != nil && ctx.Err() == nil {
				slog.Error("notification deadline capture failed")
			}
			lastDue = time.Now()
		}
		if _, err := a.processNotificationOutbox(ctx); err != nil && ctx.Err() == nil {
			slog.Error("notification outbox processing failed")
		}
		for i := 0; i < 4; i++ {
			worked, err := a.processNotificationDelivery(ctx)
			if err != nil && ctx.Err() == nil {
				slog.Error("notification delivery processing failed")
			}
			if !worked || ctx.Err() != nil {
				break
			}
		}
	}
}
func notificationEventID(id int64) string { return fmt.Sprint(id) }

func notificationEventLabel(event string) string {
	return map[string]string{"finding.created": "발견 건 등록", "finding.updated": "발견 건 변경", "finding.due": "조치 기한 도달", "scan.completed": "진단 완료", "scan.failed": "진단 실패", "approval.pending": "검토 요청", "manual.test": "테스트 알림", "finding.due_soon": "조치 기한 예고", "finding.unacknowledged": "업무 확인 지연", "team.weekly": "조직 주간 보안 현황"}[event]
}
func notificationStatusLabel(status string) string {
	if label := map[string]string{"candidate": "탐지 후보", "confirmed": "확인됨", "in_progress": "조치 중", "retest": "재검증 대기", "inconclusive": "판단 불가", "resolved": "해결", "accepted": "위험 수용", "false_positive": "오탐", "completed": "완료", "failed": "실패", "pending": "검토 대기", "pending_approval": "검토 대기", "cancelled": "취소됨"}[status]; label != "" {
		return label
	}
	return status
}
