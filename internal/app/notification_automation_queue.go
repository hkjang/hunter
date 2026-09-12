package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func (a *App) enqueueNotification(ctx context.Context, tx pgx.Tx, e notificationEvent, rule notificationRule, channel NotificationChannel, msg NotificationMessage, isTest bool, u User) (string, error) {
	if isTest {
		return a.enqueueNotificationRaw(ctx, tx, e, rule, channel, msg, isTest, u)
	}
	cfg, revision, err := a.notificationAutomationConfig(ctx, tx)
	if err != nil {
		return "", err
	}
	groupKey := ""
	available := time.Now()
	emergency := hasString(cfg.Grouping.EmergencySeverities, msg.Variables["finding.severity"])
	if cfg.Enabled && cfg.Grouping.Enabled && !emergency && e.Type != "team.weekly" && e.Type != "finding.unacknowledged" {
		cause := e.EntityID
		var raw []byte
		if err = tx.QueryRow(ctx, `SELECT data FROM resources WHERE id=$1`, e.EntityID).Scan(&raw); err != nil {
			return "", err
		}
		var data map[string]any
		if err = json.Unmarshal(raw, &data); err != nil {
			return "", err
		}
		if cve := strings.TrimSpace(str(data, "cve")); cve != "" && strings.TrimSpace(str(data, "component")) != "" {
			cause = strings.ToUpper(cve) + "\x1f" + strings.TrimSpace(str(data, "component"))
		}
		window := time.Duration(cfg.Grouping.WindowMinutes) * time.Minute
		bucket := available.Truncate(window)
		available = bucket.Add(window)
		groupKey = a.notificationHash(strings.Join([]string{rule.ID, rule.UpdatedAt.String(), channel.ID, e.Type, e.ServiceID, cause, msg.Recipient, msg.RecipientUserID, bucket.String()}, "\x1f"))
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1701))`, groupKey); err != nil {
			return "", err
		}
	}
	if e.ID != 0 {
		var previous string
		err = tx.QueryRow(ctx, `SELECT delivery_id FROM notification_delivery_members WHERE event_id=$1 AND rule_id=$2 AND recipient_hash=$3`, e.ID, rule.ID, a.notificationHash(msg.Recipient)).Scan(&previous)
		if err == nil {
			return "", nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	id := ""
	if groupKey != "" {
		err = tx.QueryRow(ctx, `SELECT d.id FROM notification_deliveries d WHERE group_key=$1 AND status='queued' AND attempts=0 AND available_at>now() AND (SELECT count(*) FROM notification_delivery_members m WHERE m.delivery_id=d.id)<100 ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, groupKey).Scan(&id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	if id == "" {
		id, err = a.enqueueNotificationRaw(ctx, tx, e, rule, channel, msg, isTest, u)
		if err != nil || id == "" {
			return id, err
		}
		var rev any
		if cfg.Enabled {
			rev = revision
		}
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET recipient_user_id=$2,automation_revision=$3,group_key=$4,available_at=$5 WHERE id=$1`, id, msg.RecipientUserID, rev, groupKey, available)
		if err != nil {
			return "", err
		}
	}
	if e.ID != 0 {
		_, err = tx.Exec(ctx, `INSERT INTO notification_delivery_members(event_id,rule_id,recipient_hash,delivery_id,entity_id,service_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, e.ID, rule.ID, a.notificationHash(msg.Recipient), id, e.EntityID, e.ServiceID)
	}
	return id, err
}

func (a *App) notificationGroupCurrent(ctx context.Context, q notificationQuerier, c *notificationClaim, render bool) bool {
	sourceID, err := a.notificationMemberSource(ctx, q, c.ID)
	if err != nil {
		return false
	}
	var raw []byte
	err = q.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object('id',e.id,'event_type',e.event_type,'entity_id',e.entity_id,'service_id',e.service_id,'created_at',e.created_at,'metadata',e.metadata) ORDER BY e.id),'[]') FROM notification_delivery_members m JOIN notification_events e ON e.id=m.event_id WHERE m.delivery_id=$1`, sourceID).Scan(&raw)
	if err != nil {
		return false
	}
	var members []struct {
		ID        int64          `json:"id"`
		Type      string         `json:"event_type"`
		EntityID  string         `json:"entity_id"`
		ServiceID string         `json:"service_id"`
		CreatedAt time.Time      `json:"created_at"`
		Metadata  map[string]any `json:"metadata"`
	}
	if json.Unmarshal(raw, &members) != nil || len(members) > 100 {
		return false
	}
	if c.EventType == "team.weekly" && c.RecipientUserID != "" {
		user, e := notificationCurrentUser(ctx, q, c.RecipientUserID)
		if e != nil || !hasString(user.Scopes, "findings:read") {
			return false
		}
		var blocked bool
		if e = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_delivery_scope scope LEFT JOIN resources s ON s.kind='services' AND s.id=scope.service_id WHERE scope.delivery_id=$1 AND NOT coalesce(s.id IS NOT NULL AND ($2 OR s.owner_id=$3 OR ($4<>'' AND s.data->>'team'=$4)),false))`, sourceID, elevated(user), user.ID, leadTeam(user)).Scan(&blocked); e != nil || blocked {
			return false
		}
	}
	c.MemberCount = len(members)
	rule, err := a.notificationRule(ctx, q, c.RuleID)
	if err != nil {
		return false
	}
	lines := []string{}
	for _, m := range members {
		vars, entity, service, err := a.notificationVariablesFor(ctx, q, notificationEvent{ID: m.ID, Type: m.Type, EntityID: m.EntityID, ServiceID: m.ServiceID, CreatedAt: m.CreatedAt, Metadata: m.Metadata})
		if err != nil || !notificationMatches(rule, entity, service) || !a.notificationDynamicCurrent(ctx, q, c, entity, service) {
			return false
		}
		ok, err := notificationEventCurrent(ctx, q, m.Type, entity, time.Now())
		if err != nil || !ok {
			return false
		}
		ok, err = a.notificationAutomationEventCurrent(ctx, q, notificationEvent{ID: m.ID, Type: m.Type, Metadata: m.Metadata}, entity)
		if err != nil || !ok {
			return false
		}
		if render {
			lines = append(lines, notificationRender(rule.BodyTemplate, vars, 16000))
		}
	}
	if render && len(members) > 1 {
		c.Message.Subject = notificationText(fmt.Sprintf("[hunter] 알림 %d건 · %s", len(members), c.Message.Variables["service.name"]), 200)
		c.Message.Body = notificationText(strings.Join(lines, "\n\n────\n\n"), 16000)
	}
	return true
}
func (a *App) notificationAutomationClaim(ctx context.Context, tx pgx.Tx, c *notificationClaim) (bool, error) {
	if c.IsTest {
		return true, nil
	}
	entity, service, err := notificationResourcePair(ctx, tx, c.EntityID, c.ServiceID)
	if err != nil {
		return false, err
	}
	var attempted bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_attempts WHERE delivery_id=$1)`, c.ID).Scan(&attempted); err != nil {
		return false, err
	}
	sourceID, sourceErr := a.notificationMemberSource(ctx, tx, c.ID)
	if sourceErr != nil {
		return false, sourceErr
	}
	attempted = attempted || sourceID != c.ID
	if !a.notificationDynamicCurrent(ctx, tx, c, entity, service) || !a.notificationGroupCurrent(ctx, tx, c, !attempted) {
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET status='cancelled',last_error='현재 동적 수신자·묶음 대상·자동화 조건과 일치하지 않습니다',updated_at=now() WHERE id=$1`, c.ID)
		return false, err
	}
	if c.EventType == "team.weekly" && !attempted {
		if err = a.notificationWeeklyMessage(ctx, tx, c, service); err != nil {
			return false, err
		}
	}
	cfg, _, err := a.notificationAutomationConfig(ctx, tx)
	if err != nil {
		return false, err
	}
	if cfg.Enabled && cfg.Grouping.Enabled && !hasString(cfg.Grouping.EmergencySeverities, str(entity.Data, "severity")) {
		hash := a.notificationHash(c.Message.Recipient)
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1702))`, hash); err != nil {
			return false, err
		}
		var count int
		var next time.Time
		err = tx.QueryRow(ctx, `SELECT count(DISTINCT d.id),coalesce(min(t.started_at)+interval '1 hour',now()+interval '1 minute') FROM notification_attempts t JOIN notification_deliveries d ON d.id=t.delivery_id WHERE d.recipient_hash=$1 AND t.started_at>now()-interval '1 hour' AND d.id<>$2`, hash, c.ID).Scan(&count, &next)
		if err != nil {
			return false, err
		}
		if count >= cfg.Grouping.RecipientHourlyLimit {
			_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET available_at=$2,last_error='수신자별 시간당 발송 한도로 대기합니다',updated_at=now() WHERE id=$1`, c.ID, next.Add(time.Second))
			return false, err
		}
	}
	// Persist the final digest to the same encrypted payload used by provider retries.
	raw, err := json.Marshal(c.Message)
	if err != nil {
		return false, err
	}
	cipher, err := a.encrypt(string(raw))
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET payload_encrypted=$2 WHERE id=$1`, c.ID, cipher)
	return err == nil, err
}
func (a *App) notificationAutomationAfterAttempt(ctx context.Context, tx pgx.Tx, c *notificationClaim, state string) error {
	if state != "sent" || c.IsTest || c.RecipientUserID == "" || c.EventType == "finding.unacknowledged" || c.EventType == "team.weekly" {
		return nil
	}
	cfg, _, err := a.notificationAutomationConfig(ctx, tx)
	if err != nil || !cfg.Enabled || !cfg.Acknowledgement.Enabled {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET ack_due_at=coalesce(ack_due_at,now()+make_interval(mins=>$2)) WHERE id=$1`, c.ID, cfg.Acknowledgement.TimeoutMinutes)
	return err
}
func (a *App) notificationAutomationEventCurrent(ctx context.Context, q notificationQuerier, e notificationEvent, entity domainResource) (bool, error) {
	if !hasString([]string{"finding.due_soon", "finding.unacknowledged", "team.weekly"}, e.Type) {
		return true, nil
	}
	cfg, _, err := a.notificationAutomationConfig(ctx, q)
	if err != nil || !cfg.Enabled {
		return false, err
	}
	switch e.Type {
	case "finding.due_soon":
		if !cfg.Calendar.Enabled {
			return false, nil
		}
		due, ok, err := notificationEffectiveDue(ctx, q, entity)
		if err != nil || !ok {
			return false, err
		}
		now := time.Now()
		loc, _ := time.LoadLocation(cfg.Timezone)
		if loc == nil {
			loc = time.UTC
		}
		local := now.In(loc)
		business := false
		for _, d := range cfg.Calendar.Weekdays {
			business = business || int(local.Weekday()) == d
		}
		if !business || hasString(cfg.Calendar.Holidays, local.Format("2006-01-02")) {
			return false, nil
		}
		if old := str(e.Metadata, "due_date"); old != "" && old != due.UTC().Format(time.RFC3339) {
			return false, nil
		}
		return due.After(now) && notificationBusinessDays(cfg, now, due) <= cfg.Calendar.RemindBusinessDays, nil
	case "finding.unacknowledged":
		if !cfg.Acknowledgement.Enabled {
			return false, nil
		}
		var valid bool
		err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_deliveries WHERE id=$1 AND acknowledged_at IS NULL AND status='sent' AND ack_due_at<=now() AND payload_purged_at IS NULL)`, str(e.Metadata, "original_delivery_id")).Scan(&valid)
		return valid && notificationFindingOpen(entity, time.Now()), err
	case "team.weekly":
		return cfg.Weekly.Enabled && (str(e.Metadata, "team") == "" || str(e.Metadata, "team") == str(entity.Data, "team")), nil
	}
	return true, nil
}
func notificationFindingOpen(e domainResource, now time.Time) bool {
	status := str(e.Data, "status")
	if hasString([]string{"resolved", "false_positive"}, status) {
		return false
	}
	if status == "accepted" {
		expires, err := time.Parse(time.RFC3339, str(e.Data, "expires_at"))
		if err != nil || expires.After(now) {
			return false
		}
	}
	return true
}
func notificationEffectiveDue(ctx context.Context, q notificationQuerier, e domainResource) (time.Time, bool, error) {
	if !notificationFindingOpen(e, time.Now()) {
		return time.Time{}, false, nil
	}
	if raw := str(e.Data, "due_date"); raw != "" {
		d, err := time.Parse(time.RFC3339, raw)
		return d, err == nil, nil
	}
	cfg, err := notificationSetting(ctx, q, "sla")
	if err != nil {
		return time.Time{}, false, err
	}
	days := asInt(cfg[str(e.Data, "severity")+"_days"])
	return e.CreatedAt.AddDate(0, 0, days), asBool(cfg["enabled"]) && days > 0, nil
}
func notificationAutomationEventKey(prefix string, parts ...string) string {
	return prefix + ":" + strings.Join(parts, ":")
}
func notificationEventNumber(id int64) string { return strconv.FormatInt(id, 10) }
