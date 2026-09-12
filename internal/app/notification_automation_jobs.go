package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (a *App) processNotificationAutomation(ctx context.Context, now time.Time) (map[string]int64, error) {
	out := map[string]int64{"due_soon": 0, "followups": 0, "weekly": 0, "purged": 0}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended(current_schema()||':notification-automation',1700))`).Scan(&locked); err != nil || !locked {
		return out, err
	}
	cfg, _, err := a.notificationAutomationConfig(ctx, tx)
	if err != nil || !cfg.Enabled {
		return out, err
	}
	var last time.Time
	err = tx.QueryRow(ctx, `INSERT INTO notification_automation_ticks(key,updated_at) VALUES('jobs',$1) ON CONFLICT(key) DO UPDATE SET updated_at=excluded.updated_at WHERE notification_automation_ticks.updated_at<=$1-interval '1 minute' RETURNING updated_at`, now).Scan(&last)
	if err == pgx.ErrNoRows {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	loc, _ := time.LoadLocation(cfg.Timezone)
	if loc == nil {
		loc = time.UTC
	}
	local := now.In(loc)
	business := false
	for _, v := range cfg.Calendar.Weekdays {
		business = business || v == int(local.Weekday())
	}
	business = business && !hasString(cfg.Calendar.Holidays, local.Format("2006-01-02"))
	if cfg.Calendar.Enabled && business {
		sla, err := notificationSetting(ctx, tx, "sla")
		if err != nil {
			return out, err
		}
		raw, _ := json.Marshal(sla)
		rows, err := tx.Query(ctx, `WITH candidates AS(SELECT r.*,coalesce(hunter_finding_timestamp(data->>'due_date'),CASE WHEN $1::jsonb->>'enabled'='true' AND coalesce(data->>'due_date','')='' AND coalesce(($1::jsonb->>(coalesce(data->>'severity','info')||'_days'))::int,0)>0 THEN created_at+make_interval(days=>($1::jsonb->>(coalesce(data->>'severity','info')||'_days'))::int) END) due FROM resources r WHERE kind='findings') SELECT id,kind,owner_id,data,created_at,updated_at,due FROM candidates WHERE due>$2 AND coalesce(data->>'status','candidate') NOT IN('resolved','false_positive') AND EXISTS(SELECT 1 FROM notification_rules WHERE enabled AND events ? 'finding.due_soon') AND NOT EXISTS(SELECT 1 FROM notification_events e WHERE e.event_key='soon:'||candidates.id||':'||to_char(due AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')||':'||$3) ORDER BY due,id LIMIT 500`, raw, now, local.Format("2006-01-02"))
		if err != nil {
			return out, err
		}
		type dueResource struct {
			r   domainResource
			due time.Time
		}
		items := []dueResource{}
		for rows.Next() {
			var item dueResource
			var data []byte
			if err = rows.Scan(&item.r.ID, &item.r.Kind, &item.r.OwnerID, &data, &item.r.CreatedAt, &item.r.UpdatedAt, &item.due); err != nil {
				break
			}
			if err = json.Unmarshal(data, &item.r.Data); err != nil {
				break
			}
			items = append(items, item)
		}
		rows.Close()
		if err != nil {
			return out, err
		}
		if rows.Err() != nil {
			return out, rows.Err()
		}
		for _, item := range items {
			if !notificationFindingOpen(item.r, now) || notificationBusinessDays(cfg, now, item.due) > cfg.Calendar.RemindBusinessDays {
				continue
			}
			due := item.due.UTC().Format(time.RFC3339)
			meta := map[string]any{"status": str(item.r.Data, "status"), "severity": str(item.r.Data, "severity"), "due_date": due}
			key := notificationAutomationEventKey("soon", item.r.ID, due, local.Format("2006-01-02"))
			n, err := notificationInsertAutomationEvent(ctx, tx, key, "finding.due_soon", item.r.ID, str(item.r.Data, "service_id"), item.r.UpdatedAt, meta, now)
			if err != nil {
				return out, err
			}
			out["due_soon"] += n
		}
	}
	if cfg.Acknowledgement.Enabled {
		rows, err := tx.Query(ctx, `SELECT d.id,r.id,r.data,r.updated_at FROM notification_deliveries d JOIN resources r ON r.id=d.entity_id AND r.kind='findings' WHERE d.status='sent' AND d.ack_due_at<=$1 AND d.acknowledged_at IS NULL AND d.payload_purged_at IS NULL AND EXISTS(SELECT 1 FROM notification_rules WHERE enabled AND events ? 'finding.unacknowledged') AND NOT EXISTS(SELECT 1 FROM notification_events e WHERE e.event_key='unack:'||d.id) ORDER BY d.ack_due_at,d.id LIMIT 100`, now)
		if err != nil {
			return out, err
		}
		type follow struct {
			id string
			r  domainResource
		}
		items := []follow{}
		for rows.Next() {
			var v follow
			var raw []byte
			if err = rows.Scan(&v.id, &v.r.ID, &raw, &v.r.UpdatedAt); err != nil {
				break
			}
			if err = json.Unmarshal(raw, &v.r.Data); err != nil {
				break
			}
			items = append(items, v)
		}
		rows.Close()
		if err != nil {
			return out, err
		}
		if rows.Err() != nil {
			return out, rows.Err()
		}
		for _, v := range items {
			if !notificationFindingOpen(v.r, now) {
				continue
			}
			n, err := notificationInsertAutomationEvent(ctx, tx, "unack:"+v.id, "finding.unacknowledged", v.r.ID, str(v.r.Data, "service_id"), v.r.UpdatedAt, map[string]any{"original_delivery_id": v.id, "status": str(v.r.Data, "status"), "severity": str(v.r.Data, "severity")}, now)
			if err != nil {
				return out, err
			}
			out["followups"] += n
		}
	}
	if cfg.Weekly.Enabled && int(local.Weekday()) == cfg.Weekly.Weekday && local.Hour() >= cfg.Weekly.Hour {
		week := local.Format("2006-01-02")
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON(data->>'team') id,coalesce(data->>'team',''),updated_at FROM resources WHERE kind='services' AND coalesce(data->>'team','')<>'' AND EXISTS(SELECT 1 FROM notification_rules WHERE enabled AND events ? 'team.weekly') AND NOT EXISTS(SELECT 1 FROM notification_events e WHERE e.event_key='weekly:'||md5(data->>'team')||':'||$1) ORDER BY data->>'team',id LIMIT 100`, week)
		if err != nil {
			return out, err
		}
		type entry struct {
			id, team string
			revision time.Time
		}
		entries := []entry{}
		for rows.Next() {
			var v entry
			if err = rows.Scan(&v.id, &v.team, &v.revision); err != nil {
				break
			}
			entries = append(entries, v)
		}
		rows.Close()
		if err != nil {
			return out, err
		}
		if rows.Err() != nil {
			return out, rows.Err()
		}
		for _, v := range entries {
			var key string
			if err = tx.QueryRow(ctx, `SELECT 'weekly:'||md5($1)||':'||$2`, v.team, week).Scan(&key); err != nil {
				return out, err
			}
			n, err := notificationInsertAutomationEvent(ctx, tx, key, "team.weekly", v.id, v.id, v.revision, map[string]any{"team": v.team, "period_start": now.AddDate(0, 0, -7).UTC().Format(time.RFC3339), "period_end": now.UTC().Format(time.RFC3339)}, now)
			if err != nil {
				return out, err
			}
			out["weekly"] += n
		}
	}
	if cfg.Retention.Enabled {
		idsRows, err := tx.Query(ctx, `SELECT id FROM notification_deliveries WHERE status IN('sent','failed','cancelled') AND NOT retention_hold AND payload_purged_at IS NULL AND updated_at<$1::timestamptz-make_interval(days=>$2) AND (ack_due_at IS NULL OR acknowledged_at IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM notification_receipts WHERE delivery_id=notification_deliveries.id AND state IN('pending','unavailable','conflict'))
 AND NOT EXISTS(SELECT 1 FROM notification_fallbacks f JOIN notification_deliveries child ON child.id=f.child_id LEFT JOIN notification_receipts receipt ON receipt.delivery_id=child.id WHERE f.parent_id=notification_deliveries.id AND (child.status IN('queued','retry','sending','uncertain') OR receipt.state IN('pending','unavailable','conflict')))
 ORDER BY updated_at,id LIMIT 100 FOR UPDATE SKIP LOCKED`, now, cfg.Retention.PayloadDays)
		if err != nil {
			return out, err
		}
		ids := []string{}
		for idsRows.Next() {
			var id string
			if err = idsRows.Scan(&id); err != nil {
				break
			}
			ids = append(ids, id)
		}
		idsRows.Close()
		if err != nil {
			return out, err
		}
		if idsRows.Err() != nil {
			return out, idsRows.Err()
		}
		for _, id := range ids {
			allowed, e := a.notificationRetentionAllowed(ctx, tx, id)
			if e != nil {
				return out, e
			}
			if !allowed {
				continue
			}
			if _, err = tx.Exec(ctx, `UPDATE notification_deliveries SET payload_encrypted='',payload_purged_at=$2,last_error='',provider_id='',updated_at=$2 WHERE id=$1`, id, now); err != nil {
				return out, err
			}
			if _, err = tx.Exec(ctx, `UPDATE notification_attempts SET detail='',provider_id='' WHERE delivery_id=$1`, id); err != nil {
				return out, err
			}
			if _, err = tx.Exec(ctx, `UPDATE notification_receipts SET provider_id='' WHERE delivery_id=$1`, id); err != nil {
				return out, err
			}
			out["purged"]++
		}
		// Identities, source membership and unique deduplication keys deliberately survive.
		if _, err = tx.Exec(ctx, `DELETE FROM notification_simulations WHERE created_at<$1::timestamptz-make_interval(days=>$2)`, now, cfg.Retention.PayloadDays); err != nil {
			return out, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}
func notificationInsertAutomationEvent(ctx context.Context, tx pgx.Tx, key, kind, entityID, serviceID string, revision time.Time, metadata map[string]any, now time.Time) (int64, error) {
	raw, _ := json.Marshal(metadata)
	tag, err := tx.Exec(ctx, `INSERT INTO notification_events(event_key,event_type,entity_id,service_id,source_revision,metadata,created_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(event_key) DO NOTHING`, key, kind, entityID, serviceID, revision, raw, now)
	return tag.RowsAffected(), err
}
func (a *App) notificationWeeklyMessage(ctx context.Context, q notificationQuerier, c *notificationClaim, service domainResource) error {
	var user User
	var err error
	if c.RecipientUserID != "" {
		user, err = notificationCurrentUser(ctx, q, c.RecipientUserID)
		if err != nil {
			return err
		}
	} else {
		user.Role = "admin"
		user.Scopes = allScopes
	}
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -7)
	var metadata []byte
	err = q.QueryRow(ctx, `SELECT metadata FROM notification_events WHERE id::text=$1`, c.Message.EventID).Scan(&metadata)
	if err == nil {
		var m map[string]any
		if json.Unmarshal(metadata, &m) == nil {
			if t, e := time.Parse(time.RFC3339, str(m, "period_start")); e == nil {
				start = t
			}
			if t, e := time.Parse(time.RFC3339, str(m, "period_end")); e == nil {
				end = t
			}
		}
	}
	if !hasString(user.Scopes, "findings:read") || !hasString(user.Scopes, "services:read") {
		return fmt.Errorf("주간 요약 조회 권한이 없습니다")
	}
	sla, err := notificationSetting(ctx, q, "sla")
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(sla)
	var total, newCount, resolved, overdue int
	var scopeRaw []byte
	err = q.QueryRow(ctx, `WITH scoped AS(SELECT r.*,coalesce(hunter_finding_timestamp(r.data->>'due_date'),CASE WHEN $7::jsonb->>'enabled'='true' AND coalesce(r.data->>'due_date','')='' AND coalesce(($7::jsonb->>(coalesce(r.data->>'severity','info')||'_days'))::int,0)>0 THEN r.created_at+make_interval(days=>coalesce(($7::jsonb->>(coalesce(r.data->>'severity','info')||'_days'))::int,0)) END) due FROM resources r JOIN resources s ON s.kind='services' AND s.id=r.data->>'service_id' WHERE r.kind='findings' AND s.data->>'team'=$1 AND ($2 OR s.owner_id=$3 OR ($4<>'' AND s.data->>'team'=$4))) SELECT count(*) FILTER(WHERE data->>'status' NOT IN('resolved','false_positive') AND NOT(data->>'status'='accepted' AND coalesce(hunter_finding_timestamp(data->>'expires_at')>$6,false))),count(*) FILTER(WHERE created_at>=$5 AND created_at<$6),count(*) FILTER(WHERE data->>'status'='resolved' AND updated_at>=$5 AND updated_at<$6),count(*) FILTER(WHERE due<$6 AND data->>'status' NOT IN('resolved','false_positive') AND NOT(data->>'status'='accepted' AND coalesce(hunter_finding_timestamp(data->>'expires_at')>$6,false))),coalesce(jsonb_agg(DISTINCT data->>'service_id'),'[]') FROM scoped`, str(service.Data, "team"), elevated(user), user.ID, leadTeam(user), start, end, raw).Scan(&total, &newCount, &resolved, &overdue, &scopeRaw)
	if err != nil {
		return err
	}
	// Keep the exact service authorization envelope that contributed to this snapshot.
	var scopeIDs []string
	if err = json.Unmarshal(scopeRaw, &scopeIDs); err != nil {
		return err
	}
	if executor, ok := q.(interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	}); ok {
		_, err = executor.Exec(ctx, `INSERT INTO notification_delivery_scope(delivery_id,service_id) SELECT $1,unnest($2::text[]) ON CONFLICT DO NOTHING`, c.ID, scopeIDs)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("주간 범위 저장 트랜잭션이 필요합니다")
	}
	if c.Message.Variables == nil {
		c.Message.Variables = map[string]string{}
	}
	for key, n := range map[string]int{"total": total, "new": newCount, "resolved": resolved, "overdue": overdue} {
		c.Message.Variables["summary."+key] = strconv.Itoa(n)
	}
	c.Message.Variables["summary.period_start"] = start.Format(time.RFC3339)
	c.Message.Variables["summary.period_end"] = end.Format(time.RFC3339)
	rule, err := a.notificationRule(ctx, q, c.RuleID)
	if err != nil {
		return err
	}
	c.Message.Subject = notificationRender(rule.SubjectTemplate, c.Message.Variables, 200)
	c.Message.Body = notificationRender(rule.BodyTemplate, c.Message.Variables, 16000)
	return nil
}
