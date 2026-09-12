package app

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"
)

func (a *App) simulateNotifications(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RuleID string    `json:"rule_id"`
		From   time.Time `json:"from"`
		To     time.Time `json:"to"`
		Limit  int       `json:"limit"`
	}
	if notificationDecode(r, &in) != nil || in.RuleID == "" || in.From.IsZero() || !in.To.After(in.From) || in.To.Sub(in.From) > 366*24*time.Hour {
		fail(w, 400, "규칙과 조회 기간(최대 366일)을 확인하세요")
		return
	}
	if in.Limit == 0 {
		in.Limit = 500
	}
	if in.Limit < 1 || in.Limit > 1000 {
		fail(w, 400, "시뮬레이션은 최대 1000개 이벤트입니다")
		return
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		fail(w, 500, "시뮬레이션 시작 실패")
		return
	}
	defer tx.Rollback(ctx)
	rule, err := a.notificationRule(ctx, tx, in.RuleID)
	if err != nil {
		fail(w, 404, "규칙을 찾지 못했습니다")
		return
	}
	channel, err := a.notificationChannel(ctx, tx, rule.ChannelID)
	if err != nil {
		fail(w, 404, "채널을 찾지 못했습니다")
		return
	}
	cfg, _, err := a.notificationAutomationConfig(ctx, tx)
	if err != nil {
		fail(w, 500, "현재 설정 조회 실패")
		return
	}
	var total int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE created_at>=$1 AND created_at<$2`, in.From, in.To).Scan(&total); err != nil {
		fail(w, 500, "보관 이벤트 조회 실패")
		return
	}
	rows, err := tx.Query(ctx, `SELECT id,event_type,entity_id,service_id,source_revision,metadata,created_at FROM notification_events WHERE created_at>=$1 AND created_at<$2 ORDER BY created_at DESC,id DESC LIMIT $3`, in.From, in.To, in.Limit)
	if err != nil {
		fail(w, 500, "보관 이벤트 조회 실패")
		return
	}
	events := []notificationEvent{}
	for rows.Next() {
		var e notificationEvent
		var raw []byte
		if err = rows.Scan(&e.ID, &e.Type, &e.EntityID, &e.ServiceID, &e.Revision, &raw, &e.CreatedAt); err != nil {
			break
		}
		if err = json.Unmarshal(raw, &e.Metadata); err != nil {
			break
		}
		events = append(events, e)
	}
	rows.Close()
	if err != nil || rows.Err() != nil {
		fail(w, 500, "보관 이벤트 읽기 실패")
		return
	}
	matched, recipients := 0, 0
	groups := map[string]int{}
	reasons := map[string]int{}
	sample := []map[string]any{}
	for _, e := range events {
		reason := "matched"
		count := 0
		if !channel.Enabled {
			reason = "channel_disabled"
		} else if !hasString(rule.Events, e.Type) {
			reason = "event_not_selected"
		} else {
			_, entity, service, err := a.notificationVariablesFor(ctx, tx, e)
			if err != nil {
				reason = "source_unavailable"
			} else if !notificationMatches(rule, entity, service) {
				reason = "rule_disabled_or_filter_mismatch"
			} else {
				valid, e1 := notificationEventCurrent(ctx, tx, e.Type, entity, time.Now())
				auto, e2 := a.notificationAutomationEventCurrent(ctx, tx, e, entity)
				if e1 != nil || e2 != nil {
					fail(w, 500, "현재 조건 조회 실패")
					return
				}
				if !valid || !auto {
					reason = "condition_no_longer_current"
				} else {
					targets, err := a.notificationTargets(ctx, tx, cfg, rule, channel, entity, service, time.Now())
					if err != nil {
						reason = "recipient_limit_exceeded"
					} else if len(targets) == 0 {
						reason = "no_current_recipient"
					} else {
						count = len(targets)
						matched++
						recipients += count
						for _, target := range targets {
							key := notificationEventNumber(e.ID) + target.Address
							if cfg.Enabled && cfg.Grouping.Enabled && !hasString(cfg.Grouping.EmergencySeverities, str(entity.Data, "severity")) && e.Type != "team.weekly" && e.Type != "finding.unacknowledged" {
								cause := entity.ID
								if str(entity.Data, "cve") != "" && str(entity.Data, "component") != "" {
									cause = str(entity.Data, "cve") + "|" + str(entity.Data, "component")
								}
								key = e.Type + "|" + e.ServiceID + "|" + cause + "|" + target.UserID + "|" + target.Address + "|" + strconv.FormatInt(e.CreatedAt.Unix()/int64(cfg.Grouping.WindowMinutes*60), 10)
							}
							groups[a.notificationHash(key)]++
						}
					}
				}
			}
		}
		reasons[reason]++
		if len(sample) < 100 {
			sample = append(sample, map[string]any{"event_id": e.ID, "entity_id": e.EntityID, "matched": reason == "matched", "recipient_count": count, "reason": reason})
		}
	}
	reasonList := []map[string]any{}
	keys := []string{}
	for key := range reasons {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		reasonList = append(reasonList, map[string]any{"code": key, "count": reasons[key]})
	}
	estimated := 0
	for _, n := range groups {
		estimated += (n + 99) / 100
	}
	result := map[string]any{"id": newID(), "created_at": time.Now().UTC(), "rule_id": rule.ID, "scanned": len(events), "matched": matched, "recipient_count": recipients, "estimated_deliveries": estimated, "truncated": total > len(events), "reasons": reasonList, "sample": sample, "semantics": "보관 이벤트를 현재 자료·규칙·수신 권한으로 대조한 추정이며 외부 발송이나 과거 원문 재현을 수행하지 않습니다"}
	raw, _ := json.Marshal(result)
	if _, err = tx.Exec(ctx, `INSERT INTO notification_simulations(id,result) VALUES($1,$2)`, result["id"], raw); err != nil || tx.Commit(ctx) != nil {
		fail(w, 500, "시뮬레이션 결과 저장 실패")
		return
	}
	a.audit(r, "notification.simulate", rule.ID, map[string]any{"scanned": len(events), "matched": matched})
	jsonResponse(w, 200, result)
}
func (a *App) listNotificationSimulations(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(r.Context(), `SELECT result FROM notification_simulations ORDER BY created_at DESC,id LIMIT 20`)
	if err != nil {
		fail(w, 500, "시뮬레이션 이력 조회 실패")
		return
	}
	items := []map[string]any{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var v map[string]any
		if err = json.Unmarshal(raw, &v); err != nil {
			break
		}
		items = append(items, v)
	}
	rows.Close()
	if err != nil || rows.Err() != nil {
		fail(w, 500, "시뮬레이션 이력 읽기 실패")
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}
