package app

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// The list applies the effective request-key scopes and current parent ACL in SQL,
// before counting/pagination. A user's display name or address is never an ACL.
const notificationInboxWhere = ` FROM notification_deliveries d JOIN resources r ON r.id=d.entity_id JOIN resources s ON s.kind='services' AND s.id=d.service_id
 WHERE d.recipient_user_id=$1 AND d.status='sent' AND d.payload_purged_at IS NULL
 AND (r.kind='services' AND r.id=s.id OR r.kind<>'services' AND r.data->>'service_id'=s.id)
 AND ($2 OR r.owner_id=$1 OR s.owner_id=$1 OR ($3<>'' AND s.data->>'team'=$3))
 AND (r.kind='services' AND (d.event_type<>'team.weekly' OR $4) OR r.kind='findings' AND $4 OR r.kind='scans' AND $5 OR r.kind='approvals' AND $6)
 AND ($7='all' OR $7='pending' AND d.acknowledged_at IS NULL AND d.ack_due_at IS NOT NULL OR $7='acknowledged' AND d.acknowledged_at IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM notification_delivery_members m
 LEFT JOIN resources mr ON mr.id=m.entity_id LEFT JOIN resources ms ON ms.kind='services' AND ms.id=m.service_id
 WHERE m.delivery_id=coalesce((SELECT parent_id FROM notification_fallbacks WHERE child_id=d.id),d.id)
 AND NOT coalesce(mr.id IS NOT NULL AND ms.id IS NOT NULL
 AND (mr.kind='services' AND mr.id=ms.id OR mr.kind<>'services' AND mr.data->>'service_id'=ms.id)
 AND ($2 OR mr.owner_id=$1 OR ms.owner_id=$1 OR ($3<>'' AND ms.data->>'team'=$3))
 AND (mr.kind='services' AND (d.event_type<>'team.weekly' OR $4) OR mr.kind='findings' AND $4 OR mr.kind='scans' AND $5 OR mr.kind='approvals' AND $6),false))
 AND NOT EXISTS(SELECT 1 FROM notification_delivery_scope scope LEFT JOIN resources ss ON ss.kind='services' AND ss.id=scope.service_id
 WHERE scope.delivery_id=coalesce((SELECT parent_id FROM notification_fallbacks WHERE child_id=d.id),d.id)
 AND NOT coalesce(ss.id IS NOT NULL AND ($2 OR ss.owner_id=$1 OR ($3<>'' AND ss.data->>'team'=$3)),false))`

func notificationInboxArgs(u User, status string) []any {
	return []any{u.ID, elevated(u), leadTeam(u), hasString(u.Scopes, "findings:read"), hasString(u.Scopes, "scans:read"), hasString(u.Scopes, "scans:approve"), status}
}
func (a *App) myNotifications(w http.ResponseWriter, r *http.Request) {
	page, size := 1, 25
	for key, p := range map[string]*int{"page": &page, "size": &size} {
		if raw := r.URL.Query().Get(key); raw != "" {
			n, e := strconv.Atoi(raw)
			if e != nil || n < 1 || key == "page" && n > 1000000 || key == "size" && n > 100 {
				fail(w, 400, "페이지와 표시 수(1~100)를 확인하세요")
				return
			}
			*p = n
		}
	}
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "all"
	}
	if !hasString([]string{"all", "pending", "acknowledged"}, status) {
		fail(w, 400, "업무 확인 상태를 선택하세요")
		return
	}
	args := notificationInboxArgs(currentUser(r), status)
	var total int
	if e := a.DB.QueryRow(r.Context(), `SELECT count(*)`+notificationInboxWhere, args...).Scan(&total); e != nil {
		fail(w, 500, "개인 알림 조회 실패")
		return
	}
	args = append(args, size, (page-1)*size)
	rows, e := a.DB.Query(r.Context(), `SELECT d.id,d.payload_encrypted,d.status,d.event_type,d.entity_id,d.service_id,d.created_at,d.acknowledged_at,d.ack_due_at`+notificationInboxWhere+` ORDER BY d.created_at DESC,d.id LIMIT $8 OFFSET $9`, args...)
	if e != nil {
		fail(w, 500, "개인 알림 조회 실패")
		return
	}
	items := []map[string]any{}
	for rows.Next() {
		var id, cipher, state, kind, entityID, serviceID string
		var created time.Time
		var ack, due *time.Time
		if e = rows.Scan(&id, &cipher, &state, &kind, &entityID, &serviceID, &created, &ack, &due); e != nil {
			break
		}
		plain, err := a.decrypt(cipher)
		if err != nil {
			e = err
			break
		}
		var m NotificationMessage
		if e = json.Unmarshal([]byte(plain), &m); e != nil {
			break
		}
		items = append(items, map[string]any{"id": id, "subject": m.Subject, "body": m.Body, "status": state, "event_type": kind, "entity_id": entityID, "service_id": serviceID, "created_at": created, "acknowledged_at": ack, "ack_due_at": due, "can_ack": ack == nil && due != nil})
	}
	rows.Close()
	if e != nil || rows.Err() != nil {
		fail(w, 500, "개인 알림 읽기 실패")
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}
func (a *App) ackNotification(w http.ResponseWriter, r *http.Request) {
	var empty struct{}
	if notificationDecode(r, &empty) != nil {
		fail(w, 400, "확인 요청 형식을 확인하세요")
		return
	}
	tx, e := a.DB.Begin(r.Context())
	if e != nil {
		fail(w, 500, "업무 확인 실패")
		return
	}
	defer tx.Rollback(r.Context())
	args := append(notificationInboxArgs(currentUser(r), "all"), r.PathValue("id"))
	var id string
	var ack, due *time.Time
	e = tx.QueryRow(r.Context(), `SELECT d.id,d.acknowledged_at,d.ack_due_at`+notificationInboxWhere+` AND d.id=$8 FOR UPDATE OF d`, args...).Scan(&id, &ack, &due)
	if e != nil {
		fail(w, 404, "확인할 수 있는 개인 알림이 없습니다")
		return
	}
	if due == nil {
		fail(w, 409, "업무 확인이 필요한 알림이 아닙니다")
		return
	}
	if ack == nil {
		sourceID, err := a.notificationMemberSource(r.Context(), tx, id)
		if err != nil {
			fail(w, 500, "업무 확인 원본 조회 실패")
			return
		}
		if _, err = tx.Exec(r.Context(), `UPDATE notification_deliveries SET acknowledged_at=coalesce(acknowledged_at,now()),updated_at=now() WHERE recipient_user_id=$2 AND (id=$1 OR id IN(SELECT child_id FROM notification_fallbacks WHERE parent_id=$1))`, sourceID, currentUser(r).ID); err != nil {
			fail(w, 500, "업무 확인 저장 실패")
			return
		}
		var at time.Time
		e = tx.QueryRow(r.Context(), `UPDATE notification_deliveries SET acknowledged_at=now(),updated_at=now() WHERE id=$1 RETURNING acknowledged_at`, id).Scan(&at)
		ack = &at
	}
	if e != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "업무 확인 저장 실패")
		return
	}
	a.audit(r, "notification.acknowledge", id, nil)
	jsonResponse(w, 200, map[string]any{"acknowledged_at": ack})
}
