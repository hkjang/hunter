package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type notificationDelivery struct {
	ID              string                `json:"id"`
	EventID         *int64                `json:"event_id"`
	EventType       string                `json:"event_type"`
	RuleID          string                `json:"rule_id"`
	RuleName        string                `json:"rule_name"`
	ChannelID       string                `json:"channel_id"`
	ChannelName     string                `json:"channel_name"`
	ChannelType     string                `json:"channel_type"`
	RecipientMasked string                `json:"recipient_masked"`
	Subject         string                `json:"subject"`
	Body            string                `json:"body,omitempty"`
	Status          string                `json:"status"`
	Attempts        int                   `json:"attempts"`
	MaxAttempts     int                   `json:"max_attempts"`
	AvailableAt     time.Time             `json:"available_at"`
	LastError       string                `json:"last_error"`
	ProviderID      string                `json:"provider_id"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
	SentAt          *time.Time            `json:"sent_at"`
	IsTest          bool                  `json:"is_test"`
	CancelRequested bool                  `json:"cancel_requested"`
	CanRetry        bool                  `json:"can_retry"`
	CanCancel       bool                  `json:"can_cancel"`
	AttemptLog      []notificationAttempt `json:"attempt_log,omitempty"`
}
type notificationAttempt struct {
	Attempt    int        `json:"attempt"`
	Status     string     `json:"status"`
	Code       string     `json:"code"`
	Detail     string     `json:"detail"`
	ProviderID string     `json:"provider_id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

const notificationDeliveryColumns = `id,event_id,event_type,rule_id,rule_name,channel_id,channel_name,channel_type,payload_encrypted,status,attempts,max_attempts,available_at,last_error,provider_id,created_at,updated_at,sent_at,is_test,cancel_requested`

func (a *App) scanNotificationDelivery(row pgx.Row, detail bool) (notificationDelivery, error) {
	var v notificationDelivery
	var cipher string
	err := row.Scan(&v.ID, &v.EventID, &v.EventType, &v.RuleID, &v.RuleName, &v.ChannelID, &v.ChannelName, &v.ChannelType, &cipher, &v.Status, &v.Attempts, &v.MaxAttempts, &v.AvailableAt, &v.LastError, &v.ProviderID, &v.CreatedAt, &v.UpdatedAt, &v.SentAt, &v.IsTest, &v.CancelRequested)
	if err != nil {
		return v, err
	}
	plain, err := a.decrypt(cipher)
	if err != nil {
		return v, err
	}
	var msg NotificationMessage
	if err = json.Unmarshal([]byte(plain), &msg); err != nil {
		return v, err
	}
	v.RecipientMasked = notificationRecipientMask(msg.Recipient)
	v.Subject = msg.Subject
	if detail {
		v.Body = msg.Body
	}
	v.CanRetry = hasString([]string{"failed", "uncertain"}, v.Status)
	v.CanCancel = hasString([]string{"queued", "retry", "sending"}, v.Status) && !v.CancelRequested
	return v, nil
}
func (a *App) notificationDelivery(ctx context.Context, id string, detail bool) (notificationDelivery, error) {
	return a.scanNotificationDelivery(a.DB.QueryRow(ctx, `SELECT `+notificationDeliveryColumns+` FROM notification_deliveries WHERE id=$1`, id), detail)
}
func (a *App) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	page, size := 1, 25
	for key, target := range map[string]*int{"page": &page, "size": &size} {
		if raw := r.URL.Query().Get(key); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 || key == "size" && v > 100 || key == "page" && v > 1000000 {
				fail(w, 400, "이력 페이지와 표시 수(1~100)를 확인하세요")
				return
			}
			*target = v
		}
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 500 {
		fail(w, 400, "검색어는 500바이트 이하로 입력하세요")
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && !hasString([]string{"queued", "sending", "sent", "retry", "failed", "uncertain", "cancelled"}, status) {
		fail(w, 400, "발송 상태를 확인하세요")
		return
	}
	sort := r.URL.Query().Get("sort")
	if sort == "" {
		sort = "created_at"
	}
	if !hasString([]string{"created_at", "updated_at", "available_at", "status", "attempts"}, sort) {
		fail(w, 400, "이력 정렬 항목을 확인하세요")
		return
	}
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		dir = "desc"
	}
	if dir != "asc" && dir != "desc" {
		fail(w, 400, "정렬 방향을 확인하세요")
		return
	}
	args := []any{status, r.URL.Query().Get("channel_id"), r.URL.Query().Get("event_type"), q}
	where := ` WHERE ($1='' OR status=$1) AND ($2='' OR channel_id=$2) AND ($3='' OR event_type=$3) AND ($4='' OR strpos(lower(concat_ws(' ',id,channel_name,rule_name,event_type)),lower($4))>0)`
	var total int
	if err := a.DB.QueryRow(r.Context(), `SELECT count(*) FROM notification_deliveries`+where, args...).Scan(&total); err != nil {
		fail(w, 500, "발송 이력 집계 실패")
		return
	}
	args = append(args, size, (page-1)*size)
	rows, err := a.DB.Query(r.Context(), `SELECT `+notificationDeliveryColumns+` FROM notification_deliveries`+where+` ORDER BY `+sort+` `+dir+`,id `+dir+` LIMIT $5 OFFSET $6`, args...)
	if err != nil {
		fail(w, 500, "발송 이력 조회 실패")
		return
	}
	items := []notificationDelivery{}
	for rows.Next() {
		item, e := a.scanNotificationDelivery(rows, false)
		if e != nil {
			err = e
			break
		}
		items = append(items, item)
	}
	rows.Close()
	if err != nil || rows.Err() != nil {
		fail(w, 500, "발송 이력을 읽지 못했습니다")
		return
	}
	summary := map[string]int{"queued": 0, "sending": 0, "sent": 0, "retry": 0, "failed": 0, "uncertain": 0, "cancelled": 0}
	counts, e := a.DB.Query(r.Context(), `SELECT status,count(*) FROM notification_deliveries GROUP BY status`)
	if e != nil {
		fail(w, 500, "발송 통계 조회 실패")
		return
	}
	for counts.Next() {
		var key string
		var n int
		if e = counts.Scan(&key, &n); e != nil {
			break
		}
		summary[key] = n
	}
	counts.Close()
	if e != nil || counts.Err() != nil {
		fail(w, 500, "발송 통계 조회 실패")
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size, "summary": summary, "as_of": time.Now().UTC()})
}
func (a *App) getNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	v, err := a.notificationDelivery(r.Context(), r.PathValue("id"), true)
	if err != nil {
		fail(w, 404, "발송 이력이 없습니다")
		return
	}
	rows, err := a.DB.Query(r.Context(), `SELECT attempt,status,code,detail,provider_id,started_at,finished_at FROM notification_attempts WHERE delivery_id=$1 ORDER BY attempt`, v.ID)
	if err != nil {
		fail(w, 500, "발송 시도 이력 조회 실패")
		return
	}
	v.AttemptLog = []notificationAttempt{}
	for rows.Next() {
		var item notificationAttempt
		if err = rows.Scan(&item.Attempt, &item.Status, &item.Code, &item.Detail, &item.ProviderID, &item.StartedAt, &item.FinishedAt); err != nil {
			break
		}
		v.AttemptLog = append(v.AttemptLog, item)
	}
	rows.Close()
	if err != nil || rows.Err() != nil {
		fail(w, 500, "발송 시도 이력을 읽지 못했습니다")
		return
	}
	jsonResponse(w, 200, v)
}
func (a *App) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Recipient string `json:"recipient"`
		Subject   string `json:"subject"`
		Body      string `json:"body"`
	}
	if notificationDecode(r, &input) != nil || len(input.Subject) > 200 || len(input.Body) > 16000 || strings.ContainsAny(input.Subject, "\r\n") {
		fail(w, 400, "테스트 수신자·제목(200바이트)·본문(16000바이트)을 확인하세요")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "테스트 알림 생성 실패")
		return
	}
	defer tx.Rollback(r.Context())
	c, err := a.notificationChannel(r.Context(), tx, r.PathValue("id"))
	if err != nil {
		fail(w, 404, "알림 채널이 없습니다")
		return
	}
	recipient, err := validateNotificationRecipient(c.Type, input.Recipient)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	subject := input.Subject
	if subject == "" {
		subject = "hunter 알림 채널 테스트"
	}
	body := input.Body
	if body == "" {
		body = "관리자가 명시적으로 요청한 알림 채널 테스트입니다."
	}
	vars := notificationSample()
	vars["event.type"] = "manual.test"
	vars["event.label"] = "테스트 알림"
	id, err := a.enqueueNotification(r.Context(), tx, notificationEvent{Type: "manual.test"}, notificationRule{}, c, NotificationMessage{Recipient: recipient, Subject: notificationText(subject, 200), Body: notificationText(body, 16000), Variables: vars}, true, currentUser(r))
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "테스트 알림을 큐에 등록하지 못했습니다")
		return
	}
	a.audit(r, "notification.test", id, map[string]any{"channel_id": c.ID, "type": c.Type})
	v, err := a.notificationDelivery(r.Context(), id, true)
	if err != nil {
		fail(w, 500, "테스트 이력을 읽지 못했습니다")
		return
	}
	jsonResponse(w, 201, v)
}
func (a *App) retryNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Confirm bool   `json:"confirm_duplicate_risk"`
		Reason  string `json:"reason"`
	}
	if notificationDecode(r, &input) != nil || len(input.Reason) > 1000 {
		fail(w, 400, "재시도 요청을 확인하세요")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "재시도 시작 실패")
		return
	}
	defer tx.Rollback(r.Context())
	var status string
	var isTest bool
	if tx.QueryRow(r.Context(), `SELECT status,is_test FROM notification_deliveries WHERE id=$1 FOR UPDATE`, r.PathValue("id")).Scan(&status, &isTest) != nil {
		fail(w, 404, "발송 이력이 없습니다")
		return
	}
	if !hasString([]string{"failed", "uncertain"}, status) {
		fail(w, 409, "실패 또는 결과 확인 필요 상태에서만 다시 시도할 수 있습니다")
		return
	}
	if status == "uncertain" && (!input.Confirm || len(strings.TrimSpace(input.Reason)) < 8) {
		fail(w, 400, "수신 시스템에서 결과와 중복 위험을 확인한 뒤 확인 여부와 사유(8바이트 이상)를 입력하세요")
		return
	}
	u := currentUser(r)
	_, err = tx.Exec(r.Context(), `UPDATE notification_deliveries SET status='queued',attempts=0,available_at=now(),cancel_requested=false,last_error='',lease_token='',lease_until=NULL,updated_at=now(),requested_by=CASE WHEN is_test THEN $2 ELSE requested_by END,credential_key_id=CASE WHEN is_test THEN $3 ELSE credential_key_id END WHERE id=$1`, r.PathValue("id"), u.ID, u.KeyID)
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "재시도를 등록하지 못했습니다")
		return
	}
	a.audit(r, "notification.retry", r.PathValue("id"), map[string]any{"previous_status": status, "duplicate_risk_confirmed": input.Confirm, "reason": notificationText(input.Reason, 1000)})
	v, err := a.notificationDelivery(r.Context(), r.PathValue("id"), true)
	if err != nil {
		fail(w, 500, "재시도 이력 조회 실패")
		return
	}
	jsonResponse(w, 200, v)
}
func (a *App) cancelNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	tag, err := a.DB.Exec(r.Context(), `UPDATE notification_deliveries SET status=CASE WHEN status='sending' THEN status ELSE 'cancelled' END,cancel_requested=true,last_error=CASE WHEN status='sending' THEN '발송 취소 요청: 이미 접수된 메시지는 취소할 수 없습니다' ELSE '관리자가 발송을 취소했습니다' END,updated_at=now() WHERE id=$1 AND status IN('queued','retry','sending') AND NOT cancel_requested`, r.PathValue("id"))
	if err != nil {
		fail(w, 500, "알림 취소 실패")
		return
	}
	if tag.RowsAffected() != 1 {
		fail(w, 409, "취소할 수 있는 대기 또는 발송 중 알림이 없습니다")
		return
	}
	a.audit(r, "notification.cancel", r.PathValue("id"), nil)
	v, err := a.notificationDelivery(r.Context(), r.PathValue("id"), true)
	if err != nil {
		fail(w, 500, "취소 이력 조회 실패")
		return
	}
	jsonResponse(w, 200, v)
}
