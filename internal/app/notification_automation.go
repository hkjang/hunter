package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/jackc/pgx/v5"
)

type notificationContact struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	WebhookID string `json:"webhook_id"`
	Verified  bool   `json:"verified"`
}
type notificationOnCall struct {
	Team     string    `json:"team"`
	UserID   string    `json:"user_id"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}
type notificationAutomation struct {
	Enabled  bool                  `json:"enabled"`
	Timezone string                `json:"timezone"`
	Contacts []notificationContact `json:"contacts"`
	OnCall   []notificationOnCall  `json:"on_call"`
	Grouping struct {
		Enabled              bool     `json:"enabled"`
		WindowMinutes        int      `json:"window_minutes"`
		EmergencySeverities  []string `json:"emergency_severities"`
		RecipientHourlyLimit int      `json:"recipient_hourly_limit"`
	} `json:"grouping"`
	Calendar struct {
		Enabled            bool     `json:"enabled"`
		Weekdays           []int    `json:"weekdays"`
		Holidays           []string `json:"holidays"`
		RemindBusinessDays int      `json:"remind_business_days"`
	} `json:"calendar"`
	Acknowledgement struct {
		Enabled        bool `json:"enabled"`
		TimeoutMinutes int  `json:"timeout_minutes"`
	} `json:"acknowledgement"`
	Weekly struct {
		Enabled bool `json:"enabled"`
		Weekday int  `json:"weekday"`
		Hour    int  `json:"hour"`
	} `json:"weekly"`
	Retention struct {
		Enabled     bool `json:"enabled"`
		PayloadDays int  `json:"payload_days"`
	} `json:"retention"`
}

func defaultNotificationAutomation() notificationAutomation {
	var c notificationAutomation
	c.Timezone = "Asia/Seoul"
	c.Contacts = []notificationContact{}
	c.OnCall = []notificationOnCall{}
	c.Grouping.WindowMinutes = 5
	c.Grouping.RecipientHourlyLimit = 30
	c.Grouping.EmergencySeverities = []string{"critical"}
	c.Calendar.Weekdays = []int{1, 2, 3, 4, 5}
	c.Calendar.Holidays = []string{}
	c.Calendar.RemindBusinessDays = 2
	c.Acknowledgement.TimeoutMinutes = 60
	c.Weekly.Weekday = 1
	c.Weekly.Hour = 9
	c.Retention.PayloadDays = 90
	return c
}
func (a *App) initNotificationAutomation(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS notification_automation(id boolean PRIMARY KEY DEFAULT true CHECK(id),config_encrypted text NOT NULL,updated_at timestamptz NOT NULL DEFAULT now());
 ALTER TABLE notification_deliveries ADD COLUMN IF NOT EXISTS recipient_user_id text NOT NULL DEFAULT '';
 ALTER TABLE notification_deliveries ADD COLUMN IF NOT EXISTS automation_revision timestamptz;
 ALTER TABLE notification_deliveries ADD COLUMN IF NOT EXISTS group_key text NOT NULL DEFAULT '';
 ALTER TABLE notification_deliveries ADD COLUMN IF NOT EXISTS ack_due_at timestamptz;
 ALTER TABLE notification_deliveries ADD COLUMN IF NOT EXISTS acknowledged_at timestamptz;
 ALTER TABLE notification_deliveries ADD COLUMN IF NOT EXISTS retention_hold boolean NOT NULL DEFAULT false;
 ALTER TABLE notification_deliveries ADD COLUMN IF NOT EXISTS payload_purged_at timestamptz;
 CREATE INDEX IF NOT EXISTS notification_deliveries_recipient ON notification_deliveries(recipient_user_id,created_at DESC);
 CREATE INDEX IF NOT EXISTS notification_deliveries_group ON notification_deliveries(group_key) WHERE status='queued' AND group_key<>'';
 CREATE TABLE IF NOT EXISTS notification_delivery_members(event_id bigint NOT NULL REFERENCES notification_events(id),rule_id text NOT NULL,recipient_hash text NOT NULL,delivery_id text NOT NULL REFERENCES notification_deliveries(id),entity_id text NOT NULL,service_id text NOT NULL,PRIMARY KEY(event_id,rule_id,recipient_hash));
 CREATE INDEX IF NOT EXISTS notification_delivery_members_delivery ON notification_delivery_members(delivery_id);
 CREATE TABLE IF NOT EXISTS notification_delivery_scope(delivery_id text NOT NULL REFERENCES notification_deliveries(id),service_id text NOT NULL,PRIMARY KEY(delivery_id,service_id));
 CREATE TABLE IF NOT EXISTS notification_simulations(id text PRIMARY KEY,created_at timestamptz NOT NULL DEFAULT now(),result jsonb NOT NULL);
 CREATE TABLE IF NOT EXISTS notification_automation_ticks(key text PRIMARY KEY,updated_at timestamptz NOT NULL DEFAULT now());`)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(defaultNotificationAutomation())
	cipher, err := a.encrypt(string(raw))
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO notification_automation(id,config_encrypted) VALUES(true,$1) ON CONFLICT DO NOTHING`, cipher)
	return err
}
func (a *App) notificationAutomationConfig(ctx context.Context, q notificationQuerier) (notificationAutomation, time.Time, error) {
	c := defaultNotificationAutomation()
	var cipher string
	var revision time.Time
	err := q.QueryRow(ctx, `SELECT config_encrypted,updated_at FROM notification_automation WHERE id`).Scan(&cipher, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, revision, nil
	}
	if err != nil {
		return c, revision, err
	}
	plain, err := a.decrypt(cipher)
	if err == nil {
		err = json.Unmarshal([]byte(plain), &c)
	}
	return c, revision, err
}
func (a *App) validateNotificationAutomation(ctx context.Context, q notificationQuerier, c *notificationAutomation) error {
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return errors.New("유효한 IANA 시간대를 입력하세요")
	}
	if len(c.Contacts) > 500 || len(c.OnCall) > 500 {
		return errors.New("연락처와 당직은 각각 500개 이하입니다")
	}
	seen := map[string]bool{}
	for i := range c.Contacts {
		v := &c.Contacts[i]
		var exists bool
		if v.UserID == "" || seen[v.UserID] {
			return errors.New("연락처 사용자 중복을 확인하세요")
		}
		seen[v.UserID] = true
		if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND NOT disabled)`, v.UserID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errors.New("활성 사용자를 연락처로 선택하세요")
		}
		for kind, p := range map[string]*string{"smtp": &v.Email, "sms": &v.Phone, "webhook": &v.WebhookID} {
			if *p != "" {
				n, e := validateNotificationRecipient(kind, *p)
				if e != nil {
					return e
				}
				*p = n
			}
		}
	}
	for _, v := range c.OnCall {
		if !notificationName(v.Team) || !seen[v.UserID] || v.StartsAt.IsZero() || !v.EndsAt.After(v.StartsAt) || v.EndsAt.Sub(v.StartsAt) > 366*24*time.Hour {
			return errors.New("당직은 연락처의 사용자·조직·시작/종료일(최대 366일)을 지정하세요")
		}
	}
	if c.Grouping.WindowMinutes < 5 || c.Grouping.WindowMinutes > 1440 || c.Grouping.RecipientHourlyLimit < 1 || c.Grouping.RecipientHourlyLimit > 1000 {
		return errors.New("묶음은 5~1440분, 수신자별 시간당 한도는 1~1000건입니다")
	}
	for _, v := range c.Grouping.EmergencySeverities {
		if !hasString([]string{"critical", "high", "medium", "low", "info"}, v) {
			return errors.New("긴급 예외 심각도를 확인하세요")
		}
	}
	if len(c.Calendar.Weekdays) < 1 || len(c.Calendar.Weekdays) > 7 || len(c.Calendar.Holidays) > 1000 || c.Calendar.RemindBusinessDays < 1 || c.Calendar.RemindBusinessDays > 30 {
		return errors.New("영업일·휴일(최대 1000개)·예고 기간(1~30 영업일)을 확인하세요")
	}
	days := map[int]bool{}
	for _, d := range c.Calendar.Weekdays {
		if d < 0 || d > 6 || days[d] {
			return errors.New("영업일 요일은 중복 없는 0~6입니다")
		}
		days[d] = true
	}
	for _, d := range c.Calendar.Holidays {
		if _, err := time.Parse("2006-01-02", d); err != nil {
			return errors.New("휴일은 YYYY-MM-DD로 입력하세요")
		}
	}
	if c.Acknowledgement.TimeoutMinutes < 5 || c.Acknowledgement.TimeoutMinutes > 10080 {
		return errors.New("업무 확인 제한은 5~10080분입니다")
	}
	if c.Weekly.Weekday < 0 || c.Weekly.Weekday > 6 || c.Weekly.Hour < 0 || c.Weekly.Hour > 23 {
		return errors.New("주간 요일은 0~6, 시각은 0~23입니다")
	}
	if c.Retention.PayloadDays < 1 || c.Retention.PayloadDays > 3650 {
		return errors.New("보존 기간은 1~3650일입니다")
	}
	return nil
}
func (a *App) registerNotificationAutomation(m *http.ServeMux) {
	m.HandleFunc("GET /api/notification-automation", a.protect("admin:manage", a.getNotificationAutomation))
	m.HandleFunc("PUT /api/notification-automation", a.protect("admin:manage", a.putNotificationAutomation))
	m.HandleFunc("POST /api/notification-automation/simulate", a.protect("admin:manage", a.simulateNotifications))
	m.HandleFunc("GET /api/notification-automation/simulations", a.protect("admin:manage", a.listNotificationSimulations))
	m.HandleFunc("GET /api/my-notifications", a.protect("services:read", a.myNotifications))
	m.HandleFunc("POST /api/my-notifications/{id}/ack", a.protect("services:read", a.ackNotification))
	m.HandleFunc("POST /api/notification-deliveries/{id}/hold", a.protect("admin:manage", a.holdNotification))
}
func (a *App) getNotificationAutomation(w http.ResponseWriter, r *http.Request) {
	c, t, e := a.notificationAutomationConfig(r.Context(), a.DB)
	if e != nil {
		fail(w, 500, "자동화 설정 조회 실패")
		return
	}
	jsonResponse(w, 200, map[string]any{"config": c, "updated_at": t})
}
func (a *App) putNotificationAutomation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Config   notificationAutomation `json:"config"`
		Expected string                 `json:"expected_updated_at"`
	}
	if notificationDecode(r, &in) != nil {
		fail(w, 400, "자동화 설정 형식을 확인하세요")
		return
	}
	exp, e := time.Parse(time.RFC3339Nano, in.Expected)
	if e != nil {
		fail(w, 400, "조회한 updated_at을 expected_updated_at으로 보내세요")
		return
	}
	tx, e := a.DB.Begin(r.Context())
	if e != nil {
		fail(w, 500, "설정 저장 실패")
		return
	}
	defer tx.Rollback(r.Context())
	if e = a.validateNotificationAutomation(r.Context(), tx, &in.Config); e != nil {
		fail(w, 400, e.Error())
		return
	}
	raw, _ := json.Marshal(in.Config)
	cipher, e := a.encrypt(string(raw))
	if e != nil {
		fail(w, 500, "설정 암호화 실패")
		return
	}
	var rev time.Time
	e = tx.QueryRow(r.Context(), `UPDATE notification_automation SET config_encrypted=$1,updated_at=clock_timestamp() WHERE id AND updated_at=$2 RETURNING updated_at`, cipher, exp).Scan(&rev)
	if errors.Is(e, pgx.ErrNoRows) {
		fail(w, 409, "자동화 설정이 변경되었습니다. 최신 설정을 확인하세요")
		return
	}
	if e != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "설정 저장 실패")
		return
	}
	a.audit(r, "notification.automation.update", "automation", map[string]any{"enabled": in.Config.Enabled, "contacts": len(in.Config.Contacts)})
	jsonResponse(w, 200, map[string]any{"config": in.Config, "updated_at": rev})
}
func (a *App) holdNotification(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hold   bool   `json:"hold"`
		Reason string `json:"reason"`
	}
	if notificationDecode(r, &in) != nil || len(strings.TrimSpace(in.Reason)) < 8 || len(in.Reason) > 1000 {
		fail(w, 400, "보존 보류 사유는 8~1000바이트로 입력하세요")
		return
	}
	tag, e := a.DB.Exec(r.Context(), `UPDATE notification_deliveries SET retention_hold=$2,updated_at=now() WHERE id=$1 AND payload_purged_at IS NULL`, r.PathValue("id"), in.Hold)
	if e != nil {
		fail(w, 500, "보존 설정 실패")
		return
	}
	if tag.RowsAffected() != 1 {
		fail(w, 409, "항목이 없거나 이미 본문이 파기되었습니다")
		return
	}
	a.audit(r, "notification.retention.hold", r.PathValue("id"), map[string]any{"hold": in.Hold, "reason": notificationText(in.Reason, 1000)})
	jsonResponse(w, 200, map[string]bool{"hold": in.Hold})
}
func notificationBusinessDays(c notificationAutomation, now, due time.Time) int {
	loc, _ := time.LoadLocation(c.Timezone)
	if loc == nil {
		loc = time.UTC
	}
	n, d := now.In(loc), due.In(loc)
	cur := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc)
	end := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc)
	days := 0
	for i := 0; cur.Before(end) && i < 3660; i++ {
		cur = cur.AddDate(0, 0, 1)
		open := false
		for _, v := range c.Calendar.Weekdays {
			open = open || v == int(cur.Weekday())
		}
		if open && !hasString(c.Calendar.Holidays, cur.Format("2006-01-02")) {
			days++
		}
	}
	return days
}
func notificationAutoError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("알림 자동화 %s: %w", action, err)
}
