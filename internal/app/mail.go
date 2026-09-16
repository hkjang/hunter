package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Event notifications over the in-house SMTP relay (MAIL-STANDARD.md).
//
// This is deliberately smaller than the rule-based notification centre: one relay
// configured under the standard's `mail.*` keys, a fixed set of events people actually
// wait for, and one row per attempt so an administrator can answer "it never arrived".
//
//   - Mail never blocks a request: the event site writes an outbox row in its own
//     transaction and the control server's loop sends it. Worker-only processes only
//     write rows, since they may not be able to reach the relay from their segment.
//   - The record keeps event, recipient, subject and outcome — never the body. The body
//     is held encrypted only until the attempt finishes and is cleared afterwards.
//   - Recipients are account ids resolved through the directory Hunter already has
//     (verified contact e-mail, else a username that is an address). No new user table.
//   - The actor of an action is never told about their own action, and rows for the
//     same recipient and event that queue up together go out as one message.
const (
	mailSettingsGroup   = "mail"
	mailMaxAttempts     = 2
	mailRetryDelay      = 30 * time.Second
	mailLeaseDuration   = 2 * time.Minute
	mailRetentionPeriod = 90 * 24 * time.Hour
	mailHistoryLimit    = 200
	mailBundleLimit     = 50
)

// Rows wait this long before sending so one action's burst goes out as one message.
var mailCoalesceWindow = 10 * time.Second

type mailEvent struct {
	Key   string
	Label string
}

// mailEvents are the events whose absence costs someone time: an approver who does not
// know a request is waiting, a requester whose scan or agent stopped, a person whose
// turn it is. Plain "something changed" events stay in the notification centre.
var mailEvents = []mailEvent{
	{"approval_requested", "진단 검토 요청"},
	{"approval_decided", "진단 검토 결과"},
	{"scan_failed", "진단 실패"},
	{"agent_waiting", "에이전트 입력 대기"},
	{"agent_failed", "에이전트 실행 중단"},
}

func mailEventLabel(key string) string {
	for _, e := range mailEvents {
		if e.Key == key {
			return e.Label
		}
	}
	if key == "test" {
		return "시험 발송"
	}
	return key
}

func mailDefaultSettings() map[string]any {
	// An in-house relay is usually port 25 without credentials or TLS; auto follows
	// what the server advertises. Everything stays off until an administrator enables it.
	out := map[string]any{"enabled": false, "smtp_host": "", "smtp_port": 25, "security": "auto", "skip_tls_verify": false,
		"username": "", "password": "", "from_address": "", "from_name": "Hunter", "base_url": "", "timeout_seconds": 10}
	for _, e := range mailEvents {
		out["notify_"+e.Key] = true
	}
	return out
}

type mailConfig struct {
	Enabled     bool
	Host        string
	Port        int
	Security    string
	SkipVerify  bool
	Username    string
	Password    string
	FromAddress string
	FromName    string
	BaseURL     string
	Timeout     time.Duration
	Notify      map[string]bool
}

type mailStore interface {
	notificationQuerier
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func mailHostValid(host string) bool {
	return host != "" && len(host) <= 253 && !strings.ContainsAny(host, "/@?#{}[] \\") && strings.IndexFunc(host, unicode.IsControl) < 0 && (!strings.Contains(host, ":") || net.ParseIP(host) != nil)
}

// validateMailSettings checks the `mail` group. Host and sender are only required once
// the relay is switched on, so a half-filled form can still be saved while disabled.
func validateMailSettings(v map[string]any) error {
	for _, k := range []string{"smtp_host", "security", "username", "from_address", "from_name", "base_url"} {
		s, ok := v[k].(string)
		if !ok || len(s) > 320 || strings.ContainsAny(s, "\r\n\x00") {
			return fmt.Errorf("%s 값을 확인해 주세요", k)
		}
		v[k] = strings.TrimSpace(s)
	}
	port := asInt(v["smtp_port"])
	if port < 1 || port > 65535 || fmt.Sprint(v["smtp_port"]) != fmt.Sprint(port) {
		return errors.New("SMTP 포트는 1~65535 정수여야 합니다")
	}
	v["smtp_port"] = port
	timeout := asInt(v["timeout_seconds"])
	if timeout < 1 || timeout > 120 || fmt.Sprint(v["timeout_seconds"]) != fmt.Sprint(timeout) {
		return errors.New("연결 시간 제한은 1~120초 정수여야 합니다")
	}
	v["timeout_seconds"] = timeout
	if !hasString([]string{"auto", "none", "starttls", "tls"}, asString(v["security"])) {
		return errors.New("보안 협상은 auto·none·starttls·tls 중 하나여야 합니다")
	}
	if host := asString(v["smtp_host"]); host != "" && !mailHostValid(host) {
		return errors.New("SMTP 릴레이 호스트 이름을 확인해 주세요")
	}
	if from := asString(v["from_address"]); from != "" {
		if _, err := validateNotificationRecipient("smtp", from); err != nil {
			return errors.New("보내는 사람 주소를 확인해 주세요")
		}
	}
	if base := asString(v["base_url"]); base != "" && !validURL(base) {
		return errors.New("메일 속 링크 주소는 http(s) URL이어야 합니다")
	}
	if asBool(v["enabled"]) && (asString(v["smtp_host"]) == "" || asString(v["from_address"]) == "") {
		return errors.New("메일 알림을 켜려면 SMTP 릴레이 호스트와 보내는 사람 주소가 필요합니다")
	}
	return nil
}

// mailConfigFrom reads the relay configuration through the caller's querier so an event
// site inside a transaction does not borrow a second pool connection.
func (a *App) mailConfigFrom(ctx context.Context, q notificationQuerier) (mailConfig, error) {
	v, err := notificationSetting(ctx, q, mailSettingsGroup)
	if err != nil {
		return mailConfig{}, err
	}
	c := mailConfig{Enabled: asBool(v["enabled"]), Host: strings.TrimSpace(asString(v["smtp_host"])), Port: asInt(v["smtp_port"]), Security: asString(v["security"]),
		SkipVerify: asBool(v["skip_tls_verify"]), Username: strings.TrimSpace(asString(v["username"])), FromAddress: strings.TrimSpace(asString(v["from_address"])),
		FromName: strings.TrimSpace(asString(v["from_name"])), BaseURL: strings.TrimRight(strings.TrimSpace(asString(v["base_url"])), "/"),
		Timeout: time.Duration(asInt(v["timeout_seconds"])) * time.Second, Notify: map[string]bool{}}
	if s := asString(v["password"]); s != "" {
		if c.Password, err = a.decrypt(s); err != nil {
			return mailConfig{}, errors.New("SMTP 비밀번호를 읽지 못했습니다")
		}
	}
	if c.Port == 0 {
		c.Port = 25
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Security == "" {
		c.Security = "auto"
	}
	// The implicit TLS port needs no extra configuration.
	if c.Security == "auto" && c.Port == 465 {
		c.Security = "tls"
	}
	for _, e := range mailEvents {
		on, ok := v["notify_"+e.Key].(bool)
		c.Notify[e.Key] = !ok || on
	}
	if c.BaseURL == "" {
		g, e := notificationSetting(ctx, q, "general")
		if e == nil {
			c.BaseURL = strings.TrimRight(asString(g["public_url"]), "/")
		}
	}
	return c, nil
}

// ready explains why nothing would be sent, which is what the delivery record shows.
func (c mailConfig) ready() error {
	if !c.Enabled {
		return errors.New("메일 알림이 꺼져 있습니다")
	}
	if c.Host == "" {
		return errors.New("SMTP 릴레이 호스트가 없습니다")
	}
	if _, err := mail.ParseAddress(c.FromAddress); err != nil {
		return errors.New("보내는 사람 주소가 없습니다")
	}
	return nil
}

func (c mailConfig) channel() NotificationChannel {
	from := c.FromAddress
	if c.FromName != "" {
		from = (&mail.Address{Name: c.FromName, Address: c.FromAddress}).String()
	}
	return NotificationChannel{ID: "mail", Name: "사내 메일 릴레이", Type: "smtp", Enabled: c.Enabled, Secret: c.Password,
		Config: map[string]any{"host": c.Host, "port": c.Port, "security": c.Security, "skip_tls_verify": c.SkipVerify, "from": from, "username": c.Username, "auth": "plain", "timeout_seconds": int(c.Timeout / time.Second)}}
}

func (a *App) initMail(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS mail_deliveries(
 id text PRIMARY KEY,event text NOT NULL,recipient text NOT NULL,recipient_user_id text NOT NULL DEFAULT '',subject text NOT NULL,
 entity_id text NOT NULL DEFAULT '',actor_id text NOT NULL DEFAULT '',body_encrypted text NOT NULL DEFAULT '',
 status text NOT NULL DEFAULT 'queued' CHECK(status IN('queued','sending','sent','failed')),attempts integer NOT NULL DEFAULT 0,
 detail text NOT NULL DEFAULT '',available_at timestamptz NOT NULL DEFAULT now(),lease_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),sent_at timestamptz);
 CREATE INDEX IF NOT EXISTS mail_deliveries_ready ON mail_deliveries(available_at) WHERE status IN('queued','sending');
 CREATE INDEX IF NOT EXISTS mail_deliveries_history ON mail_deliveries(created_at DESC);`)
	if err == nil {
		a.mailWake = make(chan struct{}, 1)
	}
	return err
}

// mailAddresses is the one directory lookup the standard allows: account id to address.
// A verified contact e-mail from the notification centre wins; otherwise a username that
// is itself an address is used. Disabled accounts and unknown ids resolve to nothing.
func (a *App) mailAddresses(ctx context.Context, q mailStore, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	cfg, _, err := a.notificationAutomationConfig(ctx, q)
	if err != nil {
		return nil, err
	}
	contacts := map[string]string{}
	for _, c := range cfg.Contacts {
		if c.Verified && c.Email != "" {
			contacts[c.UserID] = c.Email
		}
	}
	rows, err := q.Query(ctx, `SELECT id,username FROM users WHERE NOT disabled AND id=ANY($1::text[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, username string
		if err = rows.Scan(&id, &username); err != nil {
			return nil, err
		}
		address := contacts[id]
		if address == "" {
			address = username
		}
		if normal, e := validateNotificationRecipient("smtp", address); e == nil {
			out[id] = normal
		}
	}
	return out, rows.Err()
}

// mailApprovers are the people who can act on a pending review of a service: every
// administrator and the leads of the service's team.
func mailApprovers(ctx context.Context, q mailStore, team string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT id FROM users WHERE NOT disabled AND (role='admin' OR (role='lead' AND team<>'' AND team=$1)) ORDER BY id`, team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

type mailNotice struct {
	Event    string
	EntityID string
	Subject  string
	Body     string
	Path     string // appended as a link when a base URL is known
}

// mailNotify queues one row per resolved recipient, skipping the actor. It never fails the
// caller: a relay problem, a missing address or a disabled switch only leaves a log line.
// Rows are written through q so they commit or roll back with the event that caused them.
func (a *App) mailNotify(ctx context.Context, q mailStore, actorID string, recipients []string, n mailNotice) {
	if a.mailWake == nil || len(recipients) == 0 {
		return
	}
	c, err := a.mailConfigFrom(ctx, q)
	if err != nil {
		slog.Warn("mail configuration unreadable", "event", n.Event)
		return
	}
	if !c.Enabled || !c.Notify[n.Event] {
		return
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == actorID || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	addresses, err := a.mailAddresses(ctx, q, ids)
	if err != nil {
		slog.Warn("mail recipients were not resolved", "event", n.Event)
		return
	}
	text := n.Body
	if link := c.mailLink(n.Path); link != "" {
		text += "\n\n바로 가기: " + link
	}
	body, err := a.encrypt(notificationText(text, 20000))
	if err != nil {
		return
	}
	subject := notificationText(strings.Join(strings.Fields(n.Subject), " "), 300)
	used := map[string]bool{}
	for _, id := range ids {
		address := addresses[id]
		if address == "" || used[strings.ToLower(address)] {
			continue
		}
		used[strings.ToLower(address)] = true
		_, err = q.Exec(ctx, `INSERT INTO mail_deliveries(id,event,recipient,recipient_user_id,subject,entity_id,actor_id,body_encrypted,available_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+$9::interval)`,
			newID(), n.Event, address, id, subject, n.EntityID, actorID, body, mailCoalesceWindow.String())
		if err != nil {
			slog.Warn("mail delivery was not recorded", "event", n.Event)
			return
		}
	}
	select {
	case a.mailWake <- struct{}{}:
	default:
	}
}

func (a *App) StartMail(ctx context.Context) {
	if a.mailWake != nil {
		go a.mailLoop(ctx)
	}
}

func (a *App) mailLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	lastSweep := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.mailWake:
			// A fresh row is not due until its coalescing window closes.
			select {
			case <-ctx.Done():
				return
			case <-time.After(mailCoalesceWindow + time.Second):
			}
		}
		if time.Since(lastSweep) > time.Hour {
			_, _ = a.DB.Exec(ctx, `DELETE FROM mail_deliveries WHERE status IN('sent','failed') AND created_at<now()-$1::interval`, mailRetentionPeriod.String())
			lastSweep = time.Now()
		}
		for i := 0; i < 20; i++ {
			worked, err := a.mailDeliver(ctx)
			if err != nil && ctx.Err() == nil {
				slog.Error("mail delivery processing failed")
			}
			if !worked || ctx.Err() != nil {
				break
			}
		}
	}
}

type mailClaim struct {
	IDs       []string
	Event     string
	Recipient string
	Subject   string
	Bodies    []string
	Attempts  int
}

// mailDeliver claims the oldest due row, gathers its siblings (same recipient and event,
// also due) into one message, sends once and records the outcome on every row.
func (a *App) mailDeliver(ctx context.Context) (bool, error) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var head mailClaim
	var id, cipher string
	err = tx.QueryRow(ctx, `SELECT id,event,recipient,subject,body_encrypted,attempts FROM mail_deliveries WHERE available_at<=now() AND (status='queued' OR (status='sending' AND lease_until<now())) ORDER BY available_at,created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id, &head.Event, &head.Recipient, &head.Subject, &cipher, &head.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	head.IDs = []string{id}
	bodies := []string{cipher}
	subjects := []string{head.Subject}
	rows, err := tx.Query(ctx, `SELECT id,subject,body_encrypted FROM mail_deliveries WHERE id<>$1 AND event=$2 AND lower(recipient)=lower($3) AND available_at<=now() AND status='queued' ORDER BY created_at,id LIMIT $4 FOR UPDATE SKIP LOCKED`, id, head.Event, head.Recipient, mailBundleLimit-1)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var sid, ssubject, sbody string
		if err = rows.Scan(&sid, &ssubject, &sbody); err != nil {
			rows.Close()
			return false, err
		}
		head.IDs = append(head.IDs, sid)
		subjects = append(subjects, ssubject)
		bodies = append(bodies, sbody)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE mail_deliveries SET status='sending',attempts=attempts+1,lease_until=now()+$2::interval,updated_at=now() WHERE id=ANY($1::text[])`, head.IDs, mailLeaseDuration.String()); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	head.Attempts++
	for _, b := range bodies {
		plain, e := a.decrypt(b)
		if e != nil {
			plain = "(본문을 읽지 못했습니다)"
		}
		head.Bodies = append(head.Bodies, plain)
	}
	if len(head.IDs) > 1 {
		head.Subject = fmt.Sprintf("[Hunter] %s %d건", mailEventLabel(head.Event), len(head.IDs))
	}
	c, err := a.mailConfigFrom(ctx, a.DB)
	result := NotificationSendResult{State: "failed", Code: "config", Detail: "메일 설정을 읽지 못했습니다"}
	if err == nil {
		if e := c.ready(); e != nil {
			result = NotificationSendResult{State: "failed", Code: "not_ready", Detail: e.Error()}
		} else {
			sendCtx, cancel := context.WithTimeout(ctx, c.Timeout+5*time.Second)
			result = a.sendSMTPNotification(sendCtx, c.channel(), NotificationMessage{DeliveryID: head.IDs[0], Recipient: head.Recipient, Subject: head.Subject, Body: strings.Join(head.Bodies, "\n\n----------------------------------------\n\n")})
			cancel()
		}
	}
	return true, a.mailFinish(ctx, head, result)
}

func (a *App) mailFinish(ctx context.Context, c mailClaim, result NotificationSendResult) error {
	detail := notificationText(result.Detail, 500)
	if len(c.IDs) > 1 {
		detail = fmt.Sprintf("%d건 묶음 · %s", len(c.IDs), detail)
	}
	status := "failed"
	switch {
	case result.State == "sent":
		status = "sent"
	case (result.State == "retryable" || result.State == "uncertain") && c.Attempts < mailMaxAttempts:
		// A relay that briefly refuses is common; losing the notification costs more than a short wait.
		_, err := a.DB.Exec(ctx, `UPDATE mail_deliveries SET status='queued',available_at=now()+$2::interval,lease_until=NULL,detail=$3,updated_at=now() WHERE id=ANY($1::text[]) AND status='sending'`, c.IDs, mailRetryDelay.String(), detail)
		return err
	}
	if result.State != "sent" && result.Code != "" {
		slog.Warn("notification mail failed", "event", c.Event, "code", result.Code)
	}
	// The body leaves the record as soon as the attempt is over.
	_, err := a.DB.Exec(ctx, `UPDATE mail_deliveries SET status=$2,detail=$3,body_encrypted='',lease_until=NULL,sent_at=CASE WHEN $2='sent' THEN now() END,updated_at=now() WHERE id=ANY($1::text[]) AND status='sending'`, c.IDs, status, detail)
	return err
}

func (a *App) registerMail(m *http.ServeMux) {
	m.HandleFunc("GET /api/admin/mail/deliveries", a.protect("admin:manage", a.listMailDeliveries))
	m.HandleFunc("POST /api/admin/mail/test", a.protect("admin:manage", a.testMail))
}

type mailDelivery struct {
	ID          string     `json:"id"`
	Event       string     `json:"event"`
	EventLabel  string     `json:"event_label"`
	Recipient   string     `json:"recipient"`
	RecipientID string     `json:"recipient_user_id"`
	Subject     string     `json:"subject"`
	EntityID    string     `json:"entity_id"`
	ActorID     string     `json:"actor_id"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	Detail      string     `json:"detail"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	SentAt      *time.Time `json:"sent_at"`
}

func (a *App) listMailDeliveries(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(r.Context(), `SELECT id,event,recipient,recipient_user_id,subject,entity_id,actor_id,status,attempts,detail,created_at,updated_at,sent_at FROM mail_deliveries ORDER BY created_at DESC,id LIMIT $1`, mailHistoryLimit)
	if err != nil {
		fail(w, 500, "발송 기록을 읽지 못했습니다")
		return
	}
	defer rows.Close()
	items := []mailDelivery{}
	summary := map[string]int{}
	for rows.Next() {
		var d mailDelivery
		if err = rows.Scan(&d.ID, &d.Event, &d.Recipient, &d.RecipientID, &d.Subject, &d.EntityID, &d.ActorID, &d.Status, &d.Attempts, &d.Detail, &d.CreatedAt, &d.UpdatedAt, &d.SentAt); err != nil {
			fail(w, 500, "발송 기록을 읽지 못했습니다")
			return
		}
		d.EventLabel = mailEventLabel(d.Event)
		summary[d.Status]++
		items = append(items, d)
	}
	if rows.Err() != nil {
		fail(w, 500, "발송 기록을 읽지 못했습니다")
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "summary": map[string]any{"total": len(items), "status": summary}, "limit": mailHistoryLimit})
}

// testMail sends one real message with the saved configuration and reports the outcome in
// place, because a relay setting is rarely right the first time. The attempt is recorded
// like any other so the history shows what left the building.
func (a *App) testMail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		To string `json:"to"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "받는 사람 주소를 입력해 주세요")
		return
	}
	u := currentUser(r)
	to := strings.TrimSpace(in.To)
	if to == "" {
		addresses, err := a.mailAddresses(r.Context(), a.DB, []string{u.ID})
		if err != nil {
			fail(w, 500, "받는 사람 주소를 찾지 못했습니다")
			return
		}
		to = addresses[u.ID]
	}
	recipient, err := validateNotificationRecipient("smtp", to)
	if err != nil {
		fail(w, 400, "받는 사람 주소를 확인해 주세요. 내 계정에 메일 주소가 없으면 직접 입력하세요")
		return
	}
	c, err := a.mailConfigFrom(r.Context(), a.DB)
	if err != nil {
		fail(w, 500, "메일 설정을 읽지 못했습니다")
		return
	}
	if e := c.ready(); e != nil {
		fail(w, 409, e.Error()+". 설정을 저장한 뒤 다시 시도하세요")
		return
	}
	id := newID()
	subject := "[Hunter] 메일 알림 시험 발송"
	body := fmt.Sprintf("Hunter 메일 알림 설정이 올바른지 확인하는 시험 메일입니다.\n\n요청자: %s\n릴레이: %s:%d (%s)\n시각: %s\n\n이 메일은 %s 에서 보냈습니다.", u.Name, c.Host, c.Port, c.Security, time.Now().Format(time.RFC3339), c.BaseURL)
	if _, err = a.DB.Exec(r.Context(), `INSERT INTO mail_deliveries(id,event,recipient,recipient_user_id,subject,actor_id,status,attempts,lease_until) VALUES($1,'test',$2,$3,$4,$5,'sending',1,now()+$6::interval)`, id, recipient, u.ID, subject, u.ID, mailLeaseDuration.String()); err != nil {
		fail(w, 500, "발송 기록을 남기지 못했습니다")
		return
	}
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), c.Timeout+5*time.Second)
	defer cancel()
	result := a.sendSMTPNotification(sendCtx, c.channel(), NotificationMessage{DeliveryID: id, Recipient: recipient, Subject: subject, Body: body})
	if result.State != "sent" {
		// The test button reports synchronously; there is no second attempt to wait for.
		result.State = "failed"
	}
	_ = a.mailFinish(sendCtx, mailClaim{IDs: []string{id}, Event: "test", Recipient: recipient, Attempts: mailMaxAttempts}, result)
	a.audit(r, "mail.test", id, map[string]any{"recipient": notificationRecipientMask(recipient), "state": result.State, "code": result.Code})
	jsonResponse(w, 200, map[string]any{"id": id, "recipient": recipient, "state": result.State, "code": result.Code, "detail": result.Detail})
}

// mailLink is the address a message points at; empty when no base URL is known.
func (c mailConfig) mailLink(path string) string {
	if c.BaseURL == "" || path == "" {
		return ""
	}
	return c.BaseURL + path
}
