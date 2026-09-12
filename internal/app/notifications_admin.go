package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

type notificationQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (a *App) notificationChannel(ctx context.Context, q notificationQuerier, id string) (NotificationChannel, error) {
	var c NotificationChannel
	var config, secret string
	err := q.QueryRow(ctx, `SELECT id,name,type,enabled,config_encrypted,secret_encrypted,created_at,updated_at FROM notification_channels WHERE id=$1`, id).Scan(&c.ID, &c.Name, &c.Type, &c.Enabled, &config, &secret, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	plain, err := a.decrypt(config)
	if err != nil {
		return c, errors.New("알림 채널 설정을 읽지 못했습니다")
	}
	if err = json.Unmarshal([]byte(plain), &c.Config); err != nil {
		return c, err
	}
	if secret != "" {
		c.Secret, err = a.decrypt(secret)
	}
	return c, err
}
func notificationChannelOutput(c NotificationChannel) map[string]any {
	return map[string]any{"id": c.ID, "name": c.Name, "type": c.Type, "enabled": c.Enabled, "config": c.Config, "secret": "", "secret_configured": c.Secret != "", "created_at": c.CreatedAt, "updated_at": c.UpdatedAt}
}
func (a *App) listNotificationChannels(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(r.Context(), `SELECT id FROM notification_channels ORDER BY created_at,id`)
	if err != nil {
		fail(w, 500, "알림 채널 조회 실패")
		return
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
	if err != nil || rows.Err() != nil {
		fail(w, 500, "알림 채널 조회 실패")
		return
	}
	items := []map[string]any{}
	for _, id := range ids {
		c, e := a.notificationChannel(r.Context(), a.DB, id)
		if e != nil {
			fail(w, 500, "알림 채널 설정을 읽지 못했습니다")
			return
		}
		items = append(items, notificationChannelOutput(c))
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}
func notificationName(s string) bool {
	return strings.TrimSpace(s) != "" && len(s) <= 200 && !strings.ContainsFunc(s, unicode.IsControl)
}
func (a *App) saveNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name        string         `json:"name"`
		Type        string         `json:"type"`
		Enabled     bool           `json:"enabled"`
		Config      map[string]any `json:"config"`
		Secret      string         `json:"secret"`
		ClearSecret bool           `json:"clear_secret"`
		Expected    string         `json:"expected_updated_at"`
	}
	if notificationDecode(r, &input) != nil || !notificationName(input.Name) || len(input.Secret) > 16000 || input.ClearSecret && input.Secret != "" {
		fail(w, 400, "채널 이름(200바이트 이하), 비밀값 및 설정을 확인하세요")
		return
	}
	c := NotificationChannel{ID: r.PathValue("id"), Name: strings.TrimSpace(input.Name), Type: input.Type, Enabled: input.Enabled, Config: input.Config, Secret: input.Secret}
	existing := c.ID != ""
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "채널 저장 시작 실패")
		return
	}
	defer tx.Rollback(r.Context())
	if existing {
		var revision time.Time
		if err = tx.QueryRow(r.Context(), `SELECT updated_at FROM notification_channels WHERE id=$1 FOR UPDATE`, c.ID).Scan(&revision); err != nil {
			fail(w, 404, "알림 채널이 없습니다")
			return
		}
		expected, e := time.Parse(time.RFC3339Nano, input.Expected)
		if e != nil {
			fail(w, 400, "편집을 시작한 채널의 expected_updated_at이 필요합니다")
			return
		}
		if !revision.Equal(expected) {
			fail(w, 409, "채널이 변경되었습니다. 최신 설정을 확인하세요")
			return
		}
		old, e := a.notificationChannel(r.Context(), tx, c.ID)
		if e != nil {
			fail(w, 500, "기존 채널을 읽지 못했습니다")
			return
		}
		if !input.ClearSecret && input.Secret == "" {
			c.Secret = old.Secret
		}
	} else {
		c.ID = newID()
		if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(893717201)`); err != nil {
			fail(w, 500, "채널 저장 실패")
			return
		}
		var count int
		_ = tx.QueryRow(r.Context(), `SELECT count(*) FROM notification_channels`).Scan(&count)
		if count >= 200 {
			fail(w, 400, "채널은 최대 200개까지 등록할 수 있습니다")
			return
		}
	}
	if err = a.validateNotificationTransport(c); err != nil {
		fail(w, 400, err.Error())
		return
	}
	raw, _ := json.Marshal(c.Config)
	sealed, err := a.encrypt(string(raw))
	if err != nil {
		fail(w, 500, "채널 설정 암호화 실패")
		return
	}
	secret := ""
	if c.Secret != "" {
		secret, err = a.encrypt(c.Secret)
		if err != nil {
			fail(w, 500, "채널 비밀값 암호화 실패")
			return
		}
	}
	if existing {
		err = tx.QueryRow(r.Context(), `UPDATE notification_channels SET name=$2,type=$3,enabled=$4,config_encrypted=$5,secret_encrypted=$6,updated_at=clock_timestamp() WHERE id=$1 RETURNING created_at,updated_at`, c.ID, c.Name, c.Type, c.Enabled, sealed, secret).Scan(&c.CreatedAt, &c.UpdatedAt)
	} else {
		err = tx.QueryRow(r.Context(), `INSERT INTO notification_channels(id,name,type,enabled,config_encrypted,secret_encrypted) VALUES($1,$2,$3,$4,$5,$6) RETURNING created_at,updated_at`, c.ID, c.Name, c.Type, c.Enabled, sealed, secret).Scan(&c.CreatedAt, &c.UpdatedAt)
	}
	if err == nil && existing {
		_, err = tx.Exec(r.Context(), `UPDATE notification_deliveries SET status='cancelled',last_error='채널 설정이 변경되었습니다',updated_at=now() WHERE channel_id=$1 AND status IN('queued','retry')`, c.ID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "채널 저장 실패")
		return
	}
	a.audit(r, "notification.channel.save", c.ID, map[string]any{"type": c.Type, "enabled": c.Enabled})
	status := 201
	if existing {
		status = 200
	}
	jsonResponse(w, status, notificationChannelOutput(c))
}
func (a *App) deleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "채널 삭제 실패")
		return
	}
	defer tx.Rollback(r.Context())
	var id string
	if tx.QueryRow(r.Context(), `SELECT id FROM notification_channels WHERE id=$1 FOR UPDATE`, r.PathValue("id")).Scan(&id) != nil {
		fail(w, 404, "채널이 없습니다")
		return
	}
	var used bool
	if tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM notification_rules WHERE channel_id=$1) OR EXISTS(SELECT 1 FROM notification_deliveries WHERE channel_id=$1 AND status='sending')`, id).Scan(&used) != nil {
		fail(w, 500, "채널 참조 조회 실패")
		return
	}
	if used {
		fail(w, 409, "연결 규칙 또는 발송 중인 알림이 있습니다")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE notification_deliveries SET status='cancelled',last_error='채널이 삭제되었습니다',updated_at=now() WHERE channel_id=$1 AND status IN('queued','retry')`, id)
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM notification_channels WHERE id=$1`, id)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 409, "채널이 사용 중입니다")
		return
	}
	a.audit(r, "notification.channel.delete", id, nil)
	jsonResponse(w, 200, map[string]bool{"deleted": true})
}
func (a *App) notificationRule(ctx context.Context, q notificationQuerier, id string) (notificationRule, error) {
	var v notificationRule
	var events []byte
	var cipher string
	err := q.QueryRow(ctx, `SELECT id,name,channel_id,enabled,events,config_encrypted,created_at,updated_at FROM notification_rules WHERE id=$1`, id).Scan(&v.ID, &v.Name, &v.ChannelID, &v.Enabled, &events, &cipher, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	plain, err := a.decrypt(cipher)
	if err != nil {
		return v, err
	}
	var data notificationRule
	if err = json.Unmarshal([]byte(plain), &data); err != nil {
		return v, err
	}
	v.Filters = data.Filters
	v.Recipients = data.Recipients
	v.RecipientSources = data.RecipientSources
	v.SubjectTemplate = data.SubjectTemplate
	v.BodyTemplate = data.BodyTemplate
	v.MaxAttempts = data.MaxAttempts
	err = json.Unmarshal(events, &v.Events)
	return v, err
}
func (a *App) listNotificationRules(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(r.Context(), `SELECT id FROM notification_rules ORDER BY created_at,id`)
	if err != nil {
		fail(w, 500, "알림 규칙 조회 실패")
		return
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
	if err != nil || rows.Err() != nil {
		fail(w, 500, "알림 규칙 조회 실패")
		return
	}
	items := []notificationRule{}
	for _, id := range ids {
		v, e := a.notificationRule(r.Context(), a.DB, id)
		if e != nil {
			fail(w, 500, "알림 규칙 설정을 읽지 못했습니다")
			return
		}
		items = append(items, v)
	}
	jsonResponse(w, 200, map[string]any{"items": items, "events": notificationEvents, "variables": notificationVariables})
}

type notificationRuleInput struct {
	Name             string              `json:"name"`
	ChannelID        string              `json:"channel_id"`
	Enabled          bool                `json:"enabled"`
	Events           []string            `json:"events"`
	Filters          notificationFilters `json:"filters"`
	Recipients       []string            `json:"recipients"`
	RecipientSources []string            `json:"recipient_sources"`
	SubjectTemplate  string              `json:"subject_template"`
	BodyTemplate     string              `json:"body_template"`
	MaxAttempts      int                 `json:"max_attempts"`
	Expected         string              `json:"expected_updated_at"`
}

func (in notificationRuleInput) rule() notificationRule {
	return notificationRule{Name: strings.TrimSpace(in.Name), ChannelID: in.ChannelID, Enabled: in.Enabled, Events: in.Events, Filters: in.Filters, Recipients: in.Recipients, RecipientSources: in.RecipientSources, SubjectTemplate: in.SubjectTemplate, BodyTemplate: in.BodyTemplate, MaxAttempts: in.MaxAttempts}
}
func (a *App) validateNotificationRule(ctx context.Context, q notificationQuerier, v *notificationRule, c NotificationChannel) error {
	if !notificationName(v.Name) {
		return errors.New("규칙 이름은 비어 있지 않은 200바이트 이하이어야 합니다")
	}
	if len(v.Events) < 1 || len(v.Events) > len(notificationEvents) {
		return errors.New("알림 이벤트를 1개 이상 선택하세요")
	}
	seen := map[string]bool{}
	for _, e := range v.Events {
		if !hasString(notificationEvents, e) || seen[e] {
			return errors.New("이벤트 종류 또는 중복을 확인하세요")
		}
		seen[e] = true
	}
	if len(v.Events) == 1 && v.Events[0] == "team.weekly" {
		if v.SubjectTemplate == "" {
			v.SubjectTemplate = "[hunter] {{service.team}} 주간 보안 현황"
		}
		if v.BodyTemplate == "" {
			v.BodyTemplate = "기간: {{summary.period_start}} ~ {{summary.period_end}}\n현재 미조치: {{summary.total}}\n기간 신규: {{summary.new}}\n현재 해결 상태이며 기간 내 갱신: {{summary.resolved}}\n현재 기한 경과: {{summary.overdue}}"
		}
	}
	if v.SubjectTemplate == "" {
		v.SubjectTemplate = "[hunter] {{event.label}} · {{resource.title}}"
	}
	if v.BodyTemplate == "" {
		v.BodyTemplate = "서비스: {{service.name}}\n대상: {{resource.title}}\n상태: {{resource.status_label}}\n발생: {{event.time}}\n상세: {{resource.url}}"
	}
	if len(v.SubjectTemplate) > 200 || len(v.BodyTemplate) > 16000 || strings.ContainsAny(v.SubjectTemplate, "\r\n") {
		return errors.New("제목은 줄바꿈 없이 200바이트, 본문은 16000바이트 이하로 입력하세요")
	}
	if e := notificationTemplate(v.SubjectTemplate); e != nil {
		return e
	}
	if e := notificationTemplate(v.BodyTemplate); e != nil {
		return e
	}
	if v.MaxAttempts == 0 {
		v.MaxAttempts = 3
	}
	if v.MaxAttempts < 1 || v.MaxAttempts > 5 {
		return errors.New("최대 발송 시도는 1~5회입니다")
	}
	if len(v.Recipients) == 0 && len(v.RecipientSources) == 0 || len(v.Recipients) > 100 || len(v.RecipientSources) > 4 {
		return errors.New("정적 수신자는 최대 100명이며 정적 또는 동적 수신자를 선택하세요")
	}
	sources := map[string]bool{}
	for _, source := range v.RecipientSources {
		if !hasString([]string{"assignee", "service_owner", "team", "on_call"}, source) || sources[source] {
			return errors.New("동적 수신자 종류와 중복을 확인하세요")
		}
		sources[source] = true
	}
	seen = map[string]bool{}
	for i, r := range v.Recipients {
		n, e := validateNotificationRecipient(c.Type, r)
		if e != nil {
			return e
		}
		key := strings.ToLower(n)
		if seen[key] {
			return errors.New("중복 수신자를 제거하세요")
		}
		seen[key] = true
		v.Recipients[i] = n
	}
	if len(v.Filters.Severities) > 5 || len(v.Filters.ServiceIDs) > 100 || len(v.Filters.Teams) > 100 {
		return errors.New("규칙 필터 한도를 초과했습니다")
	}
	for _, s := range v.Filters.Severities {
		if !hasString([]string{"critical", "high", "medium", "low", "info"}, s) {
			return errors.New("심각도 필터를 확인하세요")
		}
	}
	for _, id := range v.Filters.ServiceIDs {
		var exists bool
		if e := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resources WHERE kind='services' AND id=$1)`, id).Scan(&exists); e != nil || !exists {
			return errors.New("존재하는 서비스를 필터로 선택하세요")
		}
	}
	for _, team := range v.Filters.Teams {
		if !notificationName(team) {
			return errors.New("팀 필터를 확인하세요")
		}
	}
	return nil
}
func (a *App) saveNotificationRule(w http.ResponseWriter, r *http.Request) {
	var input notificationRuleInput
	if notificationDecode(r, &input) != nil {
		fail(w, 400, "알림 규칙 요청을 확인하세요")
		return
	}
	v := input.rule()
	v.ID = r.PathValue("id")
	existing := v.ID != ""
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "규칙 저장 시작 실패")
		return
	}
	defer tx.Rollback(r.Context())
	if existing {
		var revision time.Time
		if tx.QueryRow(r.Context(), `SELECT updated_at FROM notification_rules WHERE id=$1 FOR UPDATE`, v.ID).Scan(&revision) != nil {
			fail(w, 404, "규칙이 없습니다")
			return
		}
		expected, e := time.Parse(time.RFC3339Nano, input.Expected)
		if e != nil {
			fail(w, 400, "편집을 시작한 규칙의 expected_updated_at이 필요합니다")
			return
		}
		if !revision.Equal(expected) {
			fail(w, 409, "규칙이 변경되었습니다. 최신 설정을 확인하세요")
			return
		}
	} else {
		v.ID = newID()
		if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(893717202)`); err != nil {
			fail(w, 500, "규칙 저장 실패")
			return
		}
		var n int
		_ = tx.QueryRow(r.Context(), `SELECT count(*) FROM notification_rules`).Scan(&n)
		if n >= 500 {
			fail(w, 400, "규칙은 최대 500개입니다")
			return
		}
	}
	c, err := a.notificationChannel(r.Context(), tx, v.ChannelID)
	if err != nil {
		fail(w, 400, "알림 채널을 선택하세요")
		return
	}
	if err = a.validateNotificationRule(r.Context(), tx, &v, c); err != nil {
		fail(w, 400, err.Error())
		return
	}
	raw, _ := json.Marshal(v)
	sealed, err := a.encrypt(string(raw))
	if err != nil {
		fail(w, 500, "규칙 암호화 실패")
		return
	}
	events, _ := json.Marshal(v.Events)
	if existing {
		err = tx.QueryRow(r.Context(), `UPDATE notification_rules SET name=$2,channel_id=$3,enabled=$4,events=$5,config_encrypted=$6,updated_at=clock_timestamp() WHERE id=$1 RETURNING created_at,updated_at`, v.ID, v.Name, v.ChannelID, v.Enabled, events, sealed).Scan(&v.CreatedAt, &v.UpdatedAt)
	} else {
		err = tx.QueryRow(r.Context(), `INSERT INTO notification_rules(id,name,channel_id,enabled,events,config_encrypted) VALUES($1,$2,$3,$4,$5,$6) RETURNING created_at,updated_at`, v.ID, v.Name, v.ChannelID, v.Enabled, events, sealed).Scan(&v.CreatedAt, &v.UpdatedAt)
	}
	if err == nil && existing {
		_, err = tx.Exec(r.Context(), `UPDATE notification_deliveries SET status='cancelled',last_error='규칙 설정이 변경되었습니다',updated_at=now() WHERE rule_id=$1 AND status IN('queued','retry')`, v.ID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "규칙 저장 실패")
		return
	}
	a.audit(r, "notification.rule.save", v.ID, map[string]any{"channel_id": v.ChannelID, "enabled": v.Enabled, "recipient_count": len(v.Recipients)})
	status := 201
	if existing {
		status = 200
	}
	jsonResponse(w, status, v)
}
func (a *App) deleteNotificationRule(w http.ResponseWriter, r *http.Request) {
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "규칙 삭제 실패")
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `DELETE FROM notification_rules WHERE id=$1`, r.PathValue("id"))
	if err != nil {
		fail(w, 500, "규칙 삭제 실패")
		return
	}
	if tag.RowsAffected() != 1 {
		fail(w, 404, "규칙이 없습니다")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE notification_deliveries SET status='cancelled',last_error='규칙이 삭제되었습니다',updated_at=now() WHERE rule_id=$1 AND status IN('queued','retry')`, r.PathValue("id"))
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "규칙 삭제 실패")
		return
	}
	a.audit(r, "notification.rule.delete", r.PathValue("id"), nil)
	jsonResponse(w, 200, map[string]bool{"deleted": true})
}
func notificationSample() map[string]string {
	v := map[string]string{}
	for _, key := range notificationVariables {
		v[key] = ""
	}
	for k, x := range map[string]string{"event.type": "finding.created", "event.label": "발견 건 등록", "resource.status_label": "탐지 후보", "finding.severity_label": "높음", "resource.url": "https://hunter.example.internal/findings?item=sample-finding", "event.time": time.Now().UTC().Format(time.RFC3339), "service.id": "sample-service", "service.name": "예시 사내 서비스", "service.team": "보안팀", "resource.id": "sample-finding", "resource.title": "예시 발견 건", "resource.status": "candidate", "finding.id": "sample-finding", "finding.title": "예시 발견 건", "finding.severity": "high", "finding.status": "candidate", "finding.due_date": "2026-12-31T00:00:00Z", "finding.assignee": "예시 담당자", "finding.cve": "CVE-2024-0001"} {
		v[k] = x
	}
	return v
}
func (a *App) previewNotificationRule(w http.ResponseWriter, r *http.Request) {
	var input notificationRuleInput
	if notificationDecode(r, &input) != nil {
		fail(w, 400, "미리보기 요청을 확인하세요")
		return
	}
	v := input.rule()
	c, err := a.notificationChannel(r.Context(), a.DB, v.ChannelID)
	if err != nil {
		fail(w, 400, "저장된 채널을 선택하세요")
		return
	}
	if err = a.validateNotificationRule(r.Context(), a.DB, &v, c); err != nil {
		fail(w, 400, err.Error())
		return
	}
	vars := notificationSample()
	vars["event.type"] = v.Events[0]
	vars["event.label"] = notificationEventLabel(v.Events[0])
	jsonResponse(w, 200, map[string]any{"subject": notificationRender(v.SubjectTemplate, vars, 200), "body": notificationRender(v.BodyTemplate, vars, 16000), "variables": vars, "sample": true, "recipients_count": len(v.Recipients)})
}
