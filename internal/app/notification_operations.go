package app

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed notification_operations_schema.sql
var notificationOperationsSchema string

type notificationTracking struct {
	Enabled                  bool              `json:"enabled"`
	Endpoint                 string            `json:"endpoint"`
	Method                   string            `json:"method"`
	Query                    map[string]string `json:"query"`
	BodyTemplate             map[string]any    `json:"body_template"`
	StatePath                string            `json:"state_path"`
	DeliveredValues          []string          `json:"delivered_values"`
	FailedValues             []string          `json:"failed_values"`
	PendingValues            []string          `json:"pending_values"`
	PollIntervalSeconds      int               `json:"poll_interval_seconds"`
	MaxChecks                int               `json:"max_checks"`
	CallbackEnabled          bool              `json:"callback_enabled"`
	CallbackSecret           string            `json:"callback_secret"`
	CallbackSecretConfigured bool              `json:"callback_secret_configured"`
	ClearCallbackSecret      bool              `json:"clear_callback_secret"`
}
type notificationProtection struct {
	Enabled             bool `json:"enabled"`
	ConsecutiveFailures int  `json:"consecutive_failures"`
	OpenSeconds         int  `json:"open_seconds"`
	MinIntervalSeconds  int  `json:"min_interval_seconds"`
}
type notificationChannelPolicy struct {
	ChannelID         string                 `json:"channel_id"`
	Tracking          notificationTracking   `json:"tracking"`
	FallbackChannelID string                 `json:"fallback_channel_id"`
	Protection        notificationProtection `json:"protection"`
}
type notificationOperationsConfig struct {
	Enabled  bool                        `json:"enabled"`
	Channels []notificationChannelPolicy `json:"channels"`
}

func (c notificationOperationsConfig) channel(id string) (notificationChannelPolicy, bool) {
	for _, p := range c.Channels {
		if p.ChannelID == id {
			return p, true
		}
	}
	return notificationChannelPolicy{}, false
}
func (a *App) initNotificationOperations(ctx context.Context) error {
	if _, err := a.DB.Exec(ctx, notificationOperationsSchema); err != nil {
		return err
	}
	cipher, err := a.encrypt(`{"enabled":false,"channels":[]}`)
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO notification_operations_config(id,config_encrypted) VALUES(true,$1) ON CONFLICT DO NOTHING`, cipher)
	return err
}
func (a *App) notificationOperationsConfig(ctx context.Context, q notificationQuerier) (notificationOperationsConfig, time.Time, error) {
	var c notificationOperationsConfig
	var cipher string
	var rev time.Time
	err := q.QueryRow(ctx, `SELECT config_encrypted,updated_at FROM notification_operations_config WHERE id`).Scan(&cipher, &rev)
	if err != nil {
		return c, rev, err
	}
	plain, err := a.decrypt(cipher)
	if err != nil {
		return c, rev, err
	}
	err = json.Unmarshal([]byte(plain), &c)
	return c, rev, err
}
func notificationOperationsOutput(c notificationOperationsConfig, rev time.Time) map[string]any {
	for i := range c.Channels {
		t := &c.Channels[i].Tracking
		t.CallbackSecretConfigured = t.CallbackSecret != ""
		t.CallbackSecret = ""
		t.ClearCallbackSecret = false
	}
	if c.Channels == nil {
		c.Channels = []notificationChannelPolicy{}
	}
	return map[string]any{"config": c, "updated_at": rev}
}
func (a *App) registerNotificationOperations(m *http.ServeMux) {
	m.HandleFunc("GET /api/notification-operations", a.protect("admin:manage", a.getNotificationOperations))
	m.HandleFunc("PUT /api/notification-operations", a.protect("admin:manage", a.saveNotificationOperations))
	m.HandleFunc("GET /api/notification-operations/status", a.protect("admin:manage", a.notificationOperationsStatus))
	m.HandleFunc("POST /api/notification-operations/channels/{id}/reset", a.protect("admin:manage", a.resetNotificationCircuit))
	m.HandleFunc("POST /api/notification-operations/receipts/{id}/refresh", a.protect("admin:manage", a.refreshNotificationReceipt))
	m.HandleFunc("POST /api/notification-receipts/{channelID}", a.notificationReceiptCallback)
}
func (a *App) getNotificationOperations(w http.ResponseWriter, r *http.Request) {
	c, rev, err := a.notificationOperationsConfig(r.Context(), a.DB)
	if err != nil {
		fail(w, 500, "알림 운영 설정 조회 실패")
		return
	}
	jsonResponse(w, 200, notificationOperationsOutput(c, rev))
}
func notificationChannelFamily(s string) string {
	if s == "sms" || s == "kakao" {
		return "phone"
	}
	return s
}
func notificationTrackingURL(t notificationTracking, providerID, deliveryID string) (*url.URL, error) {
	if strings.ContainsAny(t.Endpoint, "\r\n") {
		return nil, errors.New("invalid endpoint")
	}
	base, err := url.Parse(t.Endpoint)
	if err != nil || base.User != nil || base.Fragment != "" || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("invalid endpoint")
	}
	// Interpolation may never change authority or create additional query parameters.
	if strings.Contains(base.Host, "{{") || strings.Contains(base.RawQuery, "{{") {
		return nil, errors.New("use structured query")
	}
	path := base.EscapedPath()
	// Parse escapes braces, so replace both representations, keeping IDs a single path segment.
	for k, v := range map[string]string{"provider_id": providerID, "delivery_id": deliveryID} {
		if strings.Contains(t.Endpoint, "{{"+k+"}}") && v == "" {
			return nil, errors.New("missing identifier")
		}
		path = strings.ReplaceAll(path, url.PathEscape("{{"+k+"}}"), url.PathEscape(v))
		path = strings.ReplaceAll(path, "{{"+k+"}}", url.PathEscape(v))
	}
	decoded, err := url.PathUnescape(path)
	if err != nil || strings.Contains(decoded, "{{") {
		return nil, errors.New("invalid path")
	}
	base.Path = decoded
	base.RawPath = path
	query := base.Query()
	for k, v := range t.Query {
		for key, val := range map[string]string{"provider_id": providerID, "delivery_id": deliveryID} {
			if strings.Contains(v, "{{"+key+"}}") && val == "" {
				return nil, errors.New("missing identifier")
			}
			v = strings.ReplaceAll(v, "{{"+key+"}}", val)
		}
		if strings.Contains(v, "{{") {
			return nil, errors.New("unknown variable")
		}
		query.Set(k, v)
	}
	base.RawQuery = query.Encode()
	return base, nil
}
func (a *App) validateNotificationOperations(ctx context.Context, tx pgx.Tx, c *notificationOperationsConfig, old notificationOperationsConfig) error {
	if len(c.Channels) > 200 {
		return errors.New("채널 운영 정책은 최대 200개입니다")
	}
	seen := map[string]bool{}
	edges := map[string]string{}
	for i := range c.Channels {
		p := &c.Channels[i]
		if seen[p.ChannelID] {
			return errors.New("채널별 정책은 하나만 등록할 수 있습니다")
		}
		seen[p.ChannelID] = true
		ch, err := a.notificationChannel(ctx, tx, p.ChannelID)
		if err != nil {
			return errors.New("등록된 알림 채널을 선택하세요")
		}
		t := &p.Tracking
		previous, _ := old.channel(p.ChannelID)
		if t.ClearCallbackSecret && t.CallbackSecret != "" {
			return errors.New("비밀 교체와 삭제를 동시에 요청할 수 없습니다")
		}
		if t.ClearCallbackSecret {
			t.CallbackSecret = ""
		} else if t.CallbackSecret == "" {
			t.CallbackSecret = previous.Tracking.CallbackSecret
		}
		if len(t.CallbackSecret) > 1000 || (t.CallbackEnabled && len(t.CallbackSecret) < 32) {
			return errors.New("콜백 서명 비밀값은 32~1000바이트로 설정하세요")
		}
		t.CallbackSecretConfigured = false
		t.ClearCallbackSecret = false
		if t.Method == "" {
			t.Method = "GET"
		}
		if t.PollIntervalSeconds == 0 {
			t.PollIntervalSeconds = 60
		}
		if t.MaxChecks == 0 {
			t.MaxChecks = 10
		}
		if t.StatePath == "" {
			t.StatePath = "status"
		}
		if t.DeliveredValues == nil {
			t.DeliveredValues = []string{"delivered"}
		}
		if t.FailedValues == nil {
			t.FailedValues = []string{"failed"}
		}
		if t.PendingValues == nil {
			t.PendingValues = []string{"pending"}
		}
		if (t.Method != "GET" && t.Method != "POST") || t.PollIntervalSeconds < 60 || t.PollIntervalSeconds > 86400 || t.MaxChecks < 1 || t.MaxChecks > 100 || !notificationFieldPath.MatchString(t.StatePath) {
			return errors.New("결과 조회 방식·주기(60~86400초)·횟수(1~100)·상태 필드를 확인하세요")
		}
		values := map[string]bool{}
		for _, list := range [][]string{t.DeliveredValues, t.FailedValues, t.PendingValues} {
			if len(list) > 30 {
				return errors.New("상태별 결과값은 최대 30개입니다")
			}
			for _, v := range list {
				if v == "" || len(v) > 200 || values[v] {
					return errors.New("전달·실패·대기 결과값은 서로 달라야 합니다")
				}
				values[v] = true
			}
		}
		if len(t.Query) > 30 {
			return errors.New("조회 매개변수는 최대 30개입니다")
		}
		raw, _ := json.Marshal(t.BodyTemplate)
		if len(raw) > 16384 {
			return errors.New("결과 조회 본문은 16 KiB 이하여야 합니다")
		}
		if t.Enabled {
			if ch.Type == "smtp" {
				return errors.New("SMTP 전달 결과는 서명 콜백으로 연동하세요")
			}
			u, e := notificationTrackingURL(*t, "sample-provider", "sample-delivery")
			origin, e2 := url.Parse(str(ch.Config, "endpoint"))
			if e != nil || e2 != nil || u.Scheme != origin.Scheme || !strings.EqualFold(u.Host, origin.Host) {
				return errors.New("결과 조회는 발송 API와 동일한 프로토콜·호스트·포트를 사용해야 합니다")
			}
			if !strings.Contains(t.Endpoint+string(raw)+fmtNotificationQuery(t.Query), "{{delivery_id}}") && !strings.Contains(t.Endpoint+string(raw)+fmtNotificationQuery(t.Query), "{{provider_id}}") {
				return errors.New("조회에 provider_id 또는 delivery_id 변수를 포함하세요")
			}
			if _, e = notificationTrackingBody(*t, "sample-provider", "sample-delivery"); e != nil {
				return errors.New("결과 조회 본문의 변수를 확인하세요")
			}
		}
		pr := &p.Protection
		if pr.ConsecutiveFailures == 0 {
			pr.ConsecutiveFailures = 5
		}
		if pr.OpenSeconds == 0 {
			pr.OpenSeconds = 300
		}
		if pr.ConsecutiveFailures < 2 || pr.ConsecutiveFailures > 100 || pr.OpenSeconds < 30 || pr.OpenSeconds > 86400 || pr.MinIntervalSeconds < 0 || pr.MinIntervalSeconds > 3600 {
			return errors.New("채널 보호 임계치·대기 시간·최소 간격을 확인하세요")
		}
		if p.FallbackChannelID != "" {
			f, e := a.notificationChannel(ctx, tx, p.FallbackChannelID)
			if e != nil || f.ID == ch.ID || notificationChannelFamily(f.Type) != notificationChannelFamily(ch.Type) {
				return errors.New("대체 채널은 다른 채널 중 동일한 수신자 계열로 선택하세요")
			}
			edges[ch.ID] = f.ID
		}
	}
	for start := range edges {
		visited := map[string]bool{}
		for id := start; id != ""; id = edges[id] {
			if visited[id] {
				return errors.New("대체 채널 연결은 순환할 수 없습니다")
			}
			visited[id] = true
		}
	}
	return nil
}
func fmtNotificationQuery(q map[string]string) string { b, _ := json.Marshal(q); return string(b) }
func (a *App) saveNotificationOperations(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Config   notificationOperationsConfig `json:"config"`
		Expected string                       `json:"expected_updated_at"`
	}
	if notificationDecode(r, &in) != nil {
		fail(w, 400, "알림 운영 설정 형식을 확인하세요")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		fail(w, 500, "설정 저장 시작 실패")
		return
	}
	defer tx.Rollback(r.Context())
	var locked time.Time
	if tx.QueryRow(r.Context(), `SELECT updated_at FROM notification_operations_config WHERE id FOR UPDATE`).Scan(&locked) != nil {
		fail(w, 500, "설정 조회 실패")
		return
	}
	expected, err := time.Parse(time.RFC3339Nano, in.Expected)
	if err != nil {
		fail(w, 400, "expected_updated_at이 필요합니다")
		return
	}
	if !expected.Equal(locked) {
		fail(w, 409, "알림 운영 설정이 변경되었습니다. 입력을 보존하고 최신 설정을 확인하세요")
		return
	}
	old, _, err := a.notificationOperationsConfig(r.Context(), tx)
	if err != nil {
		fail(w, 500, "기존 설정 조회 실패")
		return
	}
	if err = a.validateNotificationOperations(r.Context(), tx, &in.Config, old); err != nil {
		fail(w, 400, err.Error())
		return
	}
	raw, _ := json.Marshal(in.Config)
	cipher, err := a.encrypt(string(raw))
	if err != nil {
		fail(w, 500, "설정 암호화 실패")
		return
	}
	var rev time.Time
	err = tx.QueryRow(r.Context(), `UPDATE notification_operations_config SET config_encrypted=$1,updated_at=clock_timestamp() WHERE id RETURNING updated_at`, cipher).Scan(&rev)
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 500, "설정 저장 실패")
		return
	}
	a.audit(r, "notification_operations.update", "", map[string]any{"enabled": in.Config.Enabled, "channels": len(in.Config.Channels)})
	jsonResponse(w, 200, notificationOperationsOutput(in.Config, rev))
}
