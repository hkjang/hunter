package app

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// NotificationChannel is decrypted only at the administrator API and transport boundary.
// Secret is never included in API responses; all configuration is encrypted at rest.
type NotificationChannel struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	Enabled   bool           `json:"enabled"`
	Config    map[string]any `json:"config"`
	Secret    string         `json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}
type NotificationMessage struct {
	RecipientUserID string            `json:"-"`
	DeliveryID      string            `json:"delivery_id"`
	EventID         string            `json:"event_id"`
	Recipient       string            `json:"recipient"`
	Subject         string            `json:"subject"`
	Body            string            `json:"body"`
	Variables       map[string]string `json:"variables"`
}

// State is sent (provider accepted), retryable (safe to retry), failed, or uncertain.
// Detail and Code must be safe summaries, never raw upstream messages or headers.
type NotificationSendResult struct {
	State      string
	ProviderID string
	Code       string
	Detail     string
	RetryAfter time.Duration
}
type notificationRule struct {
	ID               string              `json:"id"`
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
	CreatedAt        time.Time           `json:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at"`
}
type notificationFilters struct {
	Severities []string `json:"severities"`
	ServiceIDs []string `json:"service_ids"`
	Teams      []string `json:"teams"`
}

var notificationEvents = []string{"finding.created", "finding.updated", "finding.due", "scan.completed", "scan.failed", "approval.pending", "finding.due_soon", "finding.unacknowledged", "team.weekly"}
var notificationVariables = []string{"event.type", "event.label", "event.time", "service.id", "service.name", "service.team", "resource.id", "resource.title", "resource.status", "resource.status_label", "resource.url", "finding.id", "finding.title", "finding.severity", "finding.severity_label", "finding.status", "finding.due_date", "finding.assignee", "finding.cve", "scan.id", "scan.name", "scan.status", "approval.id", "approval.status", "summary.total", "summary.new", "summary.resolved", "summary.overdue", "summary.period_start", "summary.period_end"}
var notificationPlaceholder = regexp.MustCompile(`\{\{\s*([a-z_]+\.[a-z_]+)\s*\}\}`)

//go:embed notifications_schema.sql
var notificationSchema string

func (a *App) initNotifications(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, notificationSchema)
	return err
}
func notificationDecode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("알림 요청의 JSON 항목을 확인하세요")
	}
	return nil
}
func notificationText(s string, max int) string {
	s = maskAgentText(maskEvidence(s))
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
func notificationTemplate(t string) error {
	rest := notificationPlaceholder.ReplaceAllStringFunc(t, func(match string) string {
		m := notificationPlaceholder.FindStringSubmatch(match)
		if hasString(notificationVariables, m[1]) {
			return ""
		}
		return match
	})
	if strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
		return errors.New("지원하는 알림 템플릿 변수만 사용할 수 있습니다")
	}
	return nil
}
func notificationRender(t string, vars map[string]string, max int) string {
	return notificationText(notificationPlaceholder.ReplaceAllStringFunc(t, func(match string) string { return vars[notificationPlaceholder.FindStringSubmatch(match)[1]] }), max)
}
func notificationRecipientMask(s string) string {
	if i := strings.LastIndex(s, "@"); i > 0 {
		return string([]rune(s[:i])[:1]) + "***" + s[i:]
	}
	r := []rune(s)
	if len(r) > 4 {
		return "***" + string(r[len(r)-4:])
	}
	return "***"
}
func (a *App) registerNotifications(m *http.ServeMux) {
	for route, h := range map[string]http.HandlerFunc{
		"GET /api/notification-channels": a.listNotificationChannels, "POST /api/notification-channels": a.saveNotificationChannel,
		"PUT /api/notification-channels/{id}": a.saveNotificationChannel, "DELETE /api/notification-channels/{id}": a.deleteNotificationChannel,
		"POST /api/notification-channels/{id}/test": a.testNotificationChannel,
		"GET /api/notification-rules":               a.listNotificationRules, "POST /api/notification-rules": a.saveNotificationRule,
		"PUT /api/notification-rules/{id}": a.saveNotificationRule, "DELETE /api/notification-rules/{id}": a.deleteNotificationRule,
		"POST /api/notification-rules/preview": a.previewNotificationRule,
		"GET /api/notification-deliveries":     a.listNotificationDeliveries, "GET /api/notification-deliveries/{id}": a.getNotificationDelivery,
		"POST /api/notification-deliveries/{id}/retry": a.retryNotificationDelivery, "POST /api/notification-deliveries/{id}/cancel": a.cancelNotificationDelivery,
	} {
		m.HandleFunc(route, a.protect("admin:manage", h))
	}
}
