package app

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Blocked requests repeat on every page view, so the useful information is which
// origins the frame policy refused, not how often. A small in-memory buffer of
// distinct origin·directive pairs per instance is enough for an administrator to
// fix the allowed origins; it is never persisted or audited.
const maxTrackingViolations = 100

type trackingViolation struct {
	Origin    string    `json:"origin"`
	Directive string    `json:"directive"`
	Page      string    `json:"page"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Allowed   bool      `json:"allowed"`
}
type trackingViolationReport struct {
	BlockedURI string `json:"blocked_uri"`
	Directive  string `json:"directive"`
	Page       string `json:"page"`
}
type trackingViolationLog struct {
	mu    sync.Mutex
	items map[string]*trackingViolation
	now   func() time.Time
}

var trackingDirectivePattern = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)*$`)
var trackingPagePattern = regexp.MustCompile(`^/[a-z/-]*(?::id)?$`)

// trackingViolationOrigin normalises a blockedURI to an origin that could be
// allowed. inline, eval, data:, blob: and extension schemes cannot be allowed and
// are dropped so the administrator only sees actionable entries.
func trackingViolationOrigin(blockedURI string) string {
	u, err := url.Parse(strings.TrimSpace(blockedURI))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	origin, err := trackingOrigin(u.Scheme + "://" + u.Host)
	if err != nil {
		return ""
	}
	return origin
}
func (l *trackingViolationLog) record(report trackingViolationReport) bool {
	origin := trackingViolationOrigin(report.BlockedURI)
	directive := strings.ToLower(strings.TrimSpace(report.Directive))
	if i := strings.IndexByte(directive, ' '); i > 0 {
		directive = directive[:i]
	}
	if origin == "" || len(directive) > 40 || !trackingDirectivePattern.MatchString(directive) {
		return false
	}
	page := strings.TrimSpace(report.Page)
	if len(page) > 100 || !trackingPagePattern.MatchString(page) {
		page = ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.items == nil {
		l.items = map[string]*trackingViolation{}
	}
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	key := directive + " " + origin
	if v, ok := l.items[key]; ok {
		v.Count++
		v.LastSeen = now()
		if page != "" {
			v.Page = page
		}
		return true
	}
	if len(l.items) >= maxTrackingViolations {
		oldest := ""
		for k, v := range l.items {
			if oldest == "" || v.LastSeen.Before(l.items[oldest].LastSeen) {
				oldest = k
			}
		}
		delete(l.items, oldest)
	}
	moment := now()
	l.items[key] = &trackingViolation{Origin: origin, Directive: directive, Page: page, Count: 1, FirstSeen: moment, LastSeen: moment}
	return true
}
func (l *trackingViolationLog) list(allowed []string) []trackingViolation {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]trackingViolation, 0, len(l.items))
	for _, v := range l.items {
		item := *v
		item.Allowed = slices.Contains(allowed, item.Origin)
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b trackingViolation) int {
		if c := b.LastSeen.Compare(a.LastSeen); c != 0 {
			return c
		}
		return strings.Compare(a.Directive+" "+a.Origin, b.Directive+" "+b.Origin)
	})
	return out
}
func (l *trackingViolationLog) clear() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(l.items)
	l.items = nil
	return n
}

// The sandboxed frame has an opaque origin, so a report-uri from it would arrive
// without a session. The logged-in parent page relays the frame's
// securitypolicyviolation events instead, under the usual session·CSRF checks.
func (a *App) registerTrackingViolations(m *http.ServeMux) {
	m.HandleFunc("POST /api/tracking/violations", a.sessionOnly(func(w http.ResponseWriter, r *http.Request) {
		c, e := a.trackingConfig(r.Context())
		if e != nil {
			fail(w, 503, "방문 추적 설정을 읽을 수 없습니다")
			return
		}
		// Only the admin preview runs the frame while tracking is off.
		if !c.Enabled && !slices.Contains(currentUser(r).Scopes, "admin:manage") {
			fail(w, 404, "방문 추적이 꺼져 있습니다")
			return
		}
		var body struct {
			Violations []trackingViolationReport `json:"violations"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if decode(r, &body) != nil || len(body.Violations) > maxTrackingViolations {
			fail(w, 400, "차단 기록 형식을 확인해 주세요")
			return
		}
		recorded := 0
		for _, v := range body.Violations {
			if a.TrackingViolations.record(v) {
				recorded++
			}
		}
		jsonResponse(w, 202, map[string]any{"recorded": recorded})
	}))
	m.HandleFunc("GET /api/admin/tracking/violations", a.trackingAdmin(func(w http.ResponseWriter, r *http.Request) {
		c, e := a.trackingConfig(r.Context())
		if e != nil {
			fail(w, 503, "방문 추적 설정을 읽을 수 없습니다")
			return
		}
		jsonResponse(w, 200, map[string]any{"violations": a.TrackingViolations.list(c.AllowedOrigins), "limit": maxTrackingViolations})
	}))
	m.HandleFunc("DELETE /api/admin/tracking/violations", a.trackingAdmin(func(w http.ResponseWriter, r *http.Request) {
		n := a.TrackingViolations.clear()
		a.audit(r, "tracking.violations.clear", "visitor_tracking", map[string]any{"cleared": n})
		jsonResponse(w, 200, map[string]any{"cleared": n})
	}))
}
