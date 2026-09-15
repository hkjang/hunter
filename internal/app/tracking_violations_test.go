package app

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTrackingViolationLogNormalisesDedupesAndEvicts(t *testing.T) {
	clock := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	l := trackingViolationLog{now: func() time.Time { return clock }}
	for _, bad := range []trackingViolationReport{
		{BlockedURI: "inline", Directive: "script-src"},
		{BlockedURI: "eval", Directive: "script-src"},
		{BlockedURI: "data:image/png;base64,AAAA", Directive: "img-src"},
		{BlockedURI: "blob:https://stats.internal/1", Directive: "connect-src"},
		{BlockedURI: "chrome-extension://abc/x.js", Directive: "script-src"},
		{BlockedURI: "https://stats.internal/collect", Directive: "connect-src; script-src *"},
		{BlockedURI: "https://stats.internal/collect", Directive: ""},
		{BlockedURI: "https://stats.internal; script-src *", Directive: "connect-src"},
		{BlockedURI: "", Directive: "connect-src"},
	} {
		if l.record(bad) {
			t.Fatalf("recorded unusable report %+v", bad)
		}
	}
	if !l.record(trackingViolationReport{BlockedURI: "HTTPS://Stats.Internal:443/collect?id=1#x", Directive: " Connect-Src ", Page: "/services"}) {
		t.Fatal("origin report rejected")
	}
	clock = clock.Add(time.Minute)
	if !l.record(trackingViolationReport{BlockedURI: "https://stats.internal/other/path", Directive: "connect-src", Page: "/agents/:id"}) {
		t.Fatal("second report rejected")
	}
	// Same origin under another directive is a distinct entry; raw document paths are never kept.
	clock = clock.Add(time.Minute)
	l.record(trackingViolationReport{BlockedURI: "https://stats.internal/pixel.gif", Directive: "img-src", Page: "/findings/123?x=1"})
	got := l.list([]string{"https://stats.internal"})
	if len(got) != 2 || got[0].Directive != "img-src" || got[0].Page != "" || got[1].Directive != "connect-src" || got[1].Origin != "https://stats.internal" || got[1].Count != 2 || got[1].Page != "/agents/:id" || !got[1].Allowed || got[1].FirstSeen.Equal(got[1].LastSeen) {
		t.Fatalf("unexpected list %+v", got)
	}
	if l.list(nil)[1].Allowed {
		t.Fatal("allowed flag must follow the current configuration")
	}
	for i := 0; i < maxTrackingViolations+5; i++ {
		clock = clock.Add(time.Second)
		l.record(trackingViolationReport{BlockedURI: fmt.Sprintf("https://host%d.internal/x", i), Directive: "script-src"})
	}
	got = l.list(nil)
	if len(got) != maxTrackingViolations {
		t.Fatalf("buffer size %d", len(got))
	}
	for _, v := range got {
		if v.Origin == "https://stats.internal" || v.Origin == "https://host0.internal" {
			t.Fatalf("oldest entry survived eviction: %s", v.Origin)
		}
	}
	if got[0].Origin != fmt.Sprintf("https://host%d.internal", maxTrackingViolations+4) {
		t.Fatalf("list not newest first: %s", got[0].Origin)
	}
	if n := l.clear(); n != maxTrackingViolations || len(l.list(nil)) != 0 {
		t.Fatalf("clear removed %d", n)
	}
}

func TestTrackingViolationReportsRequireSessionAndAdminView(t *testing.T) {
	_, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	mustRequest(t, s, "POST", "/api/users", map[string]any{"username": "viewer", "name": "열람자", "password": "test-password-1234", "role": "viewer"}, cookie, 201)
	viewer := loginTest(t, s, "viewer", "test-password-1234")
	report := map[string]any{"violations": []map[string]any{{"blocked_uri": "https://stats.internal/collect", "directive": "connect-src", "page": "/services"}}}
	// Tracking is off: ordinary users have no frame, so their reports are refused; the admin preview may report.
	mustRequest(t, s, "POST", "/api/tracking/violations", report, viewer, 404)
	mustRequest(t, s, "POST", "/api/tracking/violations", report, "", 401)
	if code, _, _ := request(t, s, "POST", "/api/tracking/violations", report, cookie, false); code != 403 {
		t.Fatalf("csrf %d", code)
	}
	first := mustRequest(t, s, "POST", "/api/tracking/violations", report, cookie, 202)
	if first["recorded"] != float64(1) {
		t.Fatal(first)
	}
	draft := map[string]any{"enabled": true, "name": "통계", "script": "void 0", "allowed_origins": []string{"https://assets.internal"}, "revision": 0}
	mustRequest(t, s, "PUT", "/api/admin/tracking", draft, cookie, 200)
	many := []map[string]any{}
	for i := 0; i <= maxTrackingViolations; i++ {
		many = append(many, map[string]any{"blocked_uri": fmt.Sprintf("https://h%d.internal/x", i), "directive": "img-src"})
	}
	mustRequest(t, s, "POST", "/api/tracking/violations", map[string]any{"violations": many}, viewer, 400)
	mustRequest(t, s, "POST", "/api/tracking/violations", map[string]any{"violations": []map[string]any{{"blocked_uri": "https://assets.internal/a.js", "directive": "script-src-elem"}, {"blocked_uri": "inline", "directive": "script-src"}}}, viewer, 202)
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "admin test", "scopes": []string{"admin:manage"}, "expires_days": 1}, cookie, 201)
	mustRequest(t, s, "GET", "/api/admin/tracking/violations", nil, asString(key["token"]), 403)
	mustRequest(t, s, "GET", "/api/admin/tracking/violations", nil, viewer, 403)
	listed := mustRequest(t, s, "GET", "/api/admin/tracking/violations", nil, cookie, 200)
	items, _ := listed["violations"].([]any)
	if len(items) != 2 || listed["limit"] != float64(maxTrackingViolations) {
		t.Fatal(listed)
	}
	byOrigin := map[string]map[string]any{}
	for _, item := range items {
		v := item.(map[string]any)
		byOrigin[asString(v["origin"])] = v
	}
	if byOrigin["https://assets.internal"]["allowed"] != true || byOrigin["https://stats.internal"]["allowed"] != false || byOrigin["https://stats.internal"]["page"] != "/services" || byOrigin["https://assets.internal"]["directive"] != "script-src-elem" {
		t.Fatal(byOrigin)
	}
	for _, item := range items {
		if raw, _ := item.(map[string]any); strings.Contains(asString(raw["origin"]), "/collect") {
			t.Fatal("blocked path retained")
		}
	}
	mustRequest(t, s, "DELETE", "/api/admin/tracking/violations", nil, viewer, 403)
	cleared := mustRequest(t, s, "DELETE", "/api/admin/tracking/violations", nil, cookie, 200)
	if cleared["cleared"] != float64(2) {
		t.Fatal(cleared)
	}
	if after := mustRequest(t, s, "GET", "/api/admin/tracking/violations", nil, cookie, 200); len(after["violations"].([]any)) != 0 {
		t.Fatal(after)
	}
}
