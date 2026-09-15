package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHandoffSettingsValidation(t *testing.T) {
	v := defaultSettings()["handoff"]
	if e := validateSettings("handoff", v); e != nil || len(v["targets"].([]any)) != 0 {
		t.Fatalf("empty default rejected: %v", e)
	}
	good := map[string]any{"targets": []any{
		map[string]any{"name": " Ptium ", "origin": "HTTPS://Ptium.Intra:443/", "formats": []any{"markdown", "docx", "markdown"}},
		map[string]any{"name": "Kanpic", "origin": "https://kanpic.intra", "formats": []any{"csv", "xlsx"}},
	}}
	if e := validateSettings("handoff", good); e != nil {
		t.Fatal(e)
	}
	first := good["targets"].([]any)[0].(map[string]any)
	if first["name"] != "Ptium" || first["origin"] != "https://ptium.intra" || strings.Join(first["formats"].([]string), ",") != "markdown,docx" {
		t.Fatalf("not normalised: %+v", first)
	}
	for name, bad := range map[string]map[string]any{
		"not array":  {"targets": "https://ptium.intra"},
		"no name":    {"targets": []any{map[string]any{"name": " ", "origin": "https://ptium.intra", "formats": []any{"markdown"}}}},
		"path":       {"targets": []any{map[string]any{"name": "Ptium", "origin": "https://ptium.intra/handoff", "formats": []any{"markdown"}}}},
		"wildcard":   {"targets": []any{map[string]any{"name": "Ptium", "origin": "https://*.intra", "formats": []any{"markdown"}}}},
		"userinfo":   {"targets": []any{map[string]any{"name": "Ptium", "origin": "https://user@ptium.intra", "formats": []any{"markdown"}}}},
		"scheme":     {"targets": []any{map[string]any{"name": "Ptium", "origin": "ftp://ptium.intra", "formats": []any{"markdown"}}}},
		"no formats": {"targets": []any{map[string]any{"name": "Ptium", "origin": "https://ptium.intra", "formats": []any{}}}},
		"bad format": {"targets": []any{map[string]any{"name": "Ptium", "origin": "https://ptium.intra", "formats": []any{"pdf"}}}},
		"duplicate":  {"targets": []any{map[string]any{"name": "A", "origin": "https://ptium.intra", "formats": []any{"markdown"}}, map[string]any{"name": "B", "origin": "https://PTIUM.intra/", "formats": []any{"docx"}}}},
		"too many": {"targets": func() []any {
			out := []any{}
			for i := 0; i <= maxHandoffTargets; i++ {
				out = append(out, map[string]any{"name": "S", "origin": "https://s" + strings.Repeat("x", i) + ".intra", "formats": []any{"markdown"}})
			}
			return out
		}()},
	} {
		if validateSettings("handoff", bad) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestHandoffFilenameAndLoggedPath(t *testing.T) {
	name := handoffFilename(agentRun{ID: "run-1", ServiceName: " 결제/API: \"v2\"\n서비스 "})
	if name != "Hunter 진단 보고서 - 결제API v2서비스 - run-1.md" {
		t.Fatalf("filename %q", name)
	}
	if handoffFilename(agentRun{ID: "run-2", ServiceName: "///"}) != "hunter-agent-run-2.md" {
		t.Fatal("empty stem fallback")
	}
	if got := rfc5987Encode("보고서 a;b=c.md"); got != "%EB%B3%B4%EA%B3%A0%EC%84%9C%20a%3Bb%3Dc.md" {
		t.Fatalf("rfc5987 %q", got)
	}
	if loggedPath("/api/v1/handoff/claims/abc123") != "/api/v1/handoff/claims/{claim}" || loggedPath("/api/v1/handoff/claims") != "/api/v1/handoff/claims" || loggedPath("/api/services") != "/api/services" {
		t.Fatal("logged path masking")
	}
}

func TestHandoffClaimsAreSingleUseBoundAndOffByDefault(t *testing.T) {
	a, base := testApp(t)
	admin := loginTest(t, base, "admin", "test-password-1234")
	id, _ := reportFixture(t, a, base, admin, "completed")
	// Nothing configured: no targets, no claims, the receiver route answers 404 alike.
	targets := mustRequest(t, base, "GET", "/api/handoff/targets", nil, admin, 200)
	if list, _ := targets["targets"].([]any); len(list) != 0 || targets["format"] != "markdown" || targets["source"] != "http://localhost:8080" {
		t.Fatalf("default targets %+v", targets)
	}
	mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, admin, 404)
	// A target that does not receive markdown is stored but never offered.
	mustRequest(t, base, "PUT", "/api/settings/handoff", map[string]any{"targets": []any{map[string]any{"name": "Kanpic", "origin": "https://kanpic.intra", "formats": []any{"csv", "xlsx"}}}}, admin, 200)
	targets = mustRequest(t, base, "GET", "/api/handoff/targets", nil, admin, 200)
	if list, _ := targets["targets"].([]any); len(list) != 0 {
		t.Fatalf("pptx-only target offered %+v", targets)
	}
	mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, admin, 404)
	mustRequest(t, base, "PUT", "/api/settings/handoff", map[string]any{"targets": []any{
		map[string]any{"name": "Kanpic", "origin": "https://kanpic.intra", "formats": []any{"csv", "xlsx"}},
		map[string]any{"name": "Ptium", "origin": "https://ptium.intra", "formats": []any{"markdown", "docx"}},
	}}, admin, 200)
	mustRequest(t, base, "PUT", "/api/settings/general", map[string]any{"service_name": "hunter", "public_url": "https://hunter.intra/"}, admin, 200)
	targets = mustRequest(t, base, "GET", "/api/handoff/targets", nil, admin, 200)
	list, _ := targets["targets"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["origin"] != "https://ptium.intra" || list[0].(map[string]any)["name"] != "Ptium" || targets["source"] != "https://hunter.intra" {
		t.Fatalf("targets %+v", targets)
	}
	// Only the standard's shape is accepted.
	mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "pdf"}, admin, 400)
	mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": newID(), "format": "markdown"}, admin, 404)
	mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, "", 401)
	if code, _, _ := request(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, admin, false); code != 403 {
		t.Fatalf("csrf %d", code)
	}
	// Someone who cannot read the run cannot make a claim for it.
	mustRequest(t, base, "POST", "/api/users", map[string]any{"username": "handoff-other", "name": "Other", "role": "lead", "team": "blue", "password": "test-password-1234"}, admin, 201)
	other := loginTest(t, base, "handoff-other", "test-password-1234")
	mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, other, 404)
	issued := mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, admin, 201)
	claim := str(issued, "claim")
	if len(claim) < 32 || issued["source"] != "https://hunter.intra" || issued["content_type"] != "text/markdown; charset=utf-8" || !strings.HasSuffix(str(issued, "filename"), " - "+id+".md") || !strings.Contains(str(issued, "filename"), "한국어 보고서 서비스") {
		t.Fatalf("issued %+v", issued)
	}
	if exp, e := time.Parse(time.RFC3339, str(issued, "expires_at")); e != nil || time.Until(exp) > handoffClaimTTL || time.Until(exp) < handoffClaimTTL-time.Minute {
		t.Fatalf("expires_at %v %v", issued["expires_at"], e)
	}
	// The claim itself is never stored or audited; only its digest is.
	var n int
	if e := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM handoff_claims WHERE claim_hash=$1`, digest(claim)).Scan(&n); e != nil || n != 1 {
		t.Fatalf("claim row %d %v", n, e)
	}
	if e := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE detail::text LIKE '%' || $1 || '%' OR target = $1`, claim).Scan(&n); e != nil || n != 0 {
		t.Fatal("claim leaked to audit")
	}
	if e := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE action='agent.handoff' AND target=$1`, id).Scan(&n); e != nil || n != 1 {
		t.Fatal("handoff not audited")
	}
	// Collecting needs no sign-in, hands over the announced bytes as an attachment, and spends the claim.
	code, body, h := request(t, base, "GET", "/api/v1/handoff/claims/"+claim, nil, "", false)
	if code != 200 || h.Get("Content-Type") != "text/markdown; charset=utf-8" || h.Get("Cache-Control") != "no-store" || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment; filename*=UTF-8''Hunter%20") || !strings.Contains(h.Get("Content-Disposition"), "%20-%20"+id+".md") {
		t.Fatalf("redeem %d %q %q", code, h.Get("Content-Type"), h.Get("Content-Disposition"))
	}
	if float64(len(body)) != issued["bytes"] || !strings.HasPrefix(string(body), "# Hunter 에이전트 실행 보고서") || !strings.Contains(string(body), "한국어 분석 결과입니다") || strings.Contains(string(body), "should-not-appear") {
		t.Fatalf("body %d %q", len(body), string(body[:80]))
	}
	if code, _, _ := request(t, base, "GET", "/api/v1/handoff/claims/"+claim, nil, "", false); code != 404 {
		t.Fatalf("second use %d", code)
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 300), randomToken()} {
		if code, _, _ := request(t, base, "GET", "/api/v1/handoff/claims/"+bad, nil, "", false); code != 404 {
			t.Fatalf("claim %q answered %d", bad, code)
		}
	}
	// An expired claim answers the same 404 and is swept when the next claim is issued.
	expired := mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, admin, 201)
	if _, e := a.DB.Exec(context.Background(), `UPDATE handoff_claims SET expires_at=now()-interval '1 second' WHERE claim_hash=$1`, digest(str(expired, "claim"))); e != nil {
		t.Fatal(e)
	}
	if code, _, _ := request(t, base, "GET", "/api/v1/handoff/claims/"+str(expired, "claim"), nil, "", false); code != 404 {
		t.Fatalf("expired claim %d", code)
	}
	mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, admin, 201)
	if e := a.DB.QueryRow(context.Background(), `SELECT count(*) FROM handoff_claims WHERE expires_at<=now()`).Scan(&n); e != nil || n != 0 {
		t.Fatalf("expired rows kept: %d", n)
	}
	// The settings screen sees the saved list, and a viewer without agent scopes gets no claim.
	settings := mustRequest(t, base, "GET", "/api/settings", nil, admin, 200)
	var saved struct {
		Targets []handoffTarget `json:"targets"`
	}
	b, _ := json.Marshal(settings["handoff"])
	if json.Unmarshal(b, &saved) != nil || len(saved.Targets) != 2 || saved.Targets[1].Origin != "https://ptium.intra" {
		t.Fatalf("settings %s", b)
	}
	mustRequest(t, base, "POST", "/api/users", map[string]any{"username": "handoff-viewer", "name": "열람자", "role": "viewer", "team": "red", "password": "test-password-1234"}, admin, 201)
	viewer := loginTest(t, base, "handoff-viewer", "test-password-1234")
	mustRequest(t, base, "POST", "/api/v1/handoff/claims", map[string]any{"resource": id, "format": "markdown"}, viewer, 403)
	mustRequest(t, base, "GET", "/api/handoff/targets", nil, viewer, 403)
}
