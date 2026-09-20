package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Handing an agent run report to another in-house service (HANDOFF-STANDARD.md).
//
// Hunter is the sending side only: it issues a one-time five-minute claim for one
// Markdown report and the receiving service collects the body with that claim.
// Services never hold each other's credentials. The route names, request shape and
// status codes are the standard's, shared by six services, and are not Hunter's to vary.
//
//	POST /api/v1/handoff/claims          issue a claim (signed in)
//	GET  /api/v1/handoff/claims/{claim}  collect the document (the claim is the credential)
const (
	handoffFormat   = "markdown"
	handoffClaimTTL = 5 * time.Minute
	// handoffClaimsPerUser bounds the unspent claims one person may hold: a click
	// makes one claim that is collected at once, so a repeated call is a mistake or
	// a script, and each claim carries a whole encrypted report.
	handoffClaimsPerUser = 20
	maxHandoffTargets    = 20
	handoffClaimRoute    = "/api/v1/handoff/claims/"
)

// handoffFormats is the standard's whole vocabulary so an administrator can record
// what a target receives and be told when a word is not in the table.
var handoffFormats = []string{"markdown", "docx", "csv", "xlsx", "txt", "pptx"}

// handoffTarget is one receiving service an administrator named. The list is seeded
// empty: nothing is offered until a target that accepts markdown is written down.
type handoffTarget struct {
	Name    string   `json:"name"`
	Origin  string   `json:"origin"`
	Formats []string `json:"formats"`
}

func (a *App) initHandoff(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS handoff_claims (
 claim_hash text PRIMARY KEY, run_id text NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
 user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, filename text NOT NULL, content_type text NOT NULL,
 body_encrypted text NOT NULL, bytes integer NOT NULL, expires_at timestamptz NOT NULL);
 CREATE INDEX IF NOT EXISTS handoff_claims_expiry ON handoff_claims(expires_at);`)
	return err
}

// validateHandoffSettings normalises the `handoff` settings group in place: every target
// has a name, an origin of exactly scheme and host, formats from the vocabulary, no origin twice.
func validateHandoffSettings(v map[string]any) error {
	raw, ok := v["targets"].([]any)
	if !ok {
		return errors.New("보낼 곳 목록(targets)은 배열이어야 합니다")
	}
	if len(raw) > maxHandoffTargets {
		return fmt.Errorf("보낼 곳은 %d개까지 둘 수 있습니다", maxHandoffTargets)
	}
	seen := map[string]bool{}
	targets := []any{}
	for i, item := range raw {
		t, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%d번째 보낼 곳의 형식이 올바르지 않습니다", i+1)
		}
		name := strings.TrimSpace(str(t, "name"))
		if name == "" || utf8.RuneCountInString(name) > 60 || !utf8.ValidString(name) {
			return fmt.Errorf("%d번째 보낼 곳의 이름은 1~60자로 입력해 주세요", i+1)
		}
		origin, err := trackingOrigin(strings.TrimSpace(str(t, "origin")))
		if err != nil {
			return fmt.Errorf("%s의 주소는 경로 없이 http(s)://호스트[:포트] 형태의 오리진이어야 합니다", name)
		}
		if seen[origin] {
			return fmt.Errorf("같은 주소가 두 번 있습니다: %s", origin)
		}
		seen[origin] = true
		formats := []string{}
		for _, f := range stringSlice(t["formats"]) {
			if !slices.Contains(handoffFormats, f) {
				return fmt.Errorf("%s의 형식 %q은(는) 표준에 없는 형식입니다", name, f)
			}
			if !slices.Contains(formats, f) {
				formats = append(formats, f)
			}
		}
		if len(formats) == 0 {
			return fmt.Errorf("%s이(가) 받는 형식을 하나 이상 골라 주세요", name)
		}
		targets = append(targets, map[string]any{"name": name, "origin": origin, "formats": formats})
	}
	v["targets"] = targets
	return nil
}

// handoffTargets reads the configured list and keeps the services that can receive
// what Hunter sends. A target that takes only pptx is a real entry and still not
// somewhere a Markdown report can go.
func (a *App) handoffTargets(ctx context.Context) ([]handoffTarget, error) {
	v, err := a.setting(ctx, "handoff")
	if err != nil {
		return nil, err
	}
	out := []handoffTarget{}
	raw, _ := v["targets"].([]any)
	for _, item := range raw {
		t, _ := item.(map[string]any)
		formats := stringSlice(t["formats"])
		origin, e := trackingOrigin(str(t, "origin"))
		if e != nil || !slices.Contains(formats, handoffFormat) {
			continue
		}
		out = append(out, handoffTarget{Name: str(t, "name"), Origin: origin, Formats: formats})
	}
	return out, nil
}

// handoffSource is the address the receiving service fetches the claim from: the
// configured public URL, or the address this request arrived at before one is set.
// The receiver compares it with its own allow list, so a wrong value only fails closed.
func (a *App) handoffSource(r *http.Request) string {
	g, _ := a.setting(r.Context(), "general")
	if u, err := url.Parse(strings.TrimSpace(asString(g["public_url"]))); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
		return u.Scheme + "://" + u.Host
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// handoffFilename is the name the report travels under: the service name for a person
// reading a folder on the other side, with characters another service might treat as a
// path or a line break removed, then the same run identifier the download uses.
func handoffFilename(v agentRun) string {
	stem := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`/\:*?"<>|`, r) {
			return -1
		}
		return r
	}, strings.TrimSpace(v.ServiceName))
	if rr := []rune(stem); len(rr) > 60 {
		stem = string(rr[:60])
	}
	stem = strings.TrimSpace(stem)
	if stem == "" {
		return "hunter-agent-" + v.ID + ".md"
	}
	return "Hunter 진단 보고서 - " + stem + " - " + v.ID + ".md"
}

// rfc5987Encode percent-encodes everything outside RFC 5987 attr-char, which is what
// a filename* parameter may carry unescaped.
func rfc5987Encode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$&+-.^_`|~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// loggedPath is the request path as a log line may print it. A claim is a credential
// for five minutes and a log line lives longer than that.
func loggedPath(path string) string {
	if strings.HasPrefix(path, handoffClaimRoute) && len(path) > len(handoffClaimRoute) {
		return handoffClaimRoute + "{claim}"
	}
	return path
}

func (a *App) registerHandoff(m *http.ServeMux) {
	m.HandleFunc("GET /api/handoff/targets", a.protect("agents:read", func(w http.ResponseWriter, r *http.Request) {
		targets, e := a.handoffTargets(r.Context())
		if e != nil {
			fail(w, 500, "보낼 곳 설정을 읽을 수 없습니다")
			return
		}
		out := make([]map[string]string, 0, len(targets))
		for _, t := range targets {
			out = append(out, map[string]string{"name": t.Name, "origin": t.Origin})
		}
		jsonResponse(w, 200, map[string]any{"targets": out, "source": a.handoffSource(r), "format": handoffFormat})
	}))
	m.HandleFunc("POST /api/v1/handoff/claims", a.protect("agents:read", a.issueHandoffClaim))
	m.HandleFunc("GET /api/v1/handoff/claims/{claim}", a.redeemHandoffClaim)
}

// issueHandoffClaim renders the report as this person, exactly as the download does,
// and binds a claim to it. Making a claim widens nothing: the run must be readable now,
// and the body is fixed at issue so the receiver gets the bytes the claim announced.
func (a *App) issueHandoffClaim(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if !hasAgentReadScopes(u) {
		fail(w, 403, "에이전트·서비스·발견 건·진단 조회 권한이 필요합니다")
		return
	}
	var req struct {
		Resource string `json:"resource"`
		Format   string `json:"format"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if decode(r, &req) != nil {
		fail(w, 400, "요청 형식을 확인해 주세요")
		return
	}
	if req.Format != handoffFormat {
		fail(w, 400, "Hunter는 markdown 형식으로만 보낼 수 있습니다")
		return
	}
	targets, e := a.handoffTargets(r.Context())
	if e != nil {
		fail(w, 500, "보낼 곳 설정을 읽을 수 없습니다")
		return
	}
	if len(targets) == 0 {
		fail(w, 404, "다른 서비스로 보내기가 설정되지 않았습니다")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	select {
	case agentReportSlots <- struct{}{}:
		defer func() { <-agentReportSlots }()
	default:
		fail(w, 503, "보고서 생성 요청이 많습니다. 잠시 후 다시 시도하세요")
		return
	}
	v, scans, e := a.reportRun(ctx, u, strings.TrimSpace(req.Resource))
	if e != nil {
		fail(w, 404, "접근 가능한 실행 보고서를 찾을 수 없습니다")
		return
	}
	body := renderAgentReportMD(reportDocument(a.Version, v, scans))
	cipher, e := a.encrypt(string(body))
	if e != nil {
		fail(w, 500, "표를 발급하지 못했습니다")
		return
	}
	claim := randomToken()
	filename, contentType := handoffFilename(v), "text/markdown; charset=utf-8"
	expires := time.Now().Add(handoffClaimTTL)
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		fail(w, 503, "표를 발급하지 못했습니다")
		return
	}
	defer tx.Rollback(ctx)
	// Expired rows leave with the next claim; only the digest of a claim is stored.
	if _, e = tx.Exec(ctx, `DELETE FROM handoff_claims WHERE expires_at<=now()`); e != nil {
		fail(w, 503, "표를 발급하지 못했습니다")
		return
	}
	// An approximate per-person bound on unspent claims, counted after the sweep so
	// spending or expiry frees a slot. Two concurrent calls may both pass; the point
	// is that a repeated call cannot fill the table, not that the count is exact.
	var live int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM handoff_claims WHERE user_id=$1 AND expires_at>now()`, u.ID).Scan(&live); e != nil {
		fail(w, 503, "표를 발급하지 못했습니다")
		return
	}
	if live >= handoffClaimsPerUser {
		fail(w, 429, "발급했지만 아직 쓰지 않은 표가 너무 많습니다. 잠시 후 다시 시도하세요")
		return
	}
	_, e = tx.Exec(ctx, `INSERT INTO handoff_claims(claim_hash,run_id,user_id,filename,content_type,body_encrypted,bytes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, digest(claim), v.ID, u.ID, filename, contentType, cipher, len(body), expires)
	if e != nil || tx.Commit(ctx) != nil {
		fail(w, 503, "표를 발급하지 못했습니다")
		return
	}
	// The audit row says a report left, never the claim: a token in a log is a token.
	a.audit(r, "agent.handoff", v.ID, map[string]any{"format": handoffFormat, "bytes": len(body), "status": v.Status})
	jsonResponse(w, 201, map[string]any{"claim": claim, "source": a.handoffSource(r), "filename": filename, "content_type": contentType, "bytes": len(body), "expires_at": expires.Format(time.RFC3339)})
}

// redeemHandoffClaim hands the document to whoever brings the claim. No sign-in: the
// claim is the credential, so it is short, single use and bound to one document.
// Spent, expired and never issued all answer 404 alike.
func (a *App) redeemHandoffClaim(w http.ResponseWriter, r *http.Request) {
	claim := r.PathValue("claim")
	if len(claim) < 16 || len(claim) > 256 {
		fail(w, 404, "표를 찾을 수 없습니다")
		return
	}
	var filename, contentType, cipher string
	e := a.DB.QueryRow(r.Context(), `DELETE FROM handoff_claims WHERE claim_hash=$1 AND expires_at>now() RETURNING filename,content_type,body_encrypted`, digest(claim)).Scan(&filename, &contentType, &cipher)
	if e == pgx.ErrNoRows {
		fail(w, 404, "표를 찾을 수 없습니다")
		return
	}
	if e != nil {
		fail(w, 503, "표를 확인하지 못했습니다")
		return
	}
	body, e := a.decrypt(cipher)
	if e != nil {
		fail(w, 500, "문서를 읽을 수 없습니다")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+rfc5987Encode(filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(body))
}
