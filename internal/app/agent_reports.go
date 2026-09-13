package app

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/signintech/gopdf"
)

//go:embed report_assets/NanumGothic-Regular.ttf
var agentReportFont []byte

var agentReportSlots = make(chan struct{}, 4)

type agentReportSection struct {
	Title string
	Text  string
}
type agentReportDocument struct {
	Version, ID, Generated string
	Sections               []agentReportSection
}

func (a *App) registerAgentReports(m *http.ServeMux) {
	m.HandleFunc("GET /api/agent-runs/{id}/report", a.protect("agents:read", a.getAgentReport))
}

func reportText(v any, limit int) string {
	if v == nil {
		return ""
	}
	s := maskAgentText(fmt.Sprint(v))
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	rr := []rune(s)
	if len(rr) > limit {
		return string(rr[:limit]) + "\n[보고서 표시 한도로 뒷부분 생략]"
	}
	return s
}
func agentReportStatus(s string) string {
	labels := map[string]string{"queued": "대기 중", "running": "실행 중", "waiting_approval": "승인 대기", "waiting_model": "모델 연결 대기", "waiting_provider": "모델 연결 대기", "waiting_input": "추가 입력 대기", "paused": "일시 정지", "stopping": "중지 처리 중", "completed": "완료", "failed": "실패", "cancelled": "취소됨", "inconclusive": "판단 불가"}
	if v, ok := labels[s]; ok {
		return v + " (" + s + ")"
	}
	return reportText(s, 80)
}
func (a *App) reportRun(ctx context.Context, u User, id string) (agentRun, []domainResource, error) {
	v, e := a.agentRun(ctx, id)
	if e != nil || !a.canReadAgent(ctx, u, v) {
		return agentRun{}, nil, errors.New("접근 가능한 실행을 찾을 수 없습니다")
	}
	v.Prompt, e = a.decrypt(v.Prompt)
	if e != nil {
		return agentRun{}, nil, e
	}
	if v.Result != "" {
		v.Result, e = a.decrypt(v.Result)
		if e != nil {
			return agentRun{}, nil, e
		}
	}
	rows, e := a.DB.Query(ctx, `SELECT r.id,r.kind,r.owner_id,r.data,r.created_at,r.updated_at FROM resources r JOIN agent_run_scans x ON x.scan_id=r.id WHERE x.run_id=$1 ORDER BY r.created_at,r.id LIMIT 201`, id)
	if e != nil {
		return agentRun{}, nil, e
	}
	scans := []domainResource{}
	for rows.Next() {
		v, e := scanResource(rows)
		if e != nil {
			rows.Close()
			return agentRun{}, nil, e
		}
		scans = append(scans, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return agentRun{}, nil, e
	}
	visible := []domainResource{}
	for _, s := range scans {
		if !a.canAccess(ctx, u, s) {
			continue
		}
		parent, e := a.resource(ctx, "services", str(s.Data, "service_id"))
		if e != nil || !a.canAccess(ctx, u, parent) {
			continue
		}
		visible = append(visible, s)
	}
	return v, visible, nil
}
func reportDocument(version string, v agentRun, scans []domainResource) agentReportDocument {
	d := agentReportDocument{Version: version, ID: v.ID, Generated: time.Now().UTC().Format(time.RFC3339)}
	summary := fmt.Sprintf("실행 ID: %s\n서비스: %s\n현재 상태: %s\n생성 시각: %s\n최근 갱신: %s\n모델 호출: %d · Hunter 도구 호출: %d\n입력 토큰: %d · 출력 토큰: %d\n중지 요청: %t", v.ID, v.ServiceName, agentReportStatus(v.Status), v.CreatedAt.UTC().Format(time.RFC3339), v.UpdatedAt.UTC().Format(time.RFC3339), v.ModelCalls, v.ToolCalls, v.InputTokens, v.OutputTokens, v.CancelRequested)
	if v.FinishedAt != nil {
		summary += "\n종료 시각: " + v.FinishedAt.UTC().Format(time.RFC3339)
	}
	summary += "\n\n다운로드 시점의 중간 또는 최종 기록입니다. 실행 완료는 취약점 확인·해결을 뜻하지 않습니다. 실패·대기·미관측을 성공이나 해결로 처리하지 않습니다."
	d.Sections = append(d.Sections, agentReportSection{"실행 상태", reportText(summary, 8000)}, agentReportSection{"진단 목표", reportText(v.Prompt, 16000)})
	keys := []string{"max_iterations", "max_model_calls", "max_tool_calls", "timeout_minutes", "max_tokens", "context_window", "allow_diagnosis", "allow_candidates", "memory_enabled"}
	sort.Strings(keys)
	limits := []string{}
	for _, k := range keys {
		if val, ok := v.Limits[k]; ok {
			limits = append(limits, k+": "+reportText(val, 200))
		}
	}
	d.Sections = append(d.Sections, agentReportSection{"실행에 기록된 한도", strings.Join(limits, "\n")})
	tasks := []string{}
	for i, t := range v.Tasks {
		if i >= 100 {
			tasks = append(tasks, "[작업은 앞 100개까지 표시]")
			break
		}
		line := fmt.Sprintf("%d. %s\n상태: %s", i+1, reportText(t["title"], 500), reportText(t["status"], 80))
		for _, k := range []string{"description", "result"} {
			if val, ok := t[k]; ok {
				line += "\n" + k + ": " + reportText(val, 1000)
			}
		}
		if subs, ok := t["subtasks"].([]any); ok {
			for j, item := range subs {
				if j >= 20 {
					line += "\n[하위 작업은 앞 20개까지 표시]"
					break
				}
				if s, ok := item.(map[string]any); ok {
					line += "\n  - " + reportText(s["title"], 160) + " · " + reportText(s["status"], 80)
				}
			}
		}
		tasks = append(tasks, line)
	}
	if len(tasks) == 0 {
		tasks = append(tasks, "기록된 작업이 없습니다.")
	}
	d.Sections = append(d.Sections, agentReportSection{"작업 기록", reportText(strings.Join(tasks, "\n\n"), 20000)})
	scanLines := []string{}
	for i, s := range scans {
		if i >= 200 {
			scanLines = append(scanLines, "[연결 진단은 앞 200개까지 표시]")
			break
		}
		scanLines = append(scanLines, fmt.Sprintf("%s\n프로파일: %s · 상태: %s\n생성: %s", s.ID, reportText(s.Data["profile"], 200), reportText(s.Data["status"], 80), s.CreatedAt.UTC().Format(time.RFC3339)))
	}
	if len(scanLines) == 0 {
		scanLines = append(scanLines, "현재 조회 가능한 연결 진단이 없습니다.")
	}
	d.Sections = append(d.Sections, agentReportSection{"현재 조회 가능한 연결 진단", strings.Join(scanLines, "\n\n")})
	result := v.Result
	if result == "" {
		result = "저장된 최종 결과가 없습니다. 현재 상태와 작업 기록을 확인하세요."
	}
	d.Sections = append(d.Sections, agentReportSection{"저장된 분석 결과", reportText(result, 30000)})
	if v.Error != "" {
		d.Sections = append(d.Sections, agentReportSection{"실패 또는 중단 설명", reportText(v.Error, 2000)})
	}
	return d
}
func renderAgentReportMD(d agentReportDocument) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Hunter 에이전트 실행 보고서\n\n버전 %s · 생성 %s (UTC)\n", d.Version, d.Generated)
	for _, s := range d.Sections {
		fmt.Fprintf(&b, "\n## %s\n\n", s.Title)
		for _, line := range strings.Split(s.Text, "\n") {
			b.WriteString("    " + line + "\n")
		}
	}
	return []byte(b.String())
}

var agentReportHTML = template.Must(template.New("report").Parse(`<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hunter 에이전트 실행 보고서</title><style>body{font:16px/1.7 sans-serif;color:#123039;background:#f5f7f8;margin:0}main{max-width:960px;margin:auto;padding:28px}section{background:white;padding:22px;margin:20px 0;border:1px solid #d8e3e5;border-radius:12px}h1{font-size:27px}h2{font-size:21px}pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere}small{color:#496168}@media print{body{background:white}section{border:0;padding:0;break-inside:auto}h2{break-after:avoid}}</style><main><h1>Hunter 에이전트 실행 보고서</h1><small>버전 {{.Version}} · 생성 {{.Generated}} (UTC)</small>{{range .Sections}}<section><h2>{{.Title}}</h2><pre>{{.Text}}</pre></section>{{end}}</main></html>`))

func renderAgentReportHTML(d agentReportDocument) ([]byte, error) {
	var b bytes.Buffer
	e := agentReportHTML.Execute(&b, d)
	return b.Bytes(), e
}
func renderAgentReportPDF(ctx context.Context, d agentReportDocument) ([]byte, error) {
	var p gopdf.GoPdf
	p.Start(gopdf.Config{PageSize: *gopdf.PageSizeA4})
	if e := p.AddTTFFontData("hunter", agentReportFont); e != nil {
		return nil, e
	}
	if e := p.SetFont("hunter", "", 11); e != nil {
		return nil, e
	}
	page := 0
	y := 0.0
	newPage := func() error {
		page++
		p.AddPage()
		p.SetXY(42, 30)
		if e := p.Cell(nil, fmt.Sprintf("hunter · %s · %d", d.Version, page)); e != nil {
			return e
		}
		y = 62
		return nil
	}
	if e := newPage(); e != nil {
		return nil, e
	}
	textLine := func(text string, size int) error {
		if strings.TrimSpace(text) == "" {
			y += float64(size) * 1.55
			return nil
		}
		if e := p.SetFont("hunter", "", size); e != nil {
			return e
		}
		lines, e := p.SplitText(text, 510)
		if e != nil {
			return e
		}
		if len(lines) == 0 {
			lines = []string{" "}
		}
		for _, line := range lines {
			if e := ctx.Err(); e != nil {
				return e
			}
			if y > 785 {
				if e := newPage(); e != nil {
					return e
				}
			}
			p.SetXY(42, y)
			if e := p.Cell(nil, line); e != nil {
				return e
			}
			y += float64(size) * 1.55
		}
		return nil
	}
	if e := textLine("Hunter 에이전트 실행 보고서", 19); e != nil {
		return nil, e
	}
	if e := textLine("생성 "+d.Generated+" (UTC)", 10); e != nil {
		return nil, e
	}
	for _, s := range d.Sections {
		y += 15
		if e := textLine(s.Title, 14); e != nil {
			return nil, e
		}
		for _, line := range strings.Split(s.Text, "\n") {
			if e := textLine(line, 11); e != nil {
				return nil, e
			}
		}
	}
	return p.GetBytesPdfReturnErr()
}
func (a *App) getAgentReport(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if !hasAgentReadScopes(u) {
		fail(w, 403, "에이전트·서비스·발견 건·진단 조회 권한이 필요합니다")
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "md"
	}
	if !hasString([]string{"md", "html", "pdf"}, format) {
		fail(w, 400, "보고서 형식은 md, html, pdf 중에서 선택하세요")
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
	v, scans, e := a.reportRun(ctx, u, r.PathValue("id"))
	if e != nil {
		fail(w, 404, "접근 가능한 실행 보고서를 찾을 수 없습니다")
		return
	}
	d := reportDocument(a.Version, v, scans)
	var body []byte
	contentType := "text/markdown; charset=utf-8"
	switch format {
	case "md":
		body = renderAgentReportMD(d)
	case "html":
		body, e = renderAgentReportHTML(d)
		contentType = "text/html; charset=utf-8"
	case "pdf":
		body, e = renderAgentReportPDF(ctx, d)
		contentType = "application/pdf"
	}
	if e != nil || ctx.Err() != nil {
		fail(w, 500, "보고서를 생성하지 못했습니다")
		return
	}
	fresh, e := a.authenticate(r.WithContext(ctx))
	if e != nil || fresh.ID != u.ID || !a.canReadAgent(ctx, fresh, v) {
		fail(w, 403, "보고서 조회 권한이 변경되었습니다")
		return
	}
	for _, s := range scans {
		parent, e := a.resource(ctx, "services", str(s.Data, "service_id"))
		if e != nil || !a.canAccess(ctx, fresh, parent) || !a.canAccess(ctx, fresh, s) {
			fail(w, 403, "연결 진단 조회 권한이 변경되었습니다")
			return
		}
	}
	a.audit(r, "agent.report", v.ID, map[string]any{"format": format, "status": v.Status})
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="hunter-agent-%s.%s"`, v.ID, format))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Write(body)
}
