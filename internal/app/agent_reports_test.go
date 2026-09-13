package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	pdfreader "github.com/ledongthuc/pdf"
)

func reportTestApp(t *testing.T) (*App, *httptest.Server, *httptest.Server, string) {
	t.Helper()
	a, base := testApp(t)
	m := http.NewServeMux()
	a.registerAgentReports(m)
	a.registerGraphQL(m)
	s := httptest.NewServer(m)
	t.Cleanup(s.Close)
	admin := loginTest(t, base, "admin", "test-password-1234")
	return a, base, s, admin
}
func reportFixture(t *testing.T, a *App, base *httptest.Server, credential, status string) (string, string) {
	t.Helper()
	svc := mustRequest(t, base, "POST", "/api/services", map[string]any{"name": "한국어 보고서 서비스", "url": "https://report.internal", "environment": "staging", "team": "red"}, credential, 200)
	var owner string
	if e := a.DB.QueryRow(context.Background(), `SELECT owner_id FROM resources WHERE id=$1`, str(svc, "id")).Scan(&owner); e != nil {
		t.Fatal(e)
	}
	id := newID()
	prompt, _ := a.encrypt("안전한 합성 진단 목표")
	result, _ := a.encrypt("한국어 분석 결과입니다. <script>alert('x')</script>\npassword=should-not-appear\n" + strings.Repeat("긴 한글 검증 문장입니다. ", 90))
	tasks, _ := json.Marshal([]map[string]any{{"id": "task-1", "title": "조회 작업", "status": "failed", "description": "실패한 검사를 성공으로 표현하지 않습니다."}})
	_, e := a.DB.Exec(context.Background(), `INSERT INTO agent_runs(id,owner_id,service_id,service_name,scope_id,title,status,prompt,result,error,policy_hash,limits,tasks) VALUES($1,$2,$3,'한국어 보고서 서비스','','보고서 합성 실행',$4,$5,$6,'실행 실패 설명','', '{"max_model_calls":60,"max_tokens":4096}', $7)`, id, owner, str(svc, "id"), status, prompt, result, tasks)
	if e != nil {
		t.Fatal(e)
	}
	return id, str(svc, "id")
}
func TestAgentReportsFormatsPermissionsAndKoreanPDF(t *testing.T) {
	a, base, s, admin := reportTestApp(t)
	id, sid := reportFixture(t, a, base, admin, "failed")
	for _, format := range []string{"md", "html", "pdf"} {
		code, body, h := request(t, s, "GET", "/api/agent-runs/"+id+"/report?format="+format, nil, admin, false)
		if code != 200 {
			t.Fatalf("%s status %d %s", format, code, body)
		}
		if h.Get("Cache-Control") != "no-store" || !strings.Contains(h.Get("Content-Disposition"), "hunter-agent-"+id+"."+format) {
			t.Fatal("missing download headers")
		}
		if bytes.Contains(body, []byte("should-not-appear")) {
			t.Fatal("report secret leak")
		}
		if format == "html" {
			if bytes.Contains(body, []byte("<script>alert")) || !bytes.Contains(body, []byte("&lt;script&gt;")) || h.Get("Content-Security-Policy") == "" {
				t.Fatal("HTML escaping/CSP")
			}
		}
		if format == "md" && !bytes.Contains(body, []byte("실패 (failed)")) {
			t.Fatal("failure status was not preserved")
		}
		if format == "pdf" {
			reader, e := pdfreader.NewReader(bytes.NewReader(body), int64(len(body)))
			if e != nil {
				t.Fatal(e)
			}
			plain, e := reader.GetPlainText()
			if e != nil {
				t.Fatal(e)
			}
			text, e := io.ReadAll(plain)
			if e != nil {
				t.Fatal(e)
			}
			for _, word := range []string{"에이전트 실행 보고서", "한국어 분석 결과", "실패 (failed)", "안전한 합성 진단 목표"} {
				if !strings.Contains(string(text), word) {
					t.Fatalf("Korean PDF text missing %q: %.500s", word, text)
				}
			}
			if strings.Contains(string(text), "should-not-appear") {
				t.Fatal("PDF plaintext secret")
			}
			t.Logf("PDF pages=%d bytes=%d Korean extraction verified", reader.NumPage(), len(body))
			if target := os.Getenv("HUNTER_REPORT_TEST_PDF"); target != "" {
				if e := os.WriteFile(target, body, 0600); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	key := workflowTestKey(t, base, admin, []string{"agents:read"})
	if code, _, _ := request(t, s, "GET", "/api/agent-runs/"+id+"/report?format=md", nil, key, false); code != 403 {
		t.Fatal("partial read key allowed")
	}
	if code, _, _ := request(t, s, "GET", "/api/agent-runs/"+id+"/report?format=exe", nil, admin, false); code != 400 {
		t.Fatal("unknown format accepted")
	}
	u := mustRequest(t, base, "POST", "/api/users", map[string]any{"username": "report-other", "name": "Other", "role": "lead", "team": "blue", "password": "test-password-1234"}, admin, 201)
	other := loginTest(t, base, "report-other", "test-password-1234")
	if code, _, _ := request(t, s, "GET", "/api/agent-runs/"+id+"/report?format=md", nil, other, false); code != 404 {
		t.Fatal("other team accessed report")
	}
	if _, e := a.DB.Exec(context.Background(), `UPDATE resources SET owner_id=$2,data=jsonb_set(data,'{team}','"blue"') WHERE id=$1`, sid, str(u, "id")); e != nil {
		t.Fatal(e)
	}
	if code, _, _ := request(t, s, "GET", "/api/agent-runs/"+id+"/report?format=md", nil, other, false); code != 200 {
		t.Fatal("current team ownership not used")
	}
}
func TestAgentReportBoundsAndIntermediateState(t *testing.T) {
	d := reportDocument("1.8.0", agentRun{ID: newID(), Status: "running", Prompt: strings.Repeat("가", 30000), Result: "", CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil)
	md := string(renderAgentReportMD(d))
	if !strings.Contains(md, "실행 중 (running)") || !strings.Contains(md, "표시 한도로") || !strings.Contains(md, "저장된 최종 결과가 없습니다") {
		t.Fatal("intermediate state or truncation not explicit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := renderAgentReportPDF(ctx, d); e == nil {
		t.Fatal("cancelled PDF generation ignored")
	}
}
