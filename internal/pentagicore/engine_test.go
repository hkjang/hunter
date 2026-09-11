package pentagicore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vxcontrol/langchaingo/llms"
	"github.com/vxcontrol/langchaingo/llms/reasoning"
	"pentagi/pkg/database"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/tools"
)

func coreTestEngine(t *testing.T) *Engine {
	t.Helper()
	dsn := os.Getenv("HUNTER_TEST_DSN")
	if dsn == "" {
		t.Skip("HUNTER_TEST_DSN required")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("core_test_%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["search_path"] = base
	cfg.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(ctx, pool)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.Close()
		_, err := pool.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{e.schema}.Sanitize()+" CASCADE")
		if err != nil {
			t.Error(err)
		}
		pool.Close()
	})
	return e
}

func TestOriginalPlannerDelegationToolLoopAndReporter(t *testing.T) {
	e := coreTestEngine(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var events []Event
	roles := map[string]int{}
	external := map[string]int{}
	sequence := 0
	complete := func(ctx context.Context, c CompletionRequest) (CompletionResult, error) {
		roles[c.Role]++
		sequence++
		if c.OnDelta != nil {
			c.OnDelta("검토 중 ")
		}
		if c.MaxTokens != 262144 || c.ContextWindow != 262144 {
			t.Fatalf("token bounds lost: %+v", c)
		}
		for _, d := range c.Tools {
			if d.Name == "terminal" || d.Name == "browser" || d.Name == "web_search" || d.Name == "file" {
				t.Fatalf("unsafe original runtime tool exposed: %s", d.Name)
			}
		}
		call := func(name, args string) (CompletionResult, error) {
			return CompletionResult{ToolCalls: []ToolCall{{ID: fmt.Sprintf("call_%d", sequence), Name: name, Arguments: args}}, InputTokens: 10, OutputTokens: 4, FinishReason: "tool_calls"}, nil
		}
		has := func(name string) bool {
			for _, d := range c.Tools {
				if d.Name == name {
					return true
				}
			}
			return false
		}
		switch {
		case has("subtask_list"):
			return call("subtask_list", `{"subtasks":[{"title":"등록 근거 확인","description":"승인된 서비스 정보와 기존 발견을 조사한다."}],"message":"하나의 검증 작업을 계획했습니다."}`)
		case has("subtask_patch"):
			return call("subtask_patch", `{"operations":[],"message":"추가 작업이 없습니다."}`)
		case has("report_result"):
			return call("report_result", `{"success":true,"result":"등록된 근거를 검토했습니다. 신규 취약점 확정은 하지 않았습니다.","message":"검토가 끝났습니다."}`)
		case c.Role == "primary_agent":
			switch roles[c.Role] {
			case 1:
				return call("service_context", `{}`)
			case 2:
				return call("search", `{"question":"Summarize the existing approved findings.","message":"발견 근거를 분석 담당자에게 전달합니다."}`)
			case 3:
				return call("coder", `{"question":"Recommend a safe fix without executing code.","message":"개선안을 코드 분석 담당자에게 전달합니다."}`)
			default:
				return call("done", `{"success":true,"result":"서비스 정보와 기존 발견 검토 완료","message":"완료"}`)
			}
		case c.Role == "searcher":
			if roles[c.Role] == 1 {
				return call("list_findings", `{}`)
			}
			return call("search_result", `{"result":"No confirmed vulnerability in supplied evidence.","message":"기존 근거를 검토했습니다."}`)
		case c.Role == "enricher":
			return call("enricher_result", `{"result":"Use only approved Hunter data.","message":"범위를 확인했습니다."}`)
		case c.Role == "coder":
			return call("code_result", `{"result":"Require current-user authorization before reading the resource.","message":"안전한 개선안을 작성했습니다."}`)
		default:
			return CompletionResult{Content: "승인 범위의 자료만 검토하고 검증되지 않은 내용을 확정하지 않습니다.", InputTokens: 7, OutputTokens: 3, FinishReason: "stop"}, nil
		}
	}
	h := Hooks{Complete: complete, Check: func(context.Context) error { return nil }, ExecuteTool: func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		external[name]++
		return `{"status":"ok","findings":[]}`, nil
	}, Emit: func(ev Event) { events = append(events, ev) }}
	r, err := e.Run(ctx, Request{RunID: "original-loop", ServiceID: "svc-approved", Prompt: "승인된 정보로 검토 보고서를 작성하세요.", MaxIterations: 60, MaxTokens: 262144, ContextWindow: 262144}, h)
	if err != nil {
		t.Fatalf("core execution: %v", err)
	}
	if r.Status != "finished" || r.Subtasks != 1 || r.ModelCalls < 7 || r.InputTokens == 0 {
		t.Fatalf("unexpected result: %+v", r)
	}
	if roles["generator"] == 0 || roles["primary_agent"] < 3 || roles["searcher"] < 2 || roles["refiner"] == 0 || roles["simple"] == 0 {
		t.Fatalf("original roles did not execute: %+v", roles)
	}
	if roles["coder"] == 0 || roles["adviser"] == 0 || roles["enricher"] == 0 {
		t.Fatalf("original planner/adviser delegation missing: %+v", roles)
	}
	if external["service_context"] != 1 || external["list_findings"] != 1 {
		t.Fatalf("tool bridge not used: %+v", external)
	}
	foundPlan, foundDelegate, foundDelta := false, false, false
	for _, ev := range events {
		if ev.Type == "task.updated" {
			foundPlan = true
		}
		if ev.Type == "tool.completed" && ev.ToolName == "search" {
			foundDelegate = true
		}
		if ev.Type == "delta" {
			foundDelta = true
		}
	}
	if !foundPlan || !foundDelegate || !foundDelta {
		t.Fatalf("missing events plan=%v delegation=%v delta=%v", foundPlan, foundDelegate, foundDelta)
	}
	rows, err := e.db.QueryContext(ctx, "SELECT DISTINCT type FROM msgchains WHERE flow_id=$1", r.FlowID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	types := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		types[v] = true
	}
	for _, want := range []string{"generator", "primary_agent", "searcher", "refiner", "reporter"} {
		if !types[want] {
			t.Errorf("original chain type missing: %s (%v)", want, types)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSafeToolsEnforceRevocationAndDedupe(t *testing.T) {
	allowed := true
	calls := 0
	r := &runState{hooks: Hooks{Check: func(context.Context) error {
		if !allowed {
			return fmt.Errorf("key revoked")
		}
		return nil
	}, ExecuteTool: func(context.Context, string, json.RawMessage) (string, error) { calls++; return "queued", nil }}}
	s := newSafeExecutor(r)
	e, err := s.GetPrimaryExecutor(tools.PrimaryExecutorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range e.Tools() {
		if d.Function.Name == "terminal" {
			t.Fatal("terminal exposed")
		}
	}
	if _, err = e.Execute(context.Background(), 0, "1", "terminal", "", "", json.RawMessage(`{"command":"whoami"}`)); err == nil {
		t.Fatal("unknown tool executed")
	}
	for i := 0; i < 2; i++ {
		if _, err = e.Execute(context.Background(), 0, "2", "request_scan", "", "", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("duplicate side effect: %d", calls)
	}
	allowed = false
	if _, err = e.Execute(context.Background(), 0, "3", "request_scan", "", "", json.RawMessage(`{}`)); err == nil {
		t.Fatal("revoked caller executed tool")
	}
	if calls != 1 {
		t.Fatal("revoked tool reached host")
	}
}

func TestWireMessagesPreserveToolIdentityAndReasoning(t *testing.T) {
	got, err := wireMessages([]llms.MessageContent{{Role: llms.ChatMessageTypeAI, Parts: []llms.ContentPart{llms.TextContent{Text: "content", Reasoning: &reasoning.ContentReasoning{Content: "private-reasoning"}}, llms.ToolCall{ID: "call-7", FunctionCall: &llms.FunctionCall{Name: "service_context", Arguments: `{}`}}}}, {Role: llms.ChatMessageTypeTool, Parts: []llms.ContentPart{llms.ToolCallResponse{ToolCallID: "call-7", Name: "service_context", Content: "result"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Role != "assistant" || got[0].Reasoning != "private-reasoning" || got[0].ToolCalls[0].ID != "call-7" || got[1].ToolCallID != "call-7" {
		t.Fatalf("lost model tool chain: %+v", got)
	}
}

func TestPinnedOriginalCoreUnchanged(t *testing.T) {
	root := filepath.Join("..", "..", "third_party", "pentagi")
	b, err := os.ReadFile(filepath.Join(root, "UPSTREAM.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Commit string            `json:"commit"`
		Files  map[string]string `json:"original_files_sha256"`
	}
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Commit != UpstreamCommit {
		t.Fatal("upstream commit mismatch")
	}
	checked := 0
	for name, want := range m.Files {
		if !strings.HasSuffix(name, ".go") && !strings.Contains(name, "templates/") {
			continue
		}
		b, err = os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(b)
		if hex.EncodeToString(hash[:]) != want {
			t.Errorf("original bytes changed: %s", name)
		}
		checked++
	}
	if checked < 200 {
		t.Fatalf("incomplete original core provenance: %d", checked)
	}
}

func TestCoreSchemaAndRunIdentityIsolation(t *testing.T) {
	a, b := coreTestEngine(t), coreTestEngine(t)
	if a.schema == b.schema {
		t.Fatal("application schemas collided")
	}
	ctx := context.Background()
	var id int64
	if err := a.db.QueryRowContext(ctx, "INSERT INTO flows(hunter_run_id,service_id) VALUES('one','svc') RETURNING id").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.q.CreateTask(ctx, database.CreateTaskParams{FlowID: id, Status: database.TaskStatusCreated}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := b.db.QueryRowContext(ctx, "SELECT count(*) FROM flows").Scan(&count); err != nil || count != 0 {
		t.Fatalf("schema data leaked count=%d err=%v", count, err)
	}
	if _, err := a.db.ExecContext(ctx, "INSERT INTO flows(hunter_run_id,service_id) VALUES('one','svc')"); err == nil {
		t.Fatal("duplicate run accepted")
	}
}

func TestModelBudgetStopsBeforeExtraCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	r := &runState{req: Request{MaxModelCalls: 6}, cancel: cancel, hooks: Hooks{Check: func(context.Context) error { return nil }, Complete: func(context.Context, CompletionRequest) (CompletionResult, error) {
		calls++
		return CompletionResult{Content: "bounded"}, nil
	}}}
	p := &hookProvider{run: r}
	for i := 0; i < 6; i++ {
		if _, err := p.Call(ctx, pconfig.OptionsTypeSimple, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Call(ctx, pconfig.OptionsTypeSimple, "one too many"); err == nil {
		t.Fatal("budget accepted excess model call")
	}
	if calls != 6 || r.calls.Load() != 6 || ctx.Err() == nil {
		t.Fatalf("budget did not stop context: calls=%d counter=%d err=%v", calls, r.calls.Load(), ctx.Err())
	}
}
