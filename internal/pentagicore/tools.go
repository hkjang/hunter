package pentagicore

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/vxcontrol/langchaingo/llms"
	"pentagi/pkg/graphiti"
	"pentagi/pkg/providers/embeddings"
	"pentagi/pkg/schema"
	"pentagi/pkg/tools"
)

type completedCall struct {
	name, args, result string
	err                error
}
type safeExecutor struct {
	run   *runState
	mu    sync.Mutex
	calls map[string]completedCall
}

func newSafeExecutor(r *runState) *safeExecutor {
	return &safeExecutor{run: r, calls: map[string]completedCall{}}
}

func (s *safeExecutor) SetUserID(int64)                                        {}
func (s *safeExecutor) SetFlowID(int64)                                        {}
func (s *safeExecutor) SetImage(string)                                        {}
func (s *safeExecutor) SetEmbedder(embeddings.Embedder)                        {}
func (s *safeExecutor) SetFunctions(*tools.Functions)                          {}
func (s *safeExecutor) SetScreenshotProvider(tools.ScreenshotProvider)         {}
func (s *safeExecutor) SetAgentLogProvider(tools.AgentLogProvider)             {}
func (s *safeExecutor) SetMsgLogProvider(tools.MsgLogProvider)                 {}
func (s *safeExecutor) SetSearchLogProvider(tools.SearchLogProvider)           {}
func (s *safeExecutor) SetTermLogProvider(tools.TermLogProvider)               {}
func (s *safeExecutor) SetVectorStoreLogProvider(tools.VectorStoreLogProvider) {}
func (s *safeExecutor) SetToolCallLogProvider(tools.ToolCallLogProvider)       {}
func (s *safeExecutor) SetKnowledgeProvider(tools.KnowledgeProvider)           {}
func (s *safeExecutor) SetGraphitiClient(*graphiti.Client)                     {}
func (s *safeExecutor) Prepare(ctx context.Context) error                      { return s.run.check(ctx) }
func (s *safeExecutor) Release(context.Context) error                          { return nil }

func object(properties map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}
func textField() map[string]any { return map[string]any{"type": "string", "maxLength": 32000} }
func hunterDefinitions() []llms.FunctionDefinition {
	return []llms.FunctionDefinition{
		{Name: "service_context", Description: "현재 승인된 서비스의 대상·범위·환경·진단 정책을 조회합니다.", Parameters: object(map[string]any{})},
		{Name: "list_findings", Description: "현재 서비스에서 권한이 있는 발견 건을 조회합니다.", Parameters: object(map[string]any{"status": textField()})},
		{Name: "request_scan", Description: "현재 서비스의 승인된 제한 진단을 요청합니다. 대기·승인 대기는 진단 성공이 아닙니다. 실행 뒤 scan_result로 상태와 실제 근거를 확인하세요.", Parameters: object(map[string]any{"profile": map[string]any{"type": "string", "enum": []string{"http-baseline", "authorization"}}, "scenario_id": textField()})},
		{Name: "scan_result", Description: "현재 서비스 진단의 실제 완료 상태와 근거를 조회합니다.", Parameters: object(map[string]any{"scan_id": textField()}, "scan_id")},
		{Name: "record_candidate", Description: "확인되지 않은 발견 후보를 근거와 함께 기록합니다. 취약점 확인 또는 해결 상태를 변경하지 않습니다.", Parameters: object(map[string]any{"title": textField(), "severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}}, "description": textField(), "evidence": textField(), "component": textField(), "cve": textField()}, "title", "severity", "description")},
		{Name: "remember", Description: "현재 서비스의 근거 기반 분석 메모를 저장합니다. 자격증명과 개인정보를 저장하지 마세요.", Parameters: object(map[string]any{"key": textField(), "content": textField()}, "key", "content")},
		{Name: "recall", Description: "현재 서비스의 권한이 있는 분석 메모를 검색합니다.", Parameters: object(map[string]any{"query": textField()}, "query")},
	}
}

type contextExecutor struct {
	parent      *safeExecutor
	role        string
	handlers    map[string]tools.ExecutorHandler
	definitions map[string]llms.FunctionDefinition
	barriers    map[string]bool
}

func (s *safeExecutor) make(role string, handlers map[string]tools.ExecutorHandler, barriers ...string) (tools.ContextToolsExecutor, error) {
	e := &contextExecutor{parent: s, role: role, handlers: map[string]tools.ExecutorHandler{}, definitions: map[string]llms.FunctionDefinition{}, barriers: map[string]bool{}}
	registry := tools.GetRegistryDefinitions()
	for name, h := range handlers {
		if h == nil {
			continue
		}
		d, ok := registry[name]
		if !ok {
			return nil, fmt.Errorf("unknown upstream role tool %s", name)
		}
		e.handlers[name] = h
		e.definitions[name] = d
	}
	for _, d := range hunterDefinitions() {
		name := d.Name
		e.definitions[name] = d
		e.handlers[name] = func(ctx context.Context, _ string, args json.RawMessage) (string, error) {
			return s.run.hooks.ExecuteTool(ctx, name, args)
		}
	}
	for _, name := range barriers {
		if _, ok := e.handlers[name]; ok {
			e.barriers[name] = true
		}
	}
	return e, nil
}
func (e *contextExecutor) Tools() []llms.Tool {
	names := make([]string, 0, len(e.definitions))
	for n := range e.definitions {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]llms.Tool, 0, len(names))
	for _, n := range names {
		d := e.definitions[n]
		out = append(out, llms.Tool{Type: "function", Function: &d})
	}
	return out
}
func (e *contextExecutor) IsBarrierFunction(n string) bool { return e.barriers[n] }
func (e *contextExecutor) IsFunctionExists(n string) bool  { _, ok := e.handlers[n]; return ok }
func (e *contextExecutor) GetBarrierToolNames() []string {
	var out []string
	for n := range e.barriers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
func (e *contextExecutor) GetBarrierTools() []tools.FunctionInfo {
	var out []tools.FunctionInfo
	for _, n := range e.GetBarrierToolNames() {
		b, _ := json.Marshal(e.definitions[n].Parameters)
		out = append(out, tools.FunctionInfo{Name: n, Schema: string(b)})
	}
	return out
}
func (e *contextExecutor) GetToolSchema(n string) (*schema.Schema, error) {
	d, ok := e.definitions[n]
	if !ok {
		return nil, fmt.Errorf("tool %s is not allowed", n)
	}
	b, err := json.Marshal(d.Parameters)
	if err != nil {
		return nil, err
	}
	var out schema.Schema
	err = json.Unmarshal(b, &out)
	return &out, err
}
func (e *contextExecutor) Execute(ctx context.Context, _ int64, id, name, _, _ string, args json.RawMessage) (string, error) {
	if err := e.parent.run.check(ctx); err != nil {
		return "", fmt.Errorf("%w: %v", tools.ErrFlowStateGuard, err)
	}
	h, ok := e.handlers[name]
	if !ok {
		return "", fmt.Errorf("%w: tool %s is not allowed", tools.ErrFlowStateGuard, name)
	}
	if id == "" || !json.Valid(args) || len(args) > 128000 {
		return "", fmt.Errorf("%w: invalid tool call", tools.ErrFlowStateGuard)
	}
	// Reusing an upstream call ID never replays a side effect, including after a
	// model-side retry. IDs are shared by every delegated executor for this run.
	e.parent.mu.Lock()
	cached, seen := e.parent.calls[id]
	e.parent.mu.Unlock()
	if seen {
		if cached.name != name || cached.args != string(args) {
			return "", fmt.Errorf("%w: duplicate tool ID changed arguments", tools.ErrFlowStateGuard)
		}
		return cached.result, cached.err
	}
	var parsed map[string]any
	if err := json.Unmarshal(args, &parsed); err != nil || parsed == nil {
		return "", fmt.Errorf("%w: arguments must be an object", tools.ErrFlowStateGuard)
	}
	e.parent.run.emit(Event{Type: "tool.started", Role: e.role, ToolName: name, ToolCallID: id, Status: "running", Data: map[string]any{"arguments": parsed}})
	out, err := h(ctx, name, args)
	if err != nil {
		err = fmt.Errorf("%w: %v", tools.ErrFlowStateGuard, err)
	}
	e.parent.mu.Lock()
	e.parent.calls[id] = completedCall{name: name, args: string(args), result: out, err: err}
	e.parent.mu.Unlock()
	status := "finished"
	if err != nil {
		status = "failed"
	}
	e.parent.run.emit(Event{Type: "tool.completed", Role: e.role, ToolName: name, ToolCallID: id, Status: status, Data: map[string]any{"result": out}})
	return out, err
}

func (s *safeExecutor) GetPrimaryExecutor(c tools.PrimaryExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("primary_agent", map[string]tools.ExecutorHandler{tools.AdviceToolName: c.Adviser, tools.CoderToolName: c.Coder, tools.MaintenanceToolName: c.Installer, tools.MemoristToolName: c.Memorist, tools.PentesterToolName: c.Pentester, tools.SearchToolName: c.Searcher, tools.FinalyToolName: c.Barrier, tools.AskUserToolName: c.Barrier}, tools.FinalyToolName, tools.AskUserToolName)
}
func (s *safeExecutor) GetAssistantExecutor(c tools.AssistantExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("assistant", map[string]tools.ExecutorHandler{tools.AdviceToolName: c.Adviser, tools.CoderToolName: c.Coder, tools.MaintenanceToolName: c.Installer, tools.MemoristToolName: c.Memorist, tools.PentesterToolName: c.Pentester, tools.SearchToolName: c.Searcher})
}
func (s *safeExecutor) GetInstallerExecutor(c tools.InstallerExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("installer", map[string]tools.ExecutorHandler{tools.AdviceToolName: c.Adviser, tools.MemoristToolName: c.Memorist, tools.SearchToolName: c.Searcher, tools.MaintenanceResultToolName: c.MaintenanceResult}, tools.MaintenanceResultToolName)
}
func (s *safeExecutor) GetCoderExecutor(c tools.CoderExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("coder", map[string]tools.ExecutorHandler{tools.AdviceToolName: c.Adviser, tools.MaintenanceToolName: c.Installer, tools.MemoristToolName: c.Memorist, tools.SearchToolName: c.Searcher, tools.CodeResultToolName: c.CodeResult}, tools.CodeResultToolName)
}
func (s *safeExecutor) GetPentesterExecutor(c tools.PentesterExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("pentester", map[string]tools.ExecutorHandler{tools.AdviceToolName: c.Adviser, tools.CoderToolName: c.Coder, tools.MaintenanceToolName: c.Installer, tools.MemoristToolName: c.Memorist, tools.SearchToolName: c.Searcher, tools.HackResultToolName: c.HackResult}, tools.HackResultToolName)
}
func (s *safeExecutor) GetSearcherExecutor(c tools.SearcherExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("searcher", map[string]tools.ExecutorHandler{tools.MemoristToolName: c.Memorist, tools.SearchResultToolName: c.SearchResult}, tools.SearchResultToolName)
}
func (s *safeExecutor) GetGeneratorExecutor(c tools.GeneratorExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("generator", map[string]tools.ExecutorHandler{tools.MemoristToolName: c.Memorist, tools.SearchToolName: c.Searcher, tools.SubtaskListToolName: c.SubtaskList}, tools.SubtaskListToolName)
}
func (s *safeExecutor) GetRefinerExecutor(c tools.RefinerExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("refiner", map[string]tools.ExecutorHandler{tools.MemoristToolName: c.Memorist, tools.SearchToolName: c.Searcher, tools.SubtaskPatchToolName: c.SubtaskPatch}, tools.SubtaskPatchToolName)
}
func (s *safeExecutor) GetMemoristExecutor(c tools.MemoristExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("memorist", map[string]tools.ExecutorHandler{tools.MemoristResultToolName: c.SearchResult}, tools.MemoristResultToolName)
}
func (s *safeExecutor) GetEnricherExecutor(c tools.EnricherExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("enricher", map[string]tools.ExecutorHandler{tools.EnricherResultToolName: c.EnricherResult}, tools.EnricherResultToolName)
}
func (s *safeExecutor) GetReporterExecutor(c tools.ReporterExecutorConfig) (tools.ContextToolsExecutor, error) {
	return s.make("reporter", map[string]tools.ExecutorHandler{tools.ReportResultToolName: c.ReportResult}, tools.ReportResultToolName)
}
func (s *safeExecutor) GetCustomExecutor(c tools.CustomExecutorConfig) (tools.ContextToolsExecutor, error) {
	// External definitions and arbitrary builtin names are not an authorization
	// mechanism. The embedded core only uses the predefined role factories.
	if len(c.Builtin) > 0 || len(c.Definitions) > 0 {
		return nil, fmt.Errorf("custom external tools are disabled in Hunter core")
	}
	return s.make("custom", c.Handlers, c.Barriers...)
}

var _ tools.FlowToolsExecutor = (*safeExecutor)(nil)
