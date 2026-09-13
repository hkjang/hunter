package pentagicore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCoreDurableResumePreservesFlowAndToolEffects(t *testing.T) {
	for _, wait := range []bool{false, true} {
		t.Run(fmt.Sprint("input_wait_", wait), func(t *testing.T) {
			e := coreTestEngine(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, tools, primary := 0, 0, 0
			resumed := false
			inputSeen := false
			h := Hooks{Check: func(c context.Context) error { return c.Err() }, ExecuteTool: func(context.Context, string, json.RawMessage) (string, error) {
				tools++
				return `{"status":"completed"}`, nil
			}}
			h.Complete = func(c context.Context, in CompletionRequest) (CompletionResult, error) {
				calls++
				for _, m := range in.Messages {
					if strings.Contains(m.Content, "승인된 자료만 이어서") {
						inputSeen = true
					}
				}
				call := func(n, args string) (CompletionResult, error) {
					return CompletionResult{ToolCalls: []ToolCall{{ID: fmt.Sprint("resume-call-", calls), Name: n, Arguments: args}}, InputTokens: 3, OutputTokens: 2}, nil
				}
				for _, tool := range in.Tools {
					switch tool.Name {
					case "subtask_list":
						return call(tool.Name, `{"subtasks":[{"title":"자료 확인","description":"등록 자료를 확인한다"}],"message":"계획"}`)
					case "subtask_patch":
						return call(tool.Name, `{"operations":[],"message":"추가 없음"}`)
					case "report_result":
						return call(tool.Name, `{"success":true,"result":"저장된 근거를 확인했습니다","message":"보고"}`)
					}
				}
				if in.Role == "primary_agent" {
					primary++
					if primary == 1 {
						return call("service_context", `{}`)
					}
					if !resumed {
						if wait {
							return call("ask", `{"message":"추가 검토 방향을 입력하세요"}`)
						}
						cancel()
						return CompletionResult{}, errors.New("synthetic provider unavailable")
					}
					return call("done", `{"success":true,"result":"실제 기록 확인 완료","message":"완료"}`)
				}
				return CompletionResult{Content: "승인된 근거를 이용합니다", InputTokens: 1, OutputTokens: 1}, nil
			}
			req := Request{RunID: "durable-same-run", ServiceID: "approved-service", Prompt: "등록 자료 확인", MaxIterations: 24, MaxModelCalls: 60}
			first, err := e.Run(ctx, req, h)
			if wait {
				if err != nil || first.Status != "waiting" {
					t.Fatalf("waiting result=%+v err=%v", first, err)
				}
			} else if err == nil {
				t.Fatal("model interruption accepted as success")
			}
			if !first.CheckpointSaved || tools != 1 {
				t.Fatalf("checkpoint/effect missing %+v effects=%d", first, tools)
			}
			// A new engine object has no in-memory executor caches. Only persisted core
			// chain/phase data and the original run identity remain.
			restored := &Engine{db: e.db, q: e.q, schema: e.schema}
			resumed = true
			req.Resume = true
			if wait {
				noInput, e2 := restored.Run(context.Background(), req, h)
				if e2 != nil || noInput.Status != "waiting" || tools != 1 {
					t.Fatalf("waiting bypassed without input %+v %v", noInput, e2)
				}
			}
			req.Inputs = []RunInput{{ID: 1, Text: "승인된 자료만 이어서 검토하세요"}}
			second, err := restored.Run(context.Background(), req, h)
			if err != nil || second.Status != "finished" || second.FlowID != first.FlowID || second.TaskID != first.TaskID || tools != 1 || second.ModelCalls <= first.ModelCalls || !inputSeen {
				t.Fatalf("resume result=%+v err=%v effects=%d input=%v", second, err, tools, inputSeen)
			}
			if _, err = restored.Run(context.Background(), req, h); err == nil {
				t.Fatal("completed flow resumed")
			}
		})
	}
}
