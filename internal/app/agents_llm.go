package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hkjang/hunter/internal/pentagicore"
)

func (a *App) agentCompletion(ctx context.Context, run agentRun, in pentagicore.CompletionRequest) (pentagicore.CompletionResult, error) {
	var result pentagicore.CompletionResult
	ai, err := a.setting(ctx, "ai")
	if err != nil || !asBool(ai["enabled"]) {
		return result, errors.New("AI 연결이 비활성화되었습니다")
	}
	if asString(ai["model"]) != asString(run.Limits["model"]) {
		return result, errors.New("실행 도중 AI 모델이 변경되었습니다. 새 실행을 시작하세요")
	}
	cfg, err := a.setting(ctx, "agents")
	if err != nil {
		return result, err
	}
	maxCalls := min(asInt(cfg["max_model_calls"]), asInt(run.Limits["max_model_calls"]))
	maxTokens := min(asInt(ai["max_tokens"]), in.MaxTokens, asInt(run.Limits["max_tokens"]))
	window := min(asInt(ai["context_window"]), in.ContextWindow, asInt(run.Limits["context_window"]))
	if maxTokens < 1 || window < 1024 || window > 262144 {
		return result, errors.New("AI 토큰 설정을 확인하세요")
	}
	messages := []map[string]any{}
	for _, m := range in.Messages {
		role := m.Role
		switch role {
		case "human":
			role = "user"
		case "ai":
			role = "assistant"
		case "function":
			role = "tool"
		}
		if !hasString([]string{"system", "user", "assistant", "tool"}, role) {
			return result, fmt.Errorf("지원하지 않는 모델 메시지 역할: %s", role)
		}
		msg := map[string]any{"role": role, "content": m.Content}
		if m.ToolCallID != "" {
			msg["tool_call_id"] = m.ToolCallID
		}
		if m.Reasoning != "" {
			msg["reasoning_content"] = m.Reasoning
		}
		if len(m.ToolCalls) > 0 {
			calls := []map[string]any{}
			for _, c := range m.ToolCalls {
				calls = append(calls, map[string]any{"id": c.ID, "type": "function", "function": map[string]string{"name": c.Name, "arguments": c.Arguments}})
			}
			msg["tool_calls"] = calls
		}
		messages = append(messages, msg)
	}
	tools := []map[string]any{}
	for _, tool := range in.Tools {
		if !json.Valid(tool.Parameters) {
			return result, errors.New("도구 스키마가 올바르지 않습니다")
		}
		tools = append(tools, map[string]any{"type": "function", "function": map[string]any{"name": tool.Name, "description": tool.Description, "parameters": tool.Parameters}})
	}
	payload := map[string]any{"model": ai["model"], "messages": messages, "max_tokens": maxTokens, "stream": true, "stream_options": map[string]any{"include_usage": true}}
	if len(tools) > 0 {
		payload["tools"] = tools
		payload["tool_choice"] = "auto"
		payload["parallel_tool_calls"] = false
	}
	input, _ := json.Marshal(map[string]any{"messages": messages, "tools": tools})
	if len(input)+maxTokens+512 > window {
		return result, errors.New("에이전트 입력과 출력 토큰 예산이 컨텍스트 한도를 초과했습니다")
	}
	body, _ := json.Marshal(payload)
	endpoint := strings.TrimSuffix(asString(ai["base_url"]), "/")
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return result, errors.New("AI 서버 주소가 올바르지 않습니다")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if key := asString(ai["api_key"]); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	client, err := a.outboundClient(ctx, 10*time.Minute)
	if err != nil {
		return result, err
	}
	defer client.CloseIdleConnections()
	tag, err := a.DB.Exec(ctx, `UPDATE agent_runs SET model_calls=model_calls+1,updated_at=now() WHERE id=$1 AND NOT cancel_requested AND status IN ('running','waiting_approval') AND lease_until>now() AND model_calls<$2`, run.ID, maxCalls)
	if err != nil {
		return result, err
	}
	if tag.RowsAffected() != 1 {
		return result, errors.New("모델 호출 한도에 도달했거나 실행이 중지되었습니다")
	}
	response, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("AI 스트리밍 연결 실패: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result, fmt.Errorf("AI 서버가 요청을 거부했습니다 (HTTP %d)", response.StatusCode)
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		return result, errors.New("AI 서버가 SSE 스트리밍을 반환하지 않았습니다")
	}
	result, err = readAgentCompletion(response.Body, in.OnDelta)
	if err != nil {
		return result, err
	}
	if result.FinishReason == "length" {
		return result, errors.New("모델 출력이 토큰 한도에서 잘렸습니다. 출력 토큰 설정을 조정하세요")
	}
	_, err = a.DB.Exec(ctx, `UPDATE agent_runs SET input_tokens=input_tokens+$2,output_tokens=output_tokens+$3,updated_at=now() WHERE id=$1`, run.ID, max(result.InputTokens, 0), max(result.OutputTokens, 0))
	return result, err
}

// readAgentCompletion accepts multiline SSE data and incrementally reconstructs
// function arguments. An incomplete stream is an error, never a successful run.
func readAgentCompletion(reader io.Reader, onDelta func(string)) (pentagicore.CompletionResult, error) {
	var out pentagicore.CompletionResult
	scanner := bufio.NewScanner(io.LimitReader(reader, 16<<20))
	scanner.Buffer(make([]byte, 8192), 2<<20)
	calls := map[int]*pentagicore.ToolCall{}
	var data []string
	finished := false
	total := 0
	redactor := newAgentStreamRedactor(func(text string) {
		if onDelta == nil {
			return
		}
		// A masked line can still be long (up to the response bound). Keep every
		// event below the persistence limit without cutting Korean UTF-8 bytes.
		for len(text) > 8192 {
			end := 8192
			for !utf8.RuneStart(text[end]) {
				end--
			}
			onDelta(text[:end])
			text = text[end:]
		}
		if text != "" {
			onDelta(text)
		}
	})
	var pending strings.Builder
	lastFlush := time.Now()
	flush := func() {
		if pending.Len() > 0 {
			redactor.Write(pending.String())
		}
		pending.Reset()
		lastFlush = time.Now()
	}
	process := func() error {
		if len(data) == 0 {
			return nil
		}
		raw := strings.Join(data, "\n")
		data = nil
		if raw == "[DONE]" {
			finished = true
			return nil
		}
		var packet struct {
			Error   json.RawMessage `json:"error"`
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					Content   string `json:"content"`
					Reasoning string `json:"reasoning_content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				Input  int64 `json:"prompt_tokens"`
				Output int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(raw), &packet); err != nil {
			return errors.New("AI 스트림 JSON을 해석할 수 없습니다")
		}
		if len(packet.Error) > 0 && string(packet.Error) != "null" {
			return errors.New("AI 서버가 스트리밍 오류를 반환했습니다")
		}
		if packet.Usage != nil {
			out.InputTokens = packet.Usage.Input
			out.OutputTokens = packet.Usage.Output
		}
		for _, choice := range packet.Choices {
			if choice.Index != 0 {
				continue
			}
			out.Content += choice.Delta.Content
			out.Reasoning += choice.Delta.Reasoning
			pending.WriteString(choice.Delta.Content)
			total += len(choice.Delta.Content) + len(choice.Delta.Reasoning)
			if pending.Len() >= 1024 || time.Since(lastFlush) > 150*time.Millisecond {
				flush()
			}
			for _, c := range choice.Delta.ToolCalls {
				if c.Index < 0 || c.Index > 63 {
					return errors.New("AI 도구 호출 수가 허용 한도를 초과했습니다")
				}
				item := calls[c.Index]
				if item == nil {
					item = &pentagicore.ToolCall{}
					calls[c.Index] = item
				}
				if c.ID != "" {
					item.ID += c.ID
				}
				item.Name += c.Function.Name
				item.Arguments += c.Function.Arguments
				total += len(c.Function.Arguments)
				if c.Type != "" && c.Type != "function" {
					return errors.New("지원하지 않는 AI 도구 호출 형식입니다")
				}
			}
			if choice.FinishReason != nil {
				out.FinishReason = *choice.FinishReason
				finished = true
			}
		}
		if total > 4<<20 {
			return errors.New("AI 응답이 최대 크기를 초과했습니다")
		}
		return nil
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			if err := process(); err != nil {
				return out, err
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	if err := process(); err != nil {
		return out, err
	}
	flush()
	redactor.Flush()
	if !finished {
		return out, errors.New("AI 스트림이 완료 신호 없이 종료되었습니다")
	}
	indexes := []int{}
	for index := range calls {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	ids := map[string]bool{}
	for _, index := range indexes {
		call := *calls[index]
		if call.ID == "" || call.Name == "" || !json.Valid([]byte(call.Arguments)) || ids[call.ID] {
			return out, errors.New("AI 도구 호출 식별자 또는 인수가 올바르지 않습니다")
		}
		ids[call.ID] = true
		out.ToolCalls = append(out.ToolCalls, call)
	}
	if out.Content == "" && len(out.ToolCalls) == 0 {
		return out, errors.New("AI가 빈 응답을 반환했습니다")
	}
	return out, nil
}
