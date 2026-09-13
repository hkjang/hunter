package app

// Native wire formats follow the official Messages, generateContent, Ollama chat
// and Chat Completions specifications. Only text and declared function tools are
// accepted; provider-side execution/search tools are never enabled here.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/hkjang/hunter/internal/pentagicore"
	"github.com/jackc/pgx/v5"
)

func modelRole(s string) string {
	switch s {
	case "human":
		return "user"
	case "ai":
		return "assistant"
	case "function":
		return "tool"
	}
	return s
}
func modelJSON(s string) (map[string]any, error) {
	var v map[string]any
	if json.Unmarshal([]byte(s), &v) != nil || v == nil {
		return nil, &modelFailure{"invalid_tool_arguments"}
	}
	return v, nil
}
func modelToolNames(in pentagicore.CompletionRequest) map[string]string {
	m := map[string]string{}
	for _, msg := range in.Messages {
		for _, c := range msg.ToolCalls {
			m[c.ID] = c.Name
		}
	}
	return m
}
func (a *App) modelWireRequest(ctx context.Context, p agentModelProvider, in pentagicore.CompletionRequest) ([]byte, string, error) {
	if err := platformEndpoint(p.BaseURL); err != nil {
		return nil, "", &modelFailure{"invalid_endpoint"}
	}
	endpoint := strings.TrimRight(p.BaseURL, "/")
	payload := map[string]any{}
	messages := []any{}
	tools := []any{}
	systems := []string{}
	names := modelToolNames(in)
	for _, m := range in.Messages {
		if !hasString([]string{"system", "user", "assistant", "tool"}, modelRole(m.Role)) {
			return nil, "", &modelFailure{"invalid_message_role"}
		}
	}
	for _, t := range in.Tools {
		var schema map[string]any
		if json.Unmarshal(t.Parameters, &schema) != nil || schema == nil {
			return nil, "", &modelFailure{"invalid_tool_schema"}
		}
	}
	switch p.Type {
	case "anthropic":
		for _, m := range in.Messages {
			role := modelRole(m.Role)
			if role == "system" {
				systems = append(systems, m.Content)
				continue
			}
			blocks := []any{}
			if role == "tool" {
				role = "user"
				blocks = append(blocks, map[string]any{"type": "tool_result", "tool_use_id": m.ToolCallID, "content": m.Content})
			} else {
				if m.Content != "" {
					blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
				}
				for _, c := range m.ToolCalls {
					args, e := modelJSON(c.Arguments)
					if e != nil {
						return nil, "", e
					}
					blocks = append(blocks, map[string]any{"type": "tool_use", "id": c.ID, "name": c.Name, "input": args})
				}
			}
			if len(blocks) > 0 {
				messages = append(messages, map[string]any{"role": role, "content": blocks})
			}
		}
		for _, t := range in.Tools {
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "input_schema": t.Parameters})
		}
		payload = map[string]any{"model": p.Model, "messages": messages, "max_tokens": in.MaxTokens, "stream": true}
		if len(systems) > 0 {
			payload["system"] = strings.Join(systems, "\n\n")
		}
		if len(tools) > 0 {
			payload["tools"] = tools
			payload["tool_choice"] = map[string]any{"type": "auto", "disable_parallel_tool_use": true}
		}
		if !strings.HasSuffix(endpoint, "/messages") {
			endpoint += "/messages"
		}
	case "gemini":
		for _, m := range in.Messages {
			role := modelRole(m.Role)
			if role == "system" {
				systems = append(systems, m.Content)
				continue
			}
			parts := []any{}
			if role == "tool" {
				role = "user"
				name := names[m.ToolCallID]
				if name == "" {
					return nil, "", &modelFailure{"missing_tool_name"}
				}
				parts = append(parts, map[string]any{"functionResponse": map[string]any{"id": m.ToolCallID, "name": name, "response": map[string]any{"result": m.Content}}})
			} else {
				if role == "assistant" {
					role = "model"
				}
				if m.Content != "" {
					parts = append(parts, map[string]any{"text": m.Content})
				}
				for _, c := range m.ToolCalls {
					args, e := modelJSON(c.Arguments)
					if e != nil {
						return nil, "", e
					}
					parts = append(parts, map[string]any{"functionCall": map[string]any{"id": c.ID, "name": c.Name, "args": args}})
				}
				if len(m.ToolCalls) > 0 {
					stored, e := a.loadModelMetadata(ctx, p, m.ToolCalls[0].ID)
					if e != nil {
						return nil, "", e
					}
					if len(stored) > 0 {
						if json.Unmarshal(stored, &parts) != nil {
							return nil, "", &modelFailure{"invalid_provider_metadata"}
						}
					}
				}
			}
			if len(parts) > 0 {
				messages = append(messages, map[string]any{"role": role, "parts": parts})
			}
		}
		for _, t := range in.Tools {
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "parametersJsonSchema": t.Parameters})
		}
		payload = map[string]any{"contents": messages, "generationConfig": map[string]any{"maxOutputTokens": in.MaxTokens, "candidateCount": 1}}
		if len(systems) > 0 {
			payload["systemInstruction"] = map[string]any{"parts": []any{map[string]any{"text": strings.Join(systems, "\n\n")}}}
		}
		if len(tools) > 0 {
			payload["tools"] = []any{map[string]any{"functionDeclarations": tools}}
			payload["toolConfig"] = map[string]any{"functionCallingConfig": map[string]any{"mode": "AUTO"}}
		}
		endpoint += "/models/" + url.PathEscape(strings.TrimPrefix(p.Model, "models/")) + ":streamGenerateContent?alt=sse"
	default:
		for _, m := range in.Messages {
			role := modelRole(m.Role)
			msg := map[string]any{"role": role, "content": m.Content}
			if m.ToolCallID != "" {
				if p.Type == "ollama" {
					name := names[m.ToolCallID]
					if name == "" {
						return nil, "", &modelFailure{"missing_tool_name"}
					}
					msg["tool_name"] = name
				} else {
					msg["tool_call_id"] = m.ToolCallID
				}
			}
			calls := []any{}
			for _, c := range m.ToolCalls {
				var args any = c.Arguments
				if p.Type == "ollama" {
					v, e := modelJSON(c.Arguments)
					if e != nil {
						return nil, "", e
					}
					args = v
				}
				calls = append(calls, map[string]any{"id": c.ID, "type": "function", "function": map[string]any{"name": c.Name, "arguments": args}})
			}
			if len(calls) > 0 {
				msg["tool_calls"] = calls
			}
			if m.Reasoning != "" && p.Type == "openai" {
				msg["reasoning_content"] = m.Reasoning
			}
			messages = append(messages, msg)
		}
		for _, t := range in.Tools {
			tools = append(tools, map[string]any{"type": "function", "function": map[string]any{"name": t.Name, "description": t.Description, "parameters": t.Parameters}})
		}
		payload = map[string]any{"model": p.Model, "messages": messages, "stream": true}
		if len(tools) > 0 {
			payload["tools"] = tools
		}
		if p.Type == "ollama" {
			payload["options"] = map[string]any{"num_predict": in.MaxTokens, "num_ctx": in.ContextWindow}
			if !strings.HasSuffix(endpoint, "/api/chat") {
				endpoint += "/api/chat"
			}
		} else {
			payload["max_tokens"] = in.MaxTokens
			payload["stream_options"] = map[string]any{"include_usage": true}
			if len(tools) > 0 {
				payload["tool_choice"] = "auto"
				payload["parallel_tool_calls"] = false
			}
			if !strings.HasSuffix(endpoint, "/chat/completions") {
				endpoint += "/chat/completions"
			}
		}
	}
	body, e := json.Marshal(payload)
	if e != nil {
		return nil, "", e
	}
	if len(body)+in.MaxTokens+512 > in.ContextWindow {
		return nil, "", &modelFailure{"context_budget"}
	}
	return body, endpoint, nil
}

func readModelEvents(reader io.Reader, ndjson bool, fn func([]byte) error) error {
	limited := &io.LimitedReader{R: reader, N: 16<<20 + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 8192), 2<<20)
	data := []string{}
	flush := func() error {
		if len(data) == 0 {
			return nil
		}
		raw := strings.Join(data, "\n")
		data = nil
		return fn([]byte(raw))
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if ndjson {
			if strings.TrimSpace(line) != "" {
				if e := fn([]byte(line)); e != nil {
					return e
				}
			}
			continue
		}
		if line == "" {
			if e := flush(); e != nil {
				return e
			}
		} else if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if limited.N <= 0 {
		return &modelFailure{"response_too_large"}
	}
	if e := scanner.Err(); e != nil {
		return &modelFailure{"stream_interrupted"}
	}
	return flush()
}
func readModelWire(reader io.Reader, kind, contentType string) (out pentagicore.CompletionResult, metadata map[string]json.RawMessage, err error) {
	metadata = map[string]json.RawMessage{}
	if kind == "openai" {
		if !strings.HasPrefix(contentType, "text/event-stream") {
			return out, metadata, &modelFailure{"stream_required"}
		}
		out, err = readAgentCompletion(reader, nil)
		if err != nil {
			return out, metadata, &modelFailure{"invalid_stream"}
		}
		if out.FinishReason == "" {
			out.FinishReason = "stop"
			if len(out.ToolCalls) > 0 {
				out.FinishReason = "tool_calls"
			}
		}
		return out, metadata, validateModelResult(out)
	}
	if kind == "ollama" {
		if !strings.HasPrefix(contentType, "application/x-ndjson") && !strings.HasPrefix(contentType, "application/json") {
			return out, metadata, &modelFailure{"stream_required"}
		}
	} else if !strings.HasPrefix(contentType, "text/event-stream") {
		return out, metadata, &modelFailure{"stream_required"}
	}
	done := false
	calls := map[int]*pentagicore.ToolCall{}
	argumentChunks := map[int]bool{}
	geminiParts := []any{}
	geminiIDs := map[string]int{}
	geminiPartIndexes := map[string]int{}
	err = readModelEvents(reader, kind == "ollama", func(raw []byte) error {
		if bytes.Equal(raw, []byte("[DONE]")) {
			return nil
		}
		var packet map[string]json.RawMessage
		if json.Unmarshal(raw, &packet) != nil {
			return &modelFailure{"invalid_stream_json"}
		}
		if b := packet["error"]; len(b) > 0 && string(b) != "null" {
			return &modelFailure{"provider_stream_error"}
		}
		if done {
			return &modelFailure{"data_after_completion"}
		}
		switch kind {
		case "anthropic":
			var p struct {
				Type         string `json:"type"`
				Index        int    `json:"index"`
				ContentBlock struct {
					Type, ID, Name, Text, Thinking string
					Input                          json.RawMessage
				} `json:"content_block"`
				Delta struct {
					Type, Text, Thinking string
					Partial              string `json:"partial_json"`
					Stop                 string `json:"stop_reason"`
				} `json:"delta"`
				Message struct {
					Usage struct {
						Input  int64 `json:"input_tokens"`
						Output int64 `json:"output_tokens"`
					}
				} `json:"message"`
				Usage struct {
					Input  int64 `json:"input_tokens"`
					Output int64 `json:"output_tokens"`
				} `json:"usage"`
			}
			if json.Unmarshal(raw, &p) != nil {
				return &modelFailure{"invalid_stream_json"}
			}
			switch p.Type {
			case "message_start":
				out.InputTokens = p.Message.Usage.Input
				out.OutputTokens = p.Message.Usage.Output
			case "content_block_start":
				if p.Index < 0 || p.Index > 63 {
					return &modelFailure{"tool_limit"}
				}
				if p.ContentBlock.Type == "tool_use" {
					if calls[p.Index] != nil {
						return &modelFailure{"duplicate_tool_block"}
					}
					args := string(p.ContentBlock.Input)
					if args == "" {
						args = "{}"
					}
					calls[p.Index] = &pentagicore.ToolCall{ID: p.ContentBlock.ID, Name: p.ContentBlock.Name, Arguments: args}
				}
				if p.ContentBlock.Type == "text" {
					out.Content += p.ContentBlock.Text
				}
				if p.ContentBlock.Type == "thinking" {
					out.Reasoning += p.ContentBlock.Thinking
				}
				if p.ContentBlock.Type == "server_tool_use" {
					return &modelFailure{"unsupported_server_tool"}
				}
			case "content_block_delta":
				switch p.Delta.Type {
				case "text_delta":
					out.Content += p.Delta.Text
				case "thinking_delta":
					out.Reasoning += p.Delta.Thinking
				case "input_json_delta":
					c := calls[p.Index]
					if c == nil {
						return &modelFailure{"missing_tool_block"}
					}
					if !argumentChunks[p.Index] {
						c.Arguments = ""
						argumentChunks[p.Index] = true
					}
					c.Arguments += p.Delta.Partial
				}
			case "message_delta":
				if p.Usage.Input > 0 {
					out.InputTokens = p.Usage.Input
				}
				out.OutputTokens = p.Usage.Output
				out.FinishReason = normalizeModelFinish(p.Delta.Stop)
			case "message_stop":
				done = true
			}
		case "gemini":
			var p struct {
				Candidates []struct {
					Index   int `json:"index"`
					Content struct {
						Parts []json.RawMessage `json:"parts"`
					} `json:"content"`
					FinishReason string `json:"finishReason"`
				} `json:"candidates"`
				Usage struct {
					Input    int64 `json:"promptTokenCount"`
					Output   int64 `json:"candidatesTokenCount"`
					Thinking int64 `json:"thoughtsTokenCount"`
				} `json:"usageMetadata"`
				PromptFeedback struct {
					BlockReason string `json:"blockReason"`
				} `json:"promptFeedback"`
			}
			if json.Unmarshal(raw, &p) != nil {
				return &modelFailure{"invalid_stream_json"}
			}
			if p.PromptFeedback.BlockReason != "" {
				return &modelFailure{"content_filter"}
			}
			if p.Usage.Input > 0 {
				out.InputTokens = p.Usage.Input
			}
			if p.Usage.Output+p.Usage.Thinking > 0 {
				out.OutputTokens = p.Usage.Output + p.Usage.Thinking
			}
			for _, candidate := range p.Candidates {
				if candidate.Index != 0 {
					continue
				}
				for _, rawPart := range candidate.Content.Parts {
					var part map[string]any
					if json.Unmarshal(rawPart, &part) != nil {
						return &modelFailure{"invalid_stream_json"}
					}
					for key := range part {
						if !hasString([]string{"text", "thought", "thoughtSignature", "functionCall"}, key) {
							delete(part, key)
						}
					}
					if signature, ok := part["thoughtSignature"]; ok {
						v, ok := signature.(string)
						if !ok || len(v) > 65536 {
							return &modelFailure{"invalid_provider_metadata"}
						}
						if _, e := base64.StdEncoding.DecodeString(v); e != nil {
							return &modelFailure{"invalid_provider_metadata"}
						}
					}
					if text := asString(part["text"]); text != "" {
						if asBool(part["thought"]) {
							out.Reasoning += text
						} else {
							out.Content += text
						}
					}
					if fc, ok := part["functionCall"].(map[string]any); ok {
						name := asString(fc["name"])
						id := asString(fc["id"])
						if id == "" {
							id = "gemini_" + newID()
							fc["id"] = id
						}
						index, exists := geminiIDs[id]
						if !exists {
							index = len(calls)
							if index > 63 {
								return &modelFailure{"tool_limit"}
							}
							geminiIDs[id] = index
							calls[index] = &pentagicore.ToolCall{ID: id, Name: name}
						}
						args := fc["args"]
						if args == nil {
							args = map[string]any{}
						}
						b, e := json.Marshal(args)
						if e != nil {
							return &modelFailure{"invalid_tool_arguments"}
						}
						if exists && calls[index].Arguments != "" && calls[index].Arguments != string(b) {
							return &modelFailure{"conflicting_tool_arguments"}
						}
						calls[index].Arguments = string(b)
						if exists {
							prior := geminiParts[geminiPartIndexes[id]].(map[string]any)
							if sig, ok := part["thoughtSignature"]; ok {
								prior["thoughtSignature"] = sig
							}
							continue
						}
						geminiPartIndexes[id] = len(geminiParts)
					}
					geminiParts = append(geminiParts, part)
				}
				if candidate.FinishReason != "" {
					done = true
					out.FinishReason = normalizeModelFinish(candidate.FinishReason)
				}
			}
		case "ollama":
			var p struct {
				Message struct {
					Content  string `json:"content"`
					Thinking string `json:"thinking"`
					Calls    []struct {
						ID       string `json:"id"`
						Function struct {
							Name      string          `json:"name"`
							Arguments json.RawMessage `json:"arguments"`
						}
					} `json:"tool_calls"`
				} `json:"message"`
				Done   bool   `json:"done"`
				Reason string `json:"done_reason"`
				Input  int64  `json:"prompt_eval_count"`
				Output int64  `json:"eval_count"`
			}
			if json.Unmarshal(raw, &p) != nil {
				return &modelFailure{"invalid_stream_json"}
			}
			out.Content += p.Message.Content
			out.Reasoning += p.Message.Thinking
			for _, c := range p.Message.Calls {
				if len(calls) >= 64 {
					return &modelFailure{"tool_limit"}
				}
				id := c.ID
				if id == "" {
					id = "ollama_" + newID()
				}
				calls[len(calls)] = &pentagicore.ToolCall{ID: id, Name: c.Function.Name, Arguments: string(c.Function.Arguments)}
			}
			if p.Done {
				done = true
				out.InputTokens = p.Input
				out.OutputTokens = p.Output
				out.FinishReason = normalizeModelFinish(p.Reason)
			}
		}
		size := len(out.Content) + len(out.Reasoning)
		for _, c := range calls {
			size += len(c.Arguments)
		}
		if size > 4<<20 {
			return &modelFailure{"response_too_large"}
		}
		return nil
	})
	if err != nil {
		return out, metadata, err
	}
	if !done {
		return out, metadata, &modelFailure{"incomplete_stream"}
	}
	indexes := []int{}
	for i := range calls {
		indexes = append(indexes, i)
	}
	sort.Ints(indexes)
	for _, i := range indexes {
		out.ToolCalls = append(out.ToolCalls, *calls[i])
	}
	if len(out.ToolCalls) > 0 && out.FinishReason == "stop" {
		out.FinishReason = "tool_calls"
	}
	if kind == "gemini" && len(out.ToolCalls) > 0 {
		raw, _ := json.Marshal(geminiParts)
		if len(raw) > 4<<20 {
			return out, metadata, &modelFailure{"response_too_large"}
		}
		// The first call anchors its complete assistant message. Persisting the
		// same 4 MiB message once per parallel call would multiply storage 64x.
		metadata[out.ToolCalls[0].ID] = raw
	}
	return out, metadata, validateModelResult(out)
}
func normalizeModelFinish(s string) string {
	switch strings.ToLower(s) {
	case "stop", "end_turn", "stop_sequence":
		return "stop"
	case "tool_use", "tool_calls":
		return "tool_calls"
	case "max_tokens", "length":
		return "length"
	case "safety", "recitation", "blocklist", "prohibited_content", "spii", "content_filter", "refusal":
		return "content_filter"
	case "":
		return ""
	default:
		return strings.ToLower(s)
	}
}
func validateModelResult(out pentagicore.CompletionResult) error {
	if !hasString([]string{"stop", "tool_calls", "length", "content_filter"}, out.FinishReason) {
		return &modelFailure{"unsupported_finish_reason"}
	}
	if out.InputTokens < 0 || out.OutputTokens < 0 {
		return &modelFailure{"invalid_usage"}
	}
	ids := map[string]bool{}
	for _, c := range out.ToolCalls {
		if c.ID == "" || c.Name == "" || len(c.ID) > 512 || ids[c.ID] {
			return &modelFailure{"invalid_tool_call"}
		}
		if _, e := modelJSON(c.Arguments); e != nil {
			return e
		}
		ids[c.ID] = true
	}
	if len(out.ToolCalls) > 64 || out.Content == "" && len(out.ToolCalls) == 0 {
		return &modelFailure{"empty_response"}
	}
	return nil
}
func (a *App) storeModelMetadata(ctx context.Context, p agentModelProvider, items map[string]json.RawMessage) error {
	ctl, _ := ctx.Value(modelCallContextKey{}).(modelCallContext)
	if len(items) == 0 || ctl.RunID == "" {
		return nil
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	for id, raw := range items {
		sum := sha256.Sum256(raw)
		hash := hex.EncodeToString(sum[:])
		cipher, e := a.encrypt(string(raw))
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO agent_model_tool_metadata(run_id,call_id,provider_id,metadata_encrypted,metadata_hash) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, ctl.RunID, id, providerIdentity(p), cipher, hash)
		if e != nil {
			return e
		}
		var stored string
		if e = tx.QueryRow(ctx, `SELECT metadata_hash FROM agent_model_tool_metadata WHERE run_id=$1 AND call_id=$2 AND provider_id=$3`, ctl.RunID, id, providerIdentity(p)).Scan(&stored); e != nil {
			return e
		}
		if stored != hash {
			return &modelFailure{"provider_metadata_conflict"}
		}
	}
	return tx.Commit(ctx)
}
func (a *App) loadModelMetadata(ctx context.Context, p agentModelProvider, callID string) (json.RawMessage, error) {
	ctl, _ := ctx.Value(modelCallContextKey{}).(modelCallContext)
	if ctl.RunID == "" {
		return nil, nil
	}
	var cipher, hash string
	e := a.DB.QueryRow(ctx, `SELECT metadata_encrypted,metadata_hash FROM agent_model_tool_metadata WHERE run_id=$1 AND call_id=$2 AND provider_id=$3`, ctl.RunID, callID, providerIdentity(p)).Scan(&cipher, &hash)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	raw, e := a.decrypt(cipher)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256([]byte(raw))
	if fmt.Sprintf("%x", sum) != hash {
		return nil, &modelFailure{"provider_metadata_integrity"}
	}
	return json.RawMessage(raw), nil
}
