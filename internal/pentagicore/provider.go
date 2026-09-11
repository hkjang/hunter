package pentagicore

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vxcontrol/langchaingo/llms"
	"github.com/vxcontrol/langchaingo/llms/reasoning"
	"github.com/vxcontrol/langchaingo/llms/streaming"
	"pentagi/pkg/cast"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/providers/provider"
	"pentagi/pkg/templates"
)

type hookProvider struct{ run *runState }

func (p *hookProvider) Type() provider.ProviderType              { return provider.ProviderCustom }
func (p *hookProvider) Name() provider.ProviderName              { return "hunter" }
func (p *hookProvider) Model(pconfig.ProviderOptionsType) string { return "hunter-configured-model" }
func (p *hookProvider) ModelWithPrefix(o pconfig.ProviderOptionsType) string {
	return "custom/" + p.Model(o)
}
func (p *hookProvider) GetUsage(i map[string]any) pconfig.CallUsage                 { return pconfig.NewCallUsage(i) }
func (p *hookProvider) GetRawConfig() []byte                                        { return []byte(`{"transport":"hunter"}`) }
func (p *hookProvider) GetProviderConfig() *pconfig.ProviderConfig                  { return &pconfig.ProviderConfig{} }
func (p *hookProvider) GetPriceInfo(pconfig.ProviderOptionsType) *pconfig.PriceInfo { return nil }
func (p *hookProvider) GetModels() pconfig.ModelsConfig                             { return nil }
func (p *hookProvider) GetToolCallIDTemplate(context.Context, templates.Prompter) (string, error) {
	return cast.ToolCallIDTemplate, nil
}
func (p *hookProvider) Call(ctx context.Context, role pconfig.ProviderOptionsType, prompt string) (string, error) {
	r, e := p.CallEx(ctx, role, []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, prompt)}, nil)
	if e != nil {
		return "", e
	}
	if len(r.Choices) == 0 {
		return "", fmt.Errorf("empty model response")
	}
	return r.Choices[0].Content, nil
}
func (p *hookProvider) CallEx(ctx context.Context, role pconfig.ProviderOptionsType, chain []llms.MessageContent, cb streaming.Callback) (*llms.ContentResponse, error) {
	return p.CallWithTools(ctx, role, chain, nil, cb)
}
func (p *hookProvider) CallWithExtraOptions(ctx context.Context, role pconfig.ProviderOptionsType, chain []llms.MessageContent, tools []llms.Tool, cb streaming.Callback, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	return p.CallWithTools(ctx, role, chain, tools, cb)
}
func (p *hookProvider) CallWithTools(ctx context.Context, role pconfig.ProviderOptionsType, chain []llms.MessageContent, defs []llms.Tool, cb streaming.Callback) (*llms.ContentResponse, error) {
	if err := p.run.check(ctx); err != nil {
		return nil, err
	}
	for {
		n := p.run.calls.Load()
		if n >= int64(p.run.req.MaxModelCalls) {
			if p.run.cancel != nil {
				p.run.cancel()
			}
			return nil, fmt.Errorf("agent run reached total model call budget (%d)", p.run.req.MaxModelCalls)
		}
		if p.run.calls.CompareAndSwap(n, n+1) {
			break
		}
	}
	messages, err := wireMessages(chain)
	if err != nil {
		return nil, err
	}
	request := CompletionRequest{Role: string(role), Messages: messages, MaxTokens: p.run.req.MaxTokens, ContextWindow: p.run.req.ContextWindow}
	for _, t := range defs {
		b, err := json.Marshal(t.Function.Parameters)
		if err != nil {
			return nil, err
		}
		request.Tools = append(request.Tools, ToolDefinition{Name: t.Function.Name, Description: t.Function.Description, Parameters: b})
	}
	var streamErr error
	request.OnDelta = func(s string) {
		if streamErr != nil {
			return
		}
		if cb != nil {
			streamErr = cb(ctx, streaming.NewTextChunk(s))
		}
		p.run.emit(Event{Type: "delta", Role: string(role), Message: s})
	}
	p.run.emit(Event{Type: "model", Role: string(role), Status: "running"})
	answer, err := p.run.hooks.Complete(ctx, request)
	if err != nil {
		return nil, err
	}
	if streamErr != nil {
		return nil, streamErr
	}
	if err = p.run.check(ctx); err != nil {
		return nil, err
	}
	p.run.input.Add(answer.InputTokens)
	p.run.output.Add(answer.OutputTokens)
	choice := &llms.ContentChoice{Content: answer.Content, StopReason: answer.FinishReason, Reasoning: &reasoning.ContentReasoning{Content: answer.Reasoning}, GenerationInfo: map[string]any{"PromptTokens": answer.InputTokens, "CompletionTokens": answer.OutputTokens}}
	for i, t := range answer.ToolCalls {
		if t.ID == "" {
			return nil, fmt.Errorf("model tool call %d has no ID", i)
		}
		choice.ToolCalls = append(choice.ToolCalls, llms.ToolCall{ID: t.ID, Type: "function", FunctionCall: &llms.FunctionCall{Name: t.Name, Arguments: t.Arguments}})
	}
	p.run.emit(Event{Type: "model", Role: string(role), Status: "finished", Data: map[string]any{"input_tokens": answer.InputTokens, "output_tokens": answer.OutputTokens}})
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{choice}}, nil
}

func wireMessages(chain []llms.MessageContent) ([]Message, error) {
	var out []Message
	for _, raw := range chain {
		m := Message{Role: string(raw.Role)}
		switch raw.Role {
		case llms.ChatMessageTypeHuman:
			m.Role = "user"
		case llms.ChatMessageTypeAI:
			m.Role = "assistant"
		}
		for _, part := range raw.Parts {
			switch v := part.(type) {
			case llms.TextContent:
				m.Content += v.Text
				if v.Reasoning != nil {
					m.Reasoning += v.Reasoning.Content
				}
			case llms.ToolCall:
				if v.FunctionCall != nil {
					m.ToolCalls = append(m.ToolCalls, ToolCall{ID: v.ID, Name: v.FunctionCall.Name, Arguments: v.FunctionCall.Arguments})
				}
			case llms.ToolCallResponse:
				// OpenAI-compatible wire protocol requires one message per tool response.
				out = append(out, Message{Role: "tool", ToolCallID: v.ToolCallID, Content: v.Content})
			case llms.CacheControl:
			default:
				return nil, fmt.Errorf("unsupported embedded model content %T", part)
			}
		}
		if raw.Role != llms.ChatMessageTypeTool || m.Content != "" || len(m.ToolCalls) > 0 {
			out = append(out, m)
		}
	}
	return out, nil
}
