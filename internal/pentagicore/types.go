// Package pentagicore adapts the pinned PentAGI agent core to Hunter's
// authenticated model and tool boundaries. It does not open network connections
// to targets or initialize PentAGI's Docker, server, or telemetry runtimes.
package pentagicore

import (
	"context"
	"encoding/json"
)

const UpstreamCommit = "ea665308baaff015b226f308438a68d929d0f29b"

type Request struct {
	RunID         string
	ServiceID     string
	Prompt        string
	MaxIterations int
	MaxModelCalls int
	MaxTokens     int
	ContextWindow int
}

type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	Reasoning  string     `json:"reasoning_content,omitempty"`
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type CompletionRequest struct {
	Role          string
	Messages      []Message
	Tools         []ToolDefinition
	MaxTokens     int
	ContextWindow int
	OnDelta       func(string) `json:"-"`
}

type CompletionResult struct {
	Content      string
	Reasoning    string
	ToolCalls    []ToolCall
	InputTokens  int64
	OutputTokens int64
	FinishReason string
}

type Event struct {
	Type       string         `json:"type"`
	Role       string         `json:"role,omitempty"`
	Message    string         `json:"message,omitempty"`
	ToolName   string         `json:"tool_name,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	Status     string         `json:"status,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

type Hooks struct {
	Complete    func(context.Context, CompletionRequest) (CompletionResult, error)
	ExecuteTool func(context.Context, string, json.RawMessage) (string, error)
	Emit        func(Event)
	Check       func(context.Context) error
}

type Result struct {
	Status       string `json:"status"`
	Summary      string `json:"summary"`
	FlowID       int64  `json:"flow_id"`
	TaskID       int64  `json:"task_id"`
	Subtasks     int    `json:"subtasks"`
	ModelCalls   int    `json:"model_calls"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
}
