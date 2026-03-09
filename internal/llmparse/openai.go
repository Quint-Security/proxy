package llmparse

import (
	"encoding/json"
	"fmt"
	"time"
)

// openaiRequest represents the top-level OpenAI Chat Completions API request body.
type openaiRequest struct {
	Model    string       `json:"model"`
	Messages []openaiMsg  `json:"messages"`
}

// openaiMsg represents a single message in the OpenAI conversation.
type openaiMsg struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content,omitempty"` // string or null for assistant tool_calls
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"` // for role=tool messages
}

// openaiToolCall represents a tool call entry in an assistant message.
type openaiToolCall struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"` // "function"
	Function openaiFunction  `json:"function"`
}

// openaiFunction represents the function details within a tool call.
type openaiFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string
}

// openaiToolUse is an intermediate struct for pairing tool calls with results.
type openaiToolUse struct {
	id        string
	name      string
	arguments string
}

// ParseOpenAIRequest parses an OpenAI Chat Completions API request body and extracts
// the latest tool call pair (tool_call + tool result). It returns only new events,
// meaning the last tool_call/result pair found in the conversation.
func ParseOpenAIRequest(body []byte, userAgent string) (*ParseResult, error) {
	var req openaiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal openai request: %w", err)
	}

	model := req.Model

	// Collect all tool calls and tool results.
	var toolCalls []openaiToolUse
	toolResults := make(map[string]string) // tool_call_id -> result content

	for _, msg := range req.Messages {
		switch msg.Role {
		case "assistant":
			for _, tc := range msg.ToolCalls {
				toolCalls = append(toolCalls, openaiToolUse{
					id:        tc.ID,
					name:      tc.Function.Name,
					arguments: tc.Function.Arguments,
				})
			}
		case "tool":
			if msg.ToolCallID != "" {
				content := extractOpenAIContent(msg.Content)
				toolResults[msg.ToolCallID] = content
			}
		}
	}

	if len(toolCalls) == 0 {
		return &ParseResult{
			Model: model,
			Agent: userAgent,
		}, nil
	}

	// Return only the last tool call/result pair as the "new" event.
	lastCall := toolCalls[len(toolCalls)-1]
	now := time.Now().UTC()

	event := AgentEvent{
		EventID:       lastCall.id,
		Timestamp:     now,
		Provider:      "openai",
		Model:         model,
		AgentIdentity: userAgent,
		EventType:     "tool_use",
		ToolName:      lastCall.name,
		ToolArgs:      lastCall.arguments,
	}

	if result, ok := toolResults[lastCall.id]; ok {
		event.ToolResult = truncate(result, maxToolResultBytes)
	}

	return &ParseResult{
		Events: []AgentEvent{event},
		Model:  model,
		Agent:  userAgent,
	}, nil
}

// extractOpenAIContent extracts a string from the content field which may be
// a JSON string, null, or absent.
func extractOpenAIContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}

	return ""
}
