package llmparse

import (
	"encoding/json"
	"fmt"
	"time"
)

// responsesRequest represents the OpenAI Responses API request body.
type responsesRequest struct {
	Model  string          `json:"model"`
	Input  json.RawMessage `json:"input"`  // string or array of items
	Output json.RawMessage `json:"output"` // array of output items (in continuation)
	Tools  json.RawMessage `json:"tools,omitempty"`
}

// responsesItem represents an item in the input or output array.
type responsesItem struct {
	Type   string `json:"type"`             // "function_call", "function_call_output", "message", etc.
	ID     string `json:"id,omitempty"`     // for function_call
	CallID string `json:"call_id,omitempty"` // for function_call_output
	Name   string `json:"name,omitempty"`
	Args   string `json:"arguments,omitempty"` // JSON string of arguments
	Output string `json:"output,omitempty"`    // result text for function_call_output
}

// ParseOpenAIResponsesRequest parses an OpenAI Responses API request body and
// extracts the latest tool call pair (function_call + function_call_output).
func ParseOpenAIResponsesRequest(body []byte, userAgent string) (*ParseResult, error) {
	var req responsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal openai responses request: %w", err)
	}

	model := req.Model

	// Collect function_call and function_call_output items from both input and output.
	type funcCall struct {
		id   string
		name string
		args string
	}

	var calls []funcCall
	results := make(map[string]string) // id/call_id → output

	processItems := func(raw json.RawMessage) {
		if len(raw) == 0 {
			return
		}
		var items []responsesItem
		if err := json.Unmarshal(raw, &items); err != nil {
			return
		}
		for _, item := range items {
			switch item.Type {
			case "function_call":
				calls = append(calls, funcCall{
					id:   item.ID,
					name: item.Name,
					args: item.Args,
				})
			case "function_call_output":
				if item.CallID != "" {
					results[item.CallID] = item.Output
				}
			}
		}
	}

	// input can be a string or an array of items.
	// Try array first; if it fails, it's a string (no tool calls in string input).
	processItems(req.Input)
	processItems(req.Output)

	if len(calls) == 0 {
		return &ParseResult{
			Model:    model,
			Agent:    userAgent,
			Provider: "openai-responses",
		}, nil
	}

	// Return only the last function_call + its output.
	lastCall := calls[len(calls)-1]
	now := time.Now().UTC()

	event := AgentEvent{
		EventID:       lastCall.id,
		Timestamp:     now,
		Provider:      "openai-responses",
		Model:         model,
		AgentIdentity: userAgent,
		EventType:     "tool_use",
		ToolName:      lastCall.name,
		ToolArgs:      lastCall.args,
	}

	if result, ok := results[lastCall.id]; ok {
		event.ToolResult = truncate(result, maxToolResultBytes)
	}

	return &ParseResult{
		Events:   []AgentEvent{event},
		Model:    model,
		Agent:    userAgent,
		Provider: "openai-responses",
	}, nil
}
