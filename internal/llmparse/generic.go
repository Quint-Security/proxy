package llmparse

import (
	"encoding/json"
	"fmt"
	"time"
)

// ParseGenericRequest is a conservative fallback parser for unknown providers.
// It recursively searches the body for tool-call-like patterns and extracts
// the tool name and arguments if found. Returns nil if nothing resembling a
// tool call is detected (conservative — no false positives).
func ParseGenericRequest(body []byte, userAgent string) (*ParseResult, error) {
	var raw interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal generic request: %w", err)
	}

	name, args := findToolCall(raw)
	if name == "" {
		return nil, nil
	}

	now := time.Now().UTC()
	event := AgentEvent{
		EventID:       fmt.Sprintf("generic-%d", now.UnixMilli()),
		Timestamp:     now,
		Provider:      "generic",
		AgentIdentity: userAgent,
		EventType:     "tool_use",
		ToolName:      name,
		ToolArgs:      args,
	}

	// Try to extract model from top-level.
	model := ""
	if m, ok := raw.(map[string]interface{}); ok {
		if v, ok := m["model"]; ok {
			if s, ok := v.(string); ok {
				model = s
			}
		}
	}

	return &ParseResult{
		Events:   []AgentEvent{event},
		Model:    model,
		Agent:    userAgent,
		Provider: "generic",
	}, nil
}

// toolCallKeys are the JSON keys that indicate a tool call object.
var toolCallKeys = []string{"tool_use", "tool_calls", "function_call", "functionCall"}

// findToolCall recursively searches a parsed JSON value for tool-call-like structures.
// Returns the tool name and arguments JSON string, or ("", "") if not found.
func findToolCall(v interface{}) (name string, args string) {
	switch val := v.(type) {
	case map[string]interface{}:
		// Check if this object itself looks like a tool call.
		if n, a, ok := extractFromToolObject(val); ok {
			return n, a
		}

		// Check known tool-call container keys.
		for _, key := range toolCallKeys {
			if child, ok := val[key]; ok {
				if n, a := extractToolFromValue(child); n != "" {
					return n, a
				}
			}
		}

		// Recurse into all values.
		for _, child := range val {
			if n, a := findToolCall(child); n != "" {
				return n, a
			}
		}

	case []interface{}:
		// Search from the end (most recent tool call).
		for i := len(val) - 1; i >= 0; i-- {
			if n, a := findToolCall(val[i]); n != "" {
				return n, a
			}
		}
	}

	return "", ""
}

// extractToolFromValue tries to extract tool name+args from a value that may be
// a tool call object or an array of tool call objects.
func extractToolFromValue(v interface{}) (string, string) {
	switch val := v.(type) {
	case map[string]interface{}:
		if n, a, ok := extractFromToolObject(val); ok {
			return n, a
		}
	case []interface{}:
		// Search from end for latest.
		for i := len(val) - 1; i >= 0; i-- {
			if m, ok := val[i].(map[string]interface{}); ok {
				if n, a, ok := extractFromToolObject(m); ok {
					return n, a
				}
			}
		}
	}
	return "", ""
}

// extractFromToolObject checks if a map looks like a tool call and extracts name + args.
// It requires at least a "name" field to be present.
func extractFromToolObject(m map[string]interface{}) (name string, args string, ok bool) {
	// Direct name field.
	nameVal, hasName := m["name"]
	if !hasName {
		// Check for nested "function" object (OpenAI style).
		if funcObj, ok := m["function"]; ok {
			if fm, ok := funcObj.(map[string]interface{}); ok {
				return extractFromToolObject(fm)
			}
		}
		return "", "", false
	}

	nameStr, ok := nameVal.(string)
	if !ok || nameStr == "" {
		return "", "", false
	}

	// Try to extract arguments from various known keys.
	argsJSON := "{}"
	for _, key := range []string{"arguments", "input", "args"} {
		if argsVal, ok := m[key]; ok {
			switch a := argsVal.(type) {
			case string:
				argsJSON = a
			case map[string]interface{}:
				if b, err := json.Marshal(a); err == nil {
					argsJSON = string(b)
				}
			}
			break
		}
	}

	return nameStr, argsJSON, true
}
