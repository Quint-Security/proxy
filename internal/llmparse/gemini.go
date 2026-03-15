package llmparse

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// geminiRequest represents the Google Gemini API request body.
type geminiRequest struct {
	Model    string          `json:"model,omitempty"`
	Contents []geminiContent `json:"contents"`
}

// geminiContent represents a single content entry in the Gemini conversation.
type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

// geminiPart represents a part within a Gemini content entry.
type geminiPart struct {
	Text             string              `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall `json:"functionCall,omitempty"`
	FunctionResponse *geminiFuncResponse `json:"functionResponse,omitempty"`
}

// geminiFunctionCall represents a function call from the model.
type geminiFunctionCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args,omitempty"`
}

// geminiFuncResponse represents a function response from the user.
type geminiFuncResponse struct {
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response,omitempty"`
}

// ParseGeminiRequest parses a Google Gemini API request body and extracts
// the latest tool call pair (functionCall + functionResponse).
func ParseGeminiRequest(body []byte, userAgent string, path string) (*ParseResult, error) {
	var req geminiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal gemini request: %w", err)
	}

	// Determine model: try body field first, fall back to path extraction.
	model := req.Model
	if model == "" {
		model = extractModelFromPath(path)
	}

	// Collect functionCall entries from "model" role and functionResponse from "user" role.
	type funcCallEntry struct {
		name string
		args string
	}

	var calls []funcCallEntry
	responses := make(map[string]string) // function name → response JSON

	for _, content := range req.Contents {
		for _, part := range content.Parts {
			if content.Role == "model" && part.FunctionCall != nil {
				argsJSON := "{}"
				if part.FunctionCall.Args != nil {
					if b, err := json.Marshal(part.FunctionCall.Args); err == nil {
						argsJSON = string(b)
					}
				}
				calls = append(calls, funcCallEntry{
					name: part.FunctionCall.Name,
					args: argsJSON,
				})
			}
			if content.Role == "user" && part.FunctionResponse != nil {
				respJSON := ""
				if part.FunctionResponse.Response != nil {
					if b, err := json.Marshal(part.FunctionResponse.Response); err == nil {
						respJSON = string(b)
					}
				}
				responses[part.FunctionResponse.Name] = respJSON
			}
		}
	}

	if len(calls) == 0 {
		return &ParseResult{
			Model:    model,
			Agent:    userAgent,
			Provider: "google-gemini",
		}, nil
	}

	// Return only the last functionCall + its matching functionResponse.
	lastCall := calls[len(calls)-1]
	now := time.Now().UTC()

	event := AgentEvent{
		EventID:       fmt.Sprintf("gemini-%d", now.UnixMilli()),
		Timestamp:     now,
		Provider:      "google-gemini",
		Model:         model,
		AgentIdentity: userAgent,
		EventType:     "tool_use",
		ToolName:      lastCall.name,
		ToolArgs:      lastCall.args,
	}

	if result, ok := responses[lastCall.name]; ok {
		event.ToolResult = truncate(result, maxToolResultBytes)
	}

	return &ParseResult{
		Events:   []AgentEvent{event},
		Model:    model,
		Agent:    userAgent,
		Provider: "google-gemini",
	}, nil
}

// extractModelFromPath tries to extract the model name from a Gemini API path.
// Example path: /v1beta/models/gemini-2.0-flash:generateContent
func extractModelFromPath(path string) string {
	// Look for "models/" segment.
	idx := strings.Index(path, "models/")
	if idx < 0 {
		return ""
	}
	rest := path[idx+len("models/"):]
	// Model name ends at ":" or "/" or end of string.
	for i, c := range rest {
		if c == ':' || c == '/' {
			return rest[:i]
		}
	}
	return rest
}
