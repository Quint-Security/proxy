package llmparse

import (
	"encoding/json"
	"fmt"
	"time"
)

const maxToolResultBytes = 10 * 1024 // 10KB

// anthropicRequest represents the top-level Anthropic Messages API request body.
// Also covers Bedrock format which uses the same messages structure.
type anthropicRequest struct {
	Model            string            `json:"model"`
	AnthropicVersion string            `json:"anthropic_version"`
	Messages         []anthropicMsg    `json:"messages"`
}

// anthropicMsg represents a single message in the Anthropic conversation.
type anthropicMsg struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string or []contentBlock
}

// contentBlock represents a typed block inside a message content array.
type contentBlock struct {
	Type      string          `json:"type"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Text      string          `json:"text,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"` // tool_result content: string or array
}

// toolUseEvent is an intermediate struct for pairing tool_use with tool_result.
type toolUseEvent struct {
	id    string
	name  string
	input string // JSON string of the input
}

// ParseAnthropicRequest parses an Anthropic Messages API request body and extracts
// the latest tool call pair (tool_use + tool_result). It returns only new events,
// meaning the last tool_use/tool_result pair found in the conversation.
func ParseAnthropicRequest(body []byte, userAgent string) (*ParseResult, error) {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal anthropic request: %w", err)
	}

	model := req.Model

	// Collect all tool_use blocks and tool_result blocks.
	var toolUses []toolUseEvent
	toolResults := make(map[string]string) // tool_use_id -> result content

	for _, msg := range req.Messages {
		blocks := parseContentBlocks(msg.Content)
		if blocks == nil {
			continue
		}

		switch msg.Role {
		case "assistant":
			for _, b := range blocks {
				if b.Type == "tool_use" {
					inputStr := string(b.Input)
					if inputStr == "" {
						inputStr = "{}"
					}
					toolUses = append(toolUses, toolUseEvent{
						id:    b.ID,
						name:  b.Name,
						input: inputStr,
					})
				}
			}
		case "user":
			for _, b := range blocks {
				if b.Type == "tool_result" {
					result := extractToolResultContent(b.Content)
					toolResults[b.ToolUseID] = result
				}
			}
		}
	}

	if len(toolUses) == 0 {
		return &ParseResult{
			Model: model,
			Agent: userAgent,
		}, nil
	}

	// Return only the last tool_use/tool_result pair as the "new" event.
	lastUse := toolUses[len(toolUses)-1]
	now := time.Now().UTC()

	event := AgentEvent{
		EventID:       lastUse.id,
		Timestamp:     now,
		Provider:      "anthropic",
		Model:         model,
		AgentIdentity: userAgent,
		EventType:     "tool_use",
		ToolName:      lastUse.name,
		ToolArgs:      lastUse.input,
	}

	if result, ok := toolResults[lastUse.id]; ok {
		event.ToolResult = truncate(result, maxToolResultBytes)
	}

	return &ParseResult{
		Events: []AgentEvent{event},
		Model:  model,
		Agent:  userAgent,
	}, nil
}

// parseContentBlocks handles the content field which can be either a string
// or an array of content blocks.
func parseContentBlocks(raw json.RawMessage) []contentBlock {
	if len(raw) == 0 {
		return nil
	}

	// Try array first (most common for tool_use/tool_result).
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		return blocks
	}

	// Try string (simple text message).
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return []contentBlock{{Type: "text", Text: text}}
	}

	return nil
}

// extractToolResultContent extracts the text content from a tool_result content field.
// The content can be a string, an array of content blocks, or nil.
func extractToolResultContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}

	// Try array of blocks.
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var parts []string
		for _, b := range blocks {
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		if len(parts) > 0 {
			result := parts[0]
			for i := 1; i < len(parts); i++ {
				result += "\n" + parts[i]
			}
			return result
		}
	}

	return ""
}

// ParseAnthropicStreamResponse parses SSE stream data from an Anthropic streaming
// response. This is lower priority since the request body already captures all
// historical tool calls. It handles content_block_start, content_block_delta,
// and content_block_stop events.
func ParseAnthropicStreamResponse(sseData []byte) (*ParseResult, error) {
	// SSE data comes as lines like:
	// event: content_block_start
	// data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"Bash","input":{}}}
	//
	// event: content_block_delta
	// data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"..."}}
	//
	// event: content_block_stop
	// data: {"type":"content_block_stop","index":0}

	type sseEvent struct {
		Type         string          `json:"type"`
		Index        int             `json:"index"`
		ContentBlock json.RawMessage `json:"content_block,omitempty"`
		Delta        json.RawMessage `json:"delta,omitempty"`
	}

	type blockStart struct {
		Type  string `json:"type"`
		ID    string `json:"id"`
		Name  string `json:"name"`
	}

	type deltaPayload struct {
		Type        string `json:"type"`
		PartialJSON string `json:"partial_json"`
	}

	// Track in-progress tool_use blocks by index.
	type pendingBlock struct {
		id          string
		name        string
		inputChunks []string
	}

	pending := make(map[int]*pendingBlock)
	var events []AgentEvent

	// Parse each line looking for "data: " prefixed JSON.
	lines := splitLines(sseData)
	for _, line := range lines {
		if len(line) < 6 {
			continue
		}
		prefix := string(line[:6])
		if prefix != "data: " {
			continue
		}
		payload := line[6:]

		var evt sseEvent
		if err := json.Unmarshal(payload, &evt); err != nil {
			continue
		}

		switch evt.Type {
		case "content_block_start":
			var bs blockStart
			if err := json.Unmarshal(evt.ContentBlock, &bs); err != nil {
				continue
			}
			if bs.Type == "tool_use" {
				pending[evt.Index] = &pendingBlock{
					id:   bs.ID,
					name: bs.Name,
				}
			}

		case "content_block_delta":
			pb, ok := pending[evt.Index]
			if !ok {
				continue
			}
			var dp deltaPayload
			if err := json.Unmarshal(evt.Delta, &dp); err != nil {
				continue
			}
			if dp.Type == "input_json_delta" {
				pb.inputChunks = append(pb.inputChunks, dp.PartialJSON)
			}

		case "content_block_stop":
			pb, ok := pending[evt.Index]
			if !ok {
				continue
			}
			inputJSON := ""
			for _, chunk := range pb.inputChunks {
				inputJSON += chunk
			}
			if inputJSON == "" {
				inputJSON = "{}"
			}
			events = append(events, AgentEvent{
				EventID:   pb.id,
				Timestamp: time.Now().UTC(),
				Provider:  "anthropic",
				EventType: "tool_use",
				ToolName:  pb.name,
				ToolArgs:  inputJSON,
			})
			delete(pending, evt.Index)
		}
	}

	if len(events) == 0 {
		return nil, nil
	}

	return &ParseResult{Events: events}, nil
}

// splitLines splits data into lines by newline characters.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			line := data[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// truncate ensures s is no longer than maxBytes. If truncated, it appends
// a truncation marker.
func truncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes-len("...[truncated]")] + "...[truncated]"
}
