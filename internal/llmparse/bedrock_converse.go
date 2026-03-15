package llmparse

import (
	"encoding/json"
	"fmt"
	"time"
)

// bedrockConverseRequest represents the AWS Bedrock Converse API request body.
// Key difference from Anthropic: camelCase field names (toolUse/toolResult/toolUseId).
type bedrockConverseRequest struct {
	ModelID  string              `json:"modelId,omitempty"`
	Messages []bedrockConverseMsg `json:"messages"`
}

// bedrockConverseMsg represents a message in the Bedrock Converse conversation.
type bedrockConverseMsg struct {
	Role    string                   `json:"role"`
	Content []bedrockConverseContent `json:"content"`
}

// bedrockConverseContent represents a content block in a Bedrock Converse message.
type bedrockConverseContent struct {
	Text       string                   `json:"text,omitempty"`
	ToolUse    *bedrockConverseToolUse   `json:"toolUse,omitempty"`
	ToolResult *bedrockConverseToolResult `json:"toolResult,omitempty"`
}

// bedrockConverseToolUse represents a tool use block in Bedrock Converse format.
type bedrockConverseToolUse struct {
	ToolUseID string                 `json:"toolUseId"`
	Name      string                 `json:"name"`
	Input     map[string]interface{} `json:"input,omitempty"`
}

// bedrockConverseToolResult represents a tool result block in Bedrock Converse format.
type bedrockConverseToolResult struct {
	ToolUseID string                      `json:"toolUseId"`
	Content   []bedrockConverseResultItem `json:"content,omitempty"`
}

// bedrockConverseResultItem represents an item inside a tool result content array.
type bedrockConverseResultItem struct {
	Text string `json:"text,omitempty"`
}

// ParseBedrockConverseRequest parses an AWS Bedrock Converse API request body
// and extracts the latest tool call pair (toolUse + toolResult).
func ParseBedrockConverseRequest(body []byte, userAgent string) (*ParseResult, error) {
	var req bedrockConverseRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal bedrock converse request: %w", err)
	}

	model := req.ModelID

	type toolCall struct {
		id    string
		name  string
		input string
	}

	var calls []toolCall
	results := make(map[string]string) // toolUseId → result text

	for _, msg := range req.Messages {
		for _, block := range msg.Content {
			if msg.Role == "assistant" && block.ToolUse != nil {
				inputJSON := "{}"
				if block.ToolUse.Input != nil {
					if b, err := json.Marshal(block.ToolUse.Input); err == nil {
						inputJSON = string(b)
					}
				}
				calls = append(calls, toolCall{
					id:    block.ToolUse.ToolUseID,
					name:  block.ToolUse.Name,
					input: inputJSON,
				})
			}
			if msg.Role == "user" && block.ToolResult != nil {
				var parts []string
				for _, item := range block.ToolResult.Content {
					if item.Text != "" {
						parts = append(parts, item.Text)
					}
				}
				resultText := ""
				if len(parts) > 0 {
					resultText = parts[0]
					for i := 1; i < len(parts); i++ {
						resultText += "\n" + parts[i]
					}
				}
				results[block.ToolResult.ToolUseID] = resultText
			}
		}
	}

	if len(calls) == 0 {
		return &ParseResult{
			Model:    model,
			Agent:    userAgent,
			Provider: "aws-bedrock-converse",
		}, nil
	}

	// Return only the last toolUse + its toolResult.
	lastCall := calls[len(calls)-1]
	now := time.Now().UTC()

	event := AgentEvent{
		EventID:       lastCall.id,
		Timestamp:     now,
		Provider:      "aws-bedrock-converse",
		Model:         model,
		AgentIdentity: userAgent,
		EventType:     "tool_use",
		ToolName:      lastCall.name,
		ToolArgs:      lastCall.input,
	}

	if result, ok := results[lastCall.id]; ok {
		event.ToolResult = truncate(result, maxToolResultBytes)
	}

	return &ParseResult{
		Events:   []AgentEvent{event},
		Model:    model,
		Agent:    userAgent,
		Provider: "aws-bedrock-converse",
	}, nil
}
