package agentdetect

import "encoding/json"

// ExtractSystemPrompt pulls the system prompt from an API request body.
// Handles Anthropic format (top-level "system" field), OpenAI format
// (first message with role "system" or "developer"), and Google format.
func ExtractSystemPrompt(bodyPreview string) string {
	if bodyPreview == "" {
		return ""
	}

	// Try Anthropic format: { "system": "..." } or { "system": [{"text": "..."}] }
	var anthropic struct {
		System json.RawMessage `json:"system"`
	}
	if err := json.Unmarshal([]byte(bodyPreview), &anthropic); err == nil && len(anthropic.System) > 0 {
		// Try string first
		var s string
		if json.Unmarshal(anthropic.System, &s) == nil && s != "" {
			return s
		}
		// Try array of content blocks
		var blocks []struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(anthropic.System, &blocks) == nil && len(blocks) > 0 {
			var combined string
			for _, b := range blocks {
				if combined != "" {
					combined += "\n"
				}
				combined += b.Text
			}
			return combined
		}
	}

	// Try OpenAI format: { "messages": [{"role": "system"|"developer", "content": "..."}] }
	var openai struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(bodyPreview), &openai); err == nil && len(openai.Messages) > 0 {
		for _, msg := range openai.Messages {
			if msg.Role == "system" || msg.Role == "developer" {
				var s string
				if json.Unmarshal(msg.Content, &s) == nil && s != "" {
					return s
				}
				// Content could be array of parts
				var parts []struct {
					Text string `json:"text"`
				}
				if json.Unmarshal(msg.Content, &parts) == nil && len(parts) > 0 {
					return parts[0].Text
				}
			}
		}
	}

	// Try Google/Gemini format: { "system_instruction": {"parts": [{"text": "..."}]} }
	var google struct {
		SystemInstruction struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"system_instruction"`
	}
	if err := json.Unmarshal([]byte(bodyPreview), &google); err == nil && len(google.SystemInstruction.Parts) > 0 {
		return google.SystemInstruction.Parts[0].Text
	}

	return ""
}
