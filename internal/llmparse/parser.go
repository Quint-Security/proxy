package llmparse

import "strings"

// Parse routes to the appropriate LLM API parser based on the request host.
func Parse(host string, reqBody []byte, userAgent string) *ParseResult {
	if len(reqBody) == 0 {
		return nil
	}

	host = strings.ToLower(host)

	switch {
	case strings.Contains(host, "anthropic.com"):
		result, _ := ParseAnthropicRequest(reqBody, userAgent)
		return result
	case strings.Contains(host, "bedrock") && strings.Contains(host, "amazonaws.com"):
		result, _ := ParseAnthropicRequest(reqBody, userAgent) // Bedrock uses Anthropic format
		return result
	case strings.Contains(host, "openai.com"):
		result, _ := ParseOpenAIRequest(reqBody, userAgent)
		return result
	default:
		return nil
	}
}
