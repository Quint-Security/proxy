package llmparse

import (
	"bytes"
	"strings"
)

// Format IDs returned by detectFormat.
const (
	formatAnthropic        = "anthropic"
	formatOpenAI           = "openai"
	formatOpenAIResponses  = "openai-responses"
	formatGemini           = "google-gemini"
	formatBedrockConverse  = "aws-bedrock-converse"
	formatAzureOpenAI      = "azure-openai"
	formatGeneric          = "generic"
)

// Parse routes to the appropriate LLM API parser based on the request host, path,
// and body content. Detection priority: path → host → body sniff → generic fallback.
func Parse(host, path string, reqBody []byte, userAgent string) *ParseResult {
	if len(reqBody) == 0 {
		return nil
	}

	format := detectFormat(host, path, reqBody)

	switch format {
	case formatAnthropic:
		result, _ := ParseAnthropicRequest(reqBody, userAgent)
		if result != nil {
			result.Provider = formatAnthropic
		}
		return result
	case formatOpenAI:
		result, _ := ParseOpenAIRequest(reqBody, userAgent)
		if result != nil {
			result.Provider = formatOpenAI
		}
		return result
	case formatOpenAIResponses:
		result, _ := ParseOpenAIResponsesRequest(reqBody, userAgent)
		return result
	case formatGemini:
		result, _ := ParseGeminiRequest(reqBody, userAgent, path)
		return result
	case formatBedrockConverse:
		result, _ := ParseBedrockConverseRequest(reqBody, userAgent)
		return result
	case formatAzureOpenAI:
		result, _ := ParseOpenAIRequest(reqBody, userAgent)
		if result != nil {
			result.Provider = formatAzureOpenAI
		}
		return result
	case formatGeneric:
		result, _ := ParseGenericRequest(reqBody, userAgent)
		return result
	default:
		return nil
	}
}

// detectFormat determines the LLM API format based on host, path, and body content.
// Priority: path-based → host-based → body sniff → generic fallback.
func detectFormat(host, path string, body []byte) string {
	host = strings.ToLower(host)
	path = strings.ToLower(path)

	// 1. PATH-BASED (highest priority)
	if strings.Contains(path, "/v1/responses") {
		return formatOpenAIResponses
	}
	if strings.Contains(path, ":generatecontent") || strings.Contains(path, ":streamgeneratecontent") {
		return formatGemini
	}
	if strings.Contains(path, "/converse") && strings.Contains(host, "bedrock") {
		return formatBedrockConverse
	}

	// 2. HOST-BASED
	if strings.Contains(host, "anthropic.com") {
		return formatAnthropic
	}
	if strings.Contains(host, "bedrock") && strings.Contains(host, "amazonaws.com") {
		// Bedrock can use either Anthropic format (snake_case) or Converse format (camelCase).
		if bytes.Contains(body, []byte(`"toolUse"`)) {
			return formatBedrockConverse
		}
		return formatAnthropic
	}
	if strings.HasSuffix(host, ".openai.azure.com") {
		return formatAzureOpenAI
	}
	if strings.Contains(host, "openai.com") {
		return formatOpenAI
	}
	if strings.Contains(host, "googleapis.com") {
		return formatGemini
	}
	if strings.Contains(host, "mistral.ai") {
		return formatOpenAI
	}

	// 3. BODY SNIFF (unknown hosts)
	if bytes.Contains(body, []byte(`"contents"`)) {
		return formatGemini
	}
	if bytes.Contains(body, []byte(`"input"`)) && !bytes.Contains(body, []byte(`"messages"`)) {
		return formatOpenAIResponses
	}
	if bytes.Contains(body, []byte(`"toolUse"`)) {
		return formatBedrockConverse
	}

	// 4. GENERIC FALLBACK
	return formatGeneric
}
