package llmparse

import (
	"testing"
)

func TestDetectFormat_PathBased(t *testing.T) {
	tests := []struct {
		name string
		host string
		path string
		body []byte
		want string
	}{
		{
			name: "OpenAI Responses path",
			host: "api.openai.com",
			path: "/v1/responses",
			body: []byte(`{"input":"test"}`),
			want: formatOpenAIResponses,
		},
		{
			name: "Gemini generateContent",
			host: "generativelanguage.googleapis.com",
			path: "/v1beta/models/gemini-2.0-flash:generateContent",
			body: []byte(`{"contents":[]}`),
			want: formatGemini,
		},
		{
			name: "Gemini streamGenerateContent",
			host: "generativelanguage.googleapis.com",
			path: "/v1beta/models/gemini-pro:streamGenerateContent",
			body: []byte(`{"contents":[]}`),
			want: formatGemini,
		},
		{
			name: "Bedrock Converse path",
			host: "bedrock-runtime.us-east-1.amazonaws.com",
			path: "/model/anthropic.claude-3/converse",
			body: []byte(`{"messages":[]}`),
			want: formatBedrockConverse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFormat(tt.host, tt.path, tt.body)
			if got != tt.want {
				t.Errorf("detectFormat(%q, %q) = %q, want %q", tt.host, tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectFormat_HostBased(t *testing.T) {
	body := []byte(`{"messages":[]}`)

	tests := []struct {
		name string
		host string
		path string
		want string
	}{
		{"Anthropic", "api.anthropic.com", "/v1/messages", formatAnthropic},
		{"OpenAI", "api.openai.com", "/v1/chat/completions", formatOpenAI},
		{"Google APIs", "generativelanguage.googleapis.com", "/v1/models/gemini:gen", formatGemini},
		{"Azure OpenAI", "mydeployment.openai.azure.com", "/openai/deployments/gpt-4/chat/completions", formatAzureOpenAI},
		{"Bedrock snake_case", "bedrock-runtime.us-east-1.amazonaws.com", "/model/invoke", formatAnthropic},
		{"Mistral", "api.mistral.ai", "/v1/chat/completions", formatOpenAI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFormat(tt.host, tt.path, body)
			if got != tt.want {
				t.Errorf("detectFormat(%q, %q) = %q, want %q", tt.host, tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectFormat_BedrockConverseByBody(t *testing.T) {
	// Bedrock host with camelCase toolUse → Converse format.
	body := []byte(`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"tu1","name":"Bash"}}]}]}`)
	got := detectFormat("bedrock-runtime.us-east-1.amazonaws.com", "/model/invoke", body)
	if got != formatBedrockConverse {
		t.Errorf("expected %q for bedrock+toolUse body, got %q", formatBedrockConverse, got)
	}
}

func TestDetectFormat_BodySniff(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "contents → Gemini",
			body: []byte(`{"contents": [{"role":"user","parts":[]}]}`),
			want: formatGemini,
		},
		{
			name: "input without messages → OpenAI Responses",
			body: []byte(`{"input": [{"type":"function_call"}]}`),
			want: formatOpenAIResponses,
		},
		{
			name: "toolUse → Bedrock Converse",
			body: []byte(`{"messages":[{"content":[{"toolUse":{"name":"test"}}]}]}`),
			// "messages" is present but toolUse triggers body sniff after host check fails
			want: formatBedrockConverse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use unknown host to trigger body sniff.
			got := detectFormat("unknown.example.com", "/api/chat", tt.body)
			if got != tt.want {
				t.Errorf("detectFormat(unknown, body) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectFormat_GenericFallback(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	got := detectFormat("unknown.example.com", "/api/chat", body)
	if got != formatGeneric {
		t.Errorf("expected generic fallback, got %q", got)
	}
}

func TestDetectFormat_PathBeatsHost(t *testing.T) {
	// /v1/responses path should override openai.com host (which would default to Chat Completions).
	body := []byte(`{"input":"test"}`)
	got := detectFormat("api.openai.com", "/v1/responses", body)
	if got != formatOpenAIResponses {
		t.Errorf("path should beat host: expected %q, got %q", formatOpenAIResponses, got)
	}
}

func TestDetectFormat_PathBeatsBody(t *testing.T) {
	// :generateContent path should override body content.
	body := []byte(`{"messages":[]}`)
	got := detectFormat("unknown.example.com", "/v1/models/gemini:generateContent", body)
	if got != formatGemini {
		t.Errorf("path should beat body: expected %q, got %q", formatGemini, got)
	}
}

func TestDetectFormat_HostBeatsBody(t *testing.T) {
	// Anthropic host should override "contents" in body.
	body := []byte(`{"contents":[{"role":"user"}], "messages":[]}`)
	got := detectFormat("api.anthropic.com", "/v1/messages", body)
	if got != formatAnthropic {
		t.Errorf("host should beat body: expected %q, got %q", formatAnthropic, got)
	}
}

func TestDetectFormat_BodySniffInputWithMessages(t *testing.T) {
	// "input" WITH "messages" should NOT trigger OpenAI Responses sniff.
	body := []byte(`{"input":"something","messages":[{"role":"user"}]}`)
	got := detectFormat("unknown.example.com", "/api/chat", body)
	// Should fall through to generic since "messages" is present.
	if got == formatOpenAIResponses {
		t.Error("input with messages should not trigger openai-responses sniff")
	}
}
