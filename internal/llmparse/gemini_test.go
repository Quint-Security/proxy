package llmparse

import (
	"testing"
)

func TestParseGeminiRequest_SingleFunctionCall(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role": "user", "parts": [{"text": "list files"}]},
			{"role": "model", "parts": [{"functionCall": {"name": "bash", "args": {"command": "ls"}}}]},
			{"role": "user", "parts": [{"functionResponse": {"name": "bash", "response": {"result": "file.txt"}}}]}
		]
	}`)

	result, err := ParseGeminiRequest(body, "gemini-agent/1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "bash" {
		t.Errorf("expected bash, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolArgs != `{"command":"ls"}` {
		t.Errorf("expected args, got %s", result.Events[0].ToolArgs)
	}
	if result.Events[0].ToolResult == "" {
		t.Error("expected non-empty tool result")
	}
	if result.Provider != "google-gemini" {
		t.Errorf("expected provider google-gemini, got %s", result.Provider)
	}
}

func TestParseGeminiRequest_MultipleFunctionCalls(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role": "user", "parts": [{"text": "do stuff"}]},
			{"role": "model", "parts": [{"functionCall": {"name": "read", "args": {"path": "/a"}}}]},
			{"role": "user", "parts": [{"functionResponse": {"name": "read", "response": {"result": "a contents"}}}]},
			{"role": "model", "parts": [{"functionCall": {"name": "write", "args": {"path": "/b"}}}]},
			{"role": "user", "parts": [{"functionResponse": {"name": "write", "response": {"result": "ok"}}}]}
		]
	}`)

	result, err := ParseGeminiRequest(body, "agent", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event (latest), got %d", len(result.Events))
	}
	if result.Events[0].ToolName != "write" {
		t.Errorf("expected write (latest), got %s", result.Events[0].ToolName)
	}
}

func TestParseGeminiRequest_TextOnly(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role": "user", "parts": [{"text": "hello"}]},
			{"role": "model", "parts": [{"text": "Hi there!"}]}
		]
	}`)

	result, err := ParseGeminiRequest(body, "agent", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for text-only, got %d", len(result.Events))
	}
}

func TestParseGeminiRequest_PendingFunctionCall(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role": "user", "parts": [{"text": "do it"}]},
			{"role": "model", "parts": [{"functionCall": {"name": "exec", "args": {"cmd": "whoami"}}}]}
		]
	}`)

	result, err := ParseGeminiRequest(body, "agent", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "exec" {
		t.Errorf("expected exec, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolResult != "" {
		t.Errorf("expected empty result for pending call, got %q", result.Events[0].ToolResult)
	}
}

func TestParseGeminiRequest_ModelFromPath(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role": "user", "parts": [{"text": "hi"}]},
			{"role": "model", "parts": [{"functionCall": {"name": "test", "args": {}}}]}
		]
	}`)

	result, err := ParseGeminiRequest(body, "agent", "/v1beta/models/gemini-2.0-flash:generateContent")
	if err != nil {
		t.Fatal(err)
	}
	if result.Model != "gemini-2.0-flash" {
		t.Errorf("expected model gemini-2.0-flash from path, got %s", result.Model)
	}
}

func TestParseGeminiRequest_ModelFromBody(t *testing.T) {
	body := []byte(`{
		"model": "gemini-pro",
		"contents": [
			{"role": "user", "parts": [{"text": "hi"}]},
			{"role": "model", "parts": [{"functionCall": {"name": "test", "args": {}}}]}
		]
	}`)

	result, err := ParseGeminiRequest(body, "agent", "/v1beta/models/gemini-2.0-flash:generateContent")
	if err != nil {
		t.Fatal(err)
	}
	// Body model takes precedence.
	if result.Model != "gemini-pro" {
		t.Errorf("expected model gemini-pro from body, got %s", result.Model)
	}
}

func TestParseGeminiRequest_MalformedJSON(t *testing.T) {
	body := []byte(`{not valid`)

	result, err := ParseGeminiRequest(body, "agent", "")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if result != nil {
		t.Error("expected nil result")
	}
}

func TestExtractModelFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/v1beta/models/gemini-2.0-flash:generateContent", "gemini-2.0-flash"},
		{"/v1/models/gemini-pro:streamGenerateContent", "gemini-pro"},
		{"/v1/models/gemini-1.5-pro-latest", "gemini-1.5-pro-latest"},
		{"/v1/chat/completions", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractModelFromPath(tt.path)
			if got != tt.want {
				t.Errorf("extractModelFromPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
