package llmparse

import (
	"strings"
	"testing"
)

func TestParseOpenAIRequest_ToolCall(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "do something"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_01", "type": "function", "function": {"name": "bash", "arguments": "{\"command\":\"ls\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_01", "content": "file1.txt"}
		]
	}`)

	result, err := ParseOpenAIRequest(body, "openai-agent/1.0")
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
	if result.Events[0].ToolResult != "file1.txt" {
		t.Errorf("expected tool result, got %s", result.Events[0].ToolResult)
	}
	if result.Model != "gpt-4" {
		t.Errorf("expected gpt-4, got %s", result.Model)
	}
	if result.Events[0].Provider != "openai" {
		t.Errorf("expected openai, got %s", result.Events[0].Provider)
	}
}

func TestParseOpenAIRequest_MultipleToolCalls(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4-turbo",
		"messages": [
			{"role": "user", "content": "do multiple things"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_01", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"/tmp/a\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_01", "content": "contents of a"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_02", "type": "function", "function": {"name": "write_file", "arguments": "{\"path\":\"/tmp/b\",\"content\":\"hello\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_02", "content": "written"}
		]
	}`)

	result, err := ParseOpenAIRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	// Should return only the last tool call.
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event (latest), got %d", len(result.Events))
	}
	if result.Events[0].ToolName != "write_file" {
		t.Errorf("expected write_file, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].EventID != "call_02" {
		t.Errorf("expected call_02, got %s", result.Events[0].EventID)
	}
}

func TestParseOpenAIRequest_NoToolCalls(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "Hi there!"}
		]
	}`)

	result, err := ParseOpenAIRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
}

func TestParseOpenAIRequest_MalformedJSON(t *testing.T) {
	body := []byte(`{broken json`)

	result, err := ParseOpenAIRequest(body, "agent")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if result != nil {
		t.Error("expected nil result")
	}
}

func TestParseOpenAIRequest_EmptyMessages(t *testing.T) {
	body := []byte(`{"model": "gpt-4", "messages": []}`)

	result, err := ParseOpenAIRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
}

func TestParseOpenAIRequest_ToolCallWithoutResult(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "run ls"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_pending", "type": "function", "function": {"name": "bash", "arguments": "{\"command\":\"ls\"}"}}
			]}
		]
	}`)

	result, err := ParseOpenAIRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolResult != "" {
		t.Errorf("expected empty result, got %q", result.Events[0].ToolResult)
	}
}

func TestParseOpenAIRequest_LargeToolResult(t *testing.T) {
	largeResult := strings.Repeat("y", 20*1024)

	body := []byte(`{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "cat big file"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_big", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"/big\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_big", "content": "` + largeResult + `"}
		]
	}`)

	result, err := ParseOpenAIRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if len(result.Events[0].ToolResult) > 10*1024 {
		t.Errorf("expected truncation to 10KB, got %d bytes", len(result.Events[0].ToolResult))
	}
	if !strings.HasSuffix(result.Events[0].ToolResult, "...[truncated]") {
		t.Error("expected truncation marker")
	}
}

func TestParseOpenAIRequest_NullContent(t *testing.T) {
	// Assistant messages with tool_calls often have null content.
	body := []byte(`{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "do it"},
			{"role": "assistant", "content": null, "tool_calls": [
				{"id": "call_nc", "type": "function", "function": {"name": "exec", "arguments": "{}"}}
			]},
			{"role": "tool", "tool_call_id": "call_nc", "content": "done"}
		]
	}`)

	result, err := ParseOpenAIRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "exec" {
		t.Errorf("expected exec, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolResult != "done" {
		t.Errorf("expected done, got %s", result.Events[0].ToolResult)
	}
}

func TestParse_OpenAIRouter(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "run it"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_r1", "type": "function", "function": {"name": "shell", "arguments": "{}"}}
			]}
		]
	}`)

	result := Parse("api.openai.com", "", body, "agent")
	if result == nil || len(result.Events) == 0 {
		t.Fatal("expected events for openai.com")
	}
	if result.Events[0].ToolName != "shell" {
		t.Errorf("expected shell, got %s", result.Events[0].ToolName)
	}
}
