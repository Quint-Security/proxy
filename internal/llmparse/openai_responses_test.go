package llmparse

import (
	"testing"
)

func TestParseOpenAIResponsesRequest_SingleFunctionCall(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4.1",
		"input": [
			{"type": "function_call", "id": "fc_01", "name": "shell", "arguments": "{\"command\":\"ls\"}"},
			{"type": "function_call_output", "call_id": "fc_01", "output": "file1.txt\nfile2.txt"}
		]
	}`)

	result, err := ParseOpenAIResponsesRequest(body, "openai-agent/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "shell" {
		t.Errorf("expected shell, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolArgs != `{"command":"ls"}` {
		t.Errorf("expected args, got %s", result.Events[0].ToolArgs)
	}
	if result.Events[0].ToolResult != "file1.txt\nfile2.txt" {
		t.Errorf("expected tool result, got %s", result.Events[0].ToolResult)
	}
	if result.Provider != "openai-responses" {
		t.Errorf("expected provider openai-responses, got %s", result.Provider)
	}
	if result.Model != "gpt-4.1" {
		t.Errorf("expected model gpt-4.1, got %s", result.Model)
	}
}

func TestParseOpenAIResponsesRequest_MultipleFunctionCalls(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4.1",
		"input": [
			{"type": "function_call", "id": "fc_01", "name": "read_file", "arguments": "{\"path\":\"/tmp/a\"}"},
			{"type": "function_call_output", "call_id": "fc_01", "output": "contents of a"},
			{"type": "function_call", "id": "fc_02", "name": "write_file", "arguments": "{\"path\":\"/tmp/b\"}"},
			{"type": "function_call_output", "call_id": "fc_02", "output": "written"}
		]
	}`)

	result, err := ParseOpenAIResponsesRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	// Should return the last function_call.
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event (latest), got %d", len(result.Events))
	}
	if result.Events[0].ToolName != "write_file" {
		t.Errorf("expected write_file, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].EventID != "fc_02" {
		t.Errorf("expected fc_02, got %s", result.Events[0].EventID)
	}
	if result.Events[0].ToolResult != "written" {
		t.Errorf("expected 'written', got %s", result.Events[0].ToolResult)
	}
}

func TestParseOpenAIResponsesRequest_PendingFunctionCall(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4.1",
		"input": [
			{"type": "function_call", "id": "fc_pending", "name": "bash", "arguments": "{\"command\":\"rm -rf /\"}"}
		]
	}`)

	result, err := ParseOpenAIResponsesRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "bash" {
		t.Errorf("expected bash, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolResult != "" {
		t.Errorf("expected empty result for pending call, got %q", result.Events[0].ToolResult)
	}
}

func TestParseOpenAIResponsesRequest_StringInput(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4.1",
		"input": "Tell me a joke"
	}`)

	result, err := ParseOpenAIResponsesRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	// String input, no tool calls → empty events.
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for string input, got %d", len(result.Events))
	}
}

func TestParseOpenAIResponsesRequest_MalformedJSON(t *testing.T) {
	body := []byte(`{not valid json`)

	result, err := ParseOpenAIResponsesRequest(body, "agent")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if result != nil {
		t.Error("expected nil result")
	}
}

func TestParseOpenAIResponsesRequest_EmptyBody(t *testing.T) {
	result, err := ParseOpenAIResponsesRequest(nil, "agent")
	if err == nil {
		t.Fatal("expected error for nil body")
	}
	if result != nil {
		t.Error("expected nil result")
	}
}

func TestParseOpenAIResponsesRequest_OutputField(t *testing.T) {
	// Continuation requests may have output items.
	body := []byte(`{
		"model": "gpt-4.1",
		"input": "do something",
		"output": [
			{"type": "function_call", "id": "fc_out", "name": "exec", "arguments": "{\"cmd\":\"whoami\"}"},
			{"type": "function_call_output", "call_id": "fc_out", "output": "root"}
		]
	}`)

	result, err := ParseOpenAIResponsesRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events from output field")
	}
	if result.Events[0].ToolName != "exec" {
		t.Errorf("expected exec, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolResult != "root" {
		t.Errorf("expected root, got %s", result.Events[0].ToolResult)
	}
}
