package llmparse

import (
	"testing"
)

func TestParseGenericRequest_ToolCallsPattern(t *testing.T) {
	body := []byte(`{
		"model": "some-model",
		"messages": [
			{"role": "assistant", "tool_calls": [
				{"id": "tc_01", "function": {"name": "shell", "arguments": "{\"cmd\":\"ls\"}"}}
			]}
		]
	}`)

	result, err := ParseGenericRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || len(result.Events) == 0 {
		t.Fatal("expected events for tool_calls pattern")
	}
	if result.Events[0].ToolName != "shell" {
		t.Errorf("expected shell, got %s", result.Events[0].ToolName)
	}
	if result.Provider != "generic" {
		t.Errorf("expected provider generic, got %s", result.Provider)
	}
	if result.Model != "some-model" {
		t.Errorf("expected some-model, got %s", result.Model)
	}
}

func TestParseGenericRequest_FunctionCallPattern(t *testing.T) {
	body := []byte(`{
		"model": "test",
		"function_call": {"name": "read_file", "arguments": "{\"path\":\"/tmp\"}"}
	}`)

	result, err := ParseGenericRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || len(result.Events) == 0 {
		t.Fatal("expected events for function_call pattern")
	}
	if result.Events[0].ToolName != "read_file" {
		t.Errorf("expected read_file, got %s", result.Events[0].ToolName)
	}
}

func TestParseGenericRequest_CamelCaseFunctionCallPattern(t *testing.T) {
	body := []byte(`{
		"functionCall": {"name": "bash", "args": {"command": "pwd"}}
	}`)

	result, err := ParseGenericRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || len(result.Events) == 0 {
		t.Fatal("expected events for functionCall pattern")
	}
	if result.Events[0].ToolName != "bash" {
		t.Errorf("expected bash, got %s", result.Events[0].ToolName)
	}
}

func TestParseGenericRequest_NoToolPatterns(t *testing.T) {
	body := []byte(`{
		"model": "test",
		"messages": [
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "hi there"}
		]
	}`)

	result, err := ParseGenericRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil result for no tool patterns, got %+v", result)
	}
}

func TestParseGenericRequest_NonJSON(t *testing.T) {
	body := []byte(`not json at all`)

	result, err := ParseGenericRequest(body, "agent")
	if err == nil {
		t.Fatal("expected error for non-JSON")
	}
	if result != nil {
		t.Error("expected nil result")
	}
}

func TestParseGenericRequest_EmptyBody(t *testing.T) {
	result, err := ParseGenericRequest(nil, "agent")
	if err == nil {
		t.Fatal("expected error for nil body")
	}
	if result != nil {
		t.Error("expected nil result")
	}
}

func TestParseGenericRequest_ToolUsePattern(t *testing.T) {
	body := []byte(`{
		"tool_use": {"name": "edit", "input": {"file": "/tmp/x", "content": "new"}}
	}`)

	result, err := ParseGenericRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || len(result.Events) == 0 {
		t.Fatal("expected events for tool_use pattern")
	}
	if result.Events[0].ToolName != "edit" {
		t.Errorf("expected edit, got %s", result.Events[0].ToolName)
	}
}
