package llmparse

import (
	"testing"
)

func TestParseBedrockConverseRequest_SingleToolUse(t *testing.T) {
	body := []byte(`{
		"modelId": "anthropic.claude-3-5-sonnet",
		"messages": [
			{"role": "assistant", "content": [
				{"toolUse": {"toolUseId": "tu_01", "name": "Bash", "input": {"command": "ls -la"}}}
			]},
			{"role": "user", "content": [
				{"toolResult": {"toolUseId": "tu_01", "content": [{"text": "file.txt"}]}}
			]}
		]
	}`)

	result, err := ParseBedrockConverseRequest(body, "bedrock-agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "Bash" {
		t.Errorf("expected Bash, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolResult != "file.txt" {
		t.Errorf("expected file.txt, got %s", result.Events[0].ToolResult)
	}
	if result.Events[0].EventID != "tu_01" {
		t.Errorf("expected tu_01, got %s", result.Events[0].EventID)
	}
	if result.Provider != "aws-bedrock-converse" {
		t.Errorf("expected aws-bedrock-converse, got %s", result.Provider)
	}
	if result.Model != "anthropic.claude-3-5-sonnet" {
		t.Errorf("expected model, got %s", result.Model)
	}
}

func TestParseBedrockConverseRequest_MultipleToolUse(t *testing.T) {
	body := []byte(`{
		"modelId": "anthropic.claude-3-5-sonnet",
		"messages": [
			{"role": "assistant", "content": [
				{"toolUse": {"toolUseId": "tu_01", "name": "Read", "input": {"path": "/etc/hosts"}}}
			]},
			{"role": "user", "content": [
				{"toolResult": {"toolUseId": "tu_01", "content": [{"text": "127.0.0.1 localhost"}]}}
			]},
			{"role": "assistant", "content": [
				{"toolUse": {"toolUseId": "tu_02", "name": "Write", "input": {"path": "/tmp/out.txt"}}}
			]},
			{"role": "user", "content": [
				{"toolResult": {"toolUseId": "tu_02", "content": [{"text": "written"}]}}
			]}
		]
	}`)

	result, err := ParseBedrockConverseRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event (latest), got %d", len(result.Events))
	}
	if result.Events[0].ToolName != "Write" {
		t.Errorf("expected Write (latest), got %s", result.Events[0].ToolName)
	}
	if result.Events[0].EventID != "tu_02" {
		t.Errorf("expected tu_02, got %s", result.Events[0].EventID)
	}
	if result.Events[0].ToolResult != "written" {
		t.Errorf("expected 'written', got %s", result.Events[0].ToolResult)
	}
}

func TestParseBedrockConverseRequest_MalformedJSON(t *testing.T) {
	body := []byte(`{broken json`)

	result, err := ParseBedrockConverseRequest(body, "agent")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if result != nil {
		t.Error("expected nil result")
	}
}

func TestParseBedrockConverseRequest_EmptyMessages(t *testing.T) {
	body := []byte(`{"modelId": "test", "messages": []}`)

	result, err := ParseBedrockConverseRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
}

func TestParseBedrockConverseRequest_ToolUseWithoutResult(t *testing.T) {
	body := []byte(`{
		"modelId": "anthropic.claude-3-5-sonnet",
		"messages": [
			{"role": "assistant", "content": [
				{"toolUse": {"toolUseId": "tu_pending", "name": "Exec", "input": {"cmd": "whoami"}}}
			]}
		]
	}`)

	result, err := ParseBedrockConverseRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolResult != "" {
		t.Errorf("expected empty result for pending, got %q", result.Events[0].ToolResult)
	}
}

func TestParseBedrockConverseRequest_MultiPartResult(t *testing.T) {
	body := []byte(`{
		"modelId": "test",
		"messages": [
			{"role": "assistant", "content": [
				{"toolUse": {"toolUseId": "tu_mp", "name": "Read", "input": {"path": "/tmp"}}}
			]},
			{"role": "user", "content": [
				{"toolResult": {"toolUseId": "tu_mp", "content": [
					{"text": "line one"},
					{"text": "line two"}
				]}}
			]}
		]
	}`)

	result, err := ParseBedrockConverseRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolResult != "line one\nline two" {
		t.Errorf("expected joined result, got %q", result.Events[0].ToolResult)
	}
}
