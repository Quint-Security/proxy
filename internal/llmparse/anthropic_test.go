package llmparse

import (
	"strings"
	"testing"
)

func TestParseAnthropicRequest_ToolUse(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": "list files"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": {"command": "ls -la"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_01", "content": "file1.txt\nfile2.txt"}
			]}
		]
	}`)

	result, err := ParseAnthropicRequest(body, "claude-code/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "Bash" {
		t.Errorf("expected Bash, got %s", result.Events[0].ToolName)
	}
	if result.Model != "claude-sonnet-4-20250514" {
		t.Errorf("expected model, got %s", result.Model)
	}
	if result.Agent != "claude-code/1.0" {
		t.Errorf("expected agent, got %s", result.Agent)
	}
	if result.Events[0].Provider != "anthropic" {
		t.Errorf("expected provider anthropic, got %s", result.Events[0].Provider)
	}
	if result.Events[0].ToolResult != "file1.txt\nfile2.txt" {
		t.Errorf("expected tool result, got %s", result.Events[0].ToolResult)
	}
}

func TestParseAnthropicRequest_MultipleToolCalls(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": "do stuff"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_01", "name": "Read", "input": {"path": "/etc/hosts"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_01", "content": "127.0.0.1 localhost"}
			]},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_02", "name": "Write", "input": {"path": "/tmp/out.txt", "content": "hello"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_02", "content": "ok"}
			]}
		]
	}`)

	result, err := ParseAnthropicRequest(body, "claude-code/1.0")
	if err != nil {
		t.Fatal(err)
	}
	// Should return only the LAST tool call pair.
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event (latest), got %d", len(result.Events))
	}
	if result.Events[0].ToolName != "Write" {
		t.Errorf("expected Write (latest tool call), got %s", result.Events[0].ToolName)
	}
	if result.Events[0].EventID != "toolu_02" {
		t.Errorf("expected toolu_02, got %s", result.Events[0].EventID)
	}
	if result.Events[0].ToolResult != "ok" {
		t.Errorf("expected tool result 'ok', got %s", result.Events[0].ToolResult)
	}
}

func TestParseAnthropicRequest_StringContent(t *testing.T) {
	body := []byte(`{
		"model": "claude-haiku-3",
		"messages": [
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "Hi there! How can I help?"}
		]
	}`)

	result, err := ParseAnthropicRequest(body, "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	// No tool calls, should return empty events.
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for text-only conversation, got %d", len(result.Events))
	}
	if result.Model != "claude-haiku-3" {
		t.Errorf("expected model claude-haiku-3, got %s", result.Model)
	}
}

func TestParseAnthropicRequest_EmptyFields(t *testing.T) {
	body := []byte(`{
		"model": "",
		"messages": []
	}`)

	result, err := ParseAnthropicRequest(body, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
}

func TestParseAnthropicRequest_MalformedJSON(t *testing.T) {
	body := []byte(`{not valid json`)

	result, err := ParseAnthropicRequest(body, "agent")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if result != nil {
		t.Error("expected nil result for malformed JSON")
	}
}

func TestParseAnthropicRequest_NilBody(t *testing.T) {
	result, err := ParseAnthropicRequest(nil, "agent")
	if err == nil {
		t.Fatal("expected error for nil body")
	}
	if result != nil {
		t.Error("expected nil result for nil body")
	}
}

func TestParseAnthropicRequest_LargeToolResult(t *testing.T) {
	// Build a large result string > 10KB.
	largeResult := strings.Repeat("x", 20*1024)

	body := []byte(`{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": "do stuff"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_big", "name": "Bash", "input": {"command": "cat bigfile"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_big", "content": "` + largeResult + `"}
			]}
		]
	}`)

	result, err := ParseAnthropicRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if len(result.Events[0].ToolResult) > 10*1024 {
		t.Errorf("expected tool result truncated to 10KB, got %d bytes", len(result.Events[0].ToolResult))
	}
	if !strings.HasSuffix(result.Events[0].ToolResult, "...[truncated]") {
		t.Error("expected truncation marker")
	}
}

func TestParseAnthropicRequest_BedrockFormat(t *testing.T) {
	body := []byte(`{
		"anthropic_version": "bedrock-2023-05-31",
		"model": "anthropic.claude-sonnet-4-20250514-v2:0",
		"messages": [
			{"role": "user", "content": "list files"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_br", "name": "Bash", "input": {"command": "ls"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_br", "content": "file.txt"}
			]}
		]
	}`)

	result, err := ParseAnthropicRequest(body, "bedrock-agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "Bash" {
		t.Errorf("expected Bash, got %s", result.Events[0].ToolName)
	}
	if result.Model != "anthropic.claude-sonnet-4-20250514-v2:0" {
		t.Errorf("expected bedrock model, got %s", result.Model)
	}
}

func TestParseAnthropicRequest_ToolResultArrayContent(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": "check"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_arr", "name": "Read", "input": {"path": "/tmp/x"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_arr", "content": [
					{"type": "text", "text": "line one"},
					{"type": "text", "text": "line two"}
				]}
			]}
		]
	}`)

	result, err := ParseAnthropicRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolResult != "line one\nline two" {
		t.Errorf("expected joined array content, got %q", result.Events[0].ToolResult)
	}
}

func TestParseAnthropicRequest_ToolUseWithoutResult(t *testing.T) {
	// The latest request may have a tool_use that hasn't been responded to yet.
	body := []byte(`{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": "do something"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_pending", "name": "Edit", "input": {"path": "/tmp/f", "old": "a", "new": "b"}}
			]}
		]
	}`)

	result, err := ParseAnthropicRequest(body, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("expected events")
	}
	if result.Events[0].ToolName != "Edit" {
		t.Errorf("expected Edit, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolResult != "" {
		t.Errorf("expected empty tool result, got %q", result.Events[0].ToolResult)
	}
}

func TestParseAnthropicStreamResponse_BasicToolUse(t *testing.T) {
	sseData := []byte(`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_s1","name":"Bash","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"ls -la\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

`)

	result, err := ParseAnthropicStreamResponse(sseData)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if result.Events[0].ToolName != "Bash" {
		t.Errorf("expected Bash, got %s", result.Events[0].ToolName)
	}
	if result.Events[0].ToolArgs != `{"command":"ls -la"}` {
		t.Errorf("expected assembled args, got %s", result.Events[0].ToolArgs)
	}
}

func TestParseAnthropicStreamResponse_NoToolUse(t *testing.T) {
	sseData := []byte(`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

`)

	result, err := ParseAnthropicStreamResponse(sseData)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil result for text-only stream")
	}
}

func TestParse_Router(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_r1", "name": "Glob", "input": {"pattern": "*.go"}}
			]}
		]
	}`)

	tests := []struct {
		host     string
		wantNil  bool
		wantTool string
	}{
		{"api.anthropic.com", false, "Glob"},
		{"bedrock-runtime.us-east-1.amazonaws.com", false, "Glob"},
		{"unknown.example.com", true, ""},
		{"", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := Parse(tt.host, body, "agent")
			if tt.wantNil {
				if result != nil && len(result.Events) > 0 {
					t.Errorf("expected nil/empty result for host %s", tt.host)
				}
				return
			}
			if result == nil || len(result.Events) == 0 {
				t.Fatalf("expected events for host %s", tt.host)
			}
			if result.Events[0].ToolName != tt.wantTool {
				t.Errorf("expected %s, got %s", tt.wantTool, result.Events[0].ToolName)
			}
		})
	}
}

func TestParse_EmptyBody(t *testing.T) {
	result := Parse("api.anthropic.com", nil, "agent")
	if result != nil {
		t.Error("expected nil result for empty body")
	}

	result = Parse("api.anthropic.com", []byte{}, "agent")
	if result != nil {
		t.Error("expected nil result for empty body")
	}
}
