package gateway

import (
	"encoding/json"
	"testing"
)

func TestSplitNamespacedTool(t *testing.T) {
	tests := []struct {
		input   string
		backend string
		tool    string
	}{
		{"github.list_repos", "github", "list_repos"},
		{"fs-server.read_file", "fs-server", "read_file"},
		{"memory.create_entities", "memory", "create_entities"},
		{"no_namespace", "", "no_namespace"},
		{"a.b.c", "a", "b.c"},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			backend, tool := splitNamespacedTool(tt.input)
			if backend != tt.backend {
				t.Errorf("backend = %q, want %q", backend, tt.backend)
			}
			if tool != tt.tool {
				t.Errorf("tool = %q, want %q", tool, tt.tool)
			}
		})
	}
}

func TestEscapeJSON(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`hello`, `hello`},
		{`say "hi"`, `say \"hi\"`},
		{`back\slash`, `back\\slash`},
		{`normal text`, `normal text`},
	}

	for _, tt := range tests {
		got := escapeJSON(tt.input)
		if got != tt.want {
			t.Errorf("escapeJSON(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGatewayHandleInitialize(t *testing.T) {
	g := &Gateway{
		backends:  make(map[string]Backend),
		toolIndex: make(map[string]string),
	}

	resp := g.handleInitialize(json.RawMessage(`1`))
	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if parsed["jsonrpc"] != "2.0" {
		t.Error("missing jsonrpc field")
	}

	result, ok := parsed["result"].(map[string]any)
	if !ok {
		t.Fatal("missing result field")
	}

	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("missing serverInfo")
	}
	if serverInfo["name"] != "quint-gateway" {
		t.Errorf("server name = %v, want quint-gateway", serverInfo["name"])
	}
}

func TestGatewayHandleToolsList(t *testing.T) {
	g := &Gateway{
		backends:  make(map[string]Backend),
		toolIndex: make(map[string]string),
		allTools: []Tool{
			{Name: "github.list_repos", Description: "[github] List repos"},
			{Name: "fs-server.read_file", Description: "[fs-server] Read file"},
		},
	}

	resp := g.handleToolsList(json.RawMessage(`2`))
	var parsed struct {
		Result struct {
			Tools []Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed.Result.Tools) != 2 {
		t.Errorf("got %d tools, want 2", len(parsed.Result.Tools))
	}
	if parsed.Result.Tools[0].Name != "github.list_repos" {
		t.Errorf("first tool = %q, want github.list_repos", parsed.Result.Tools[0].Name)
	}
}

func TestGatewayJsonRpcError(t *testing.T) {
	g := &Gateway{}

	resp := g.jsonRpcError(json.RawMessage(`42`), -32601, "Method not found")
	var parsed map[string]any
	json.Unmarshal([]byte(resp), &parsed)

	if parsed["id"].(float64) != 42 {
		t.Errorf("id = %v, want 42", parsed["id"])
	}

	errObj := parsed["error"].(map[string]any)
	if errObj["code"].(float64) != -32601 {
		t.Errorf("error code = %v, want -32601", errObj["code"])
	}
}

func TestGatewayHandleToolsCallUnknownTool(t *testing.T) {
	g := &Gateway{
		backends:  make(map[string]Backend),
		toolIndex: make(map[string]string),
	}

	params, _ := json.Marshal(map[string]any{
		"name":      "nonexistent.tool",
		"arguments": map[string]any{},
	})

	resp := g.handleToolsCall(json.RawMessage(`3`), json.RawMessage(params))
	var parsed map[string]any
	json.Unmarshal([]byte(resp), &parsed)

	if parsed["error"] == nil {
		t.Error("expected error for unknown tool")
	}
}
