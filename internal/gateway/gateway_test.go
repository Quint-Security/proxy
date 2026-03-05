package gateway

import (
	"encoding/json"
	"testing"

	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
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

	resp := g.handleInitialize(json.RawMessage(`1`), nil)
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

func TestGatewayHandleInitializeWithClientInfo(t *testing.T) {
	g := &Gateway{
		backends:  make(map[string]Backend),
		toolIndex: make(map[string]string),
		policy:    intercept.DefaultPolicy(),
	}

	params := json.RawMessage(`{"protocolVersion":"2024-11-05","clientInfo":{"name":"test-agent","version":"1.0"}}`)
	resp := g.handleInitialize(json.RawMessage(`2`), params)

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	result, ok := parsed["result"].(map[string]any)
	if !ok {
		t.Fatal("missing result")
	}
	serverInfo := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "quint-gateway" {
		t.Errorf("server name = %v, want quint-gateway", serverInfo["name"])
	}

	// Identity should remain nil (no authDB, no matching agent)
	if g.identity != nil {
		t.Errorf("identity should be nil without authDB, got %+v", g.identity)
	}
}

func TestGatewayHandleInitializeWithQuintAuth(t *testing.T) {
	g := &Gateway{
		backends:  make(map[string]Backend),
		toolIndex: make(map[string]string),
		policy:    intercept.DefaultPolicy(),
	}

	params := json.RawMessage(`{"clientInfo":{"name":"x"},"_quint":{"api_key":"qk_test123"}}`)
	resp := g.handleInitialize(json.RawMessage(`3`), params)

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	// Should still return valid response even if auth fails
	if parsed["result"] == nil {
		t.Error("missing result — initialize must always return a response")
	}
}

func TestGatewayHandleMessageInitialize(t *testing.T) {
	g := &Gateway{
		backends:  make(map[string]Backend),
		toolIndex: make(map[string]string),
		policy:    intercept.DefaultPolicy(),
	}

	// Full JSON-RPC initialize message through handleMessage
	msg := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"claude","version":"3.5"}}}`
	resp := g.handleMessage(msg)

	if resp == "" {
		t.Fatal("handleMessage returned empty string for initialize")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["result"] == nil {
		t.Error("missing result in initialize response")
	}
}

func TestGatewaySessionIdentityResolution(t *testing.T) {
	tmpDir := t.TempDir()
	authDB, err := auth.OpenDB(tmpDir)
	if err != nil {
		t.Fatalf("failed to open auth DB: %v", err)
	}
	defer authDB.Close()

	// Register an agent
	agent, _, err := authDB.CreateAgent("my-agent", "generic", "", "read,write", "test")
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	g := &Gateway{
		backends:  make(map[string]Backend),
		toolIndex: make(map[string]string),
		policy:    intercept.DefaultPolicy(),
		authDB:    authDB,
	}

	// Initialize with matching clientInfo.name
	params := json.RawMessage(`{"protocolVersion":"2024-11-05","clientInfo":{"name":"my-agent","version":"1.0"}}`)
	resp := g.handleInitialize(json.RawMessage(`1`), params)

	// Must return valid response
	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["result"] == nil {
		t.Fatal("missing result in initialize response")
	}

	// Identity should be resolved to the registered agent
	if g.identity == nil {
		t.Fatal("identity should be resolved")
	}
	if g.identity.AgentID != agent.ID {
		t.Errorf("agent ID = %q, want %q", g.identity.AgentID, agent.ID)
	}
	if g.identity.AgentName != "my-agent" {
		t.Errorf("agent name = %q, want my-agent", g.identity.AgentName)
	}
	if g.identity.Source != "client_info" {
		t.Errorf("source = %q, want client_info", g.identity.Source)
	}
}

func TestGatewayAutoRegisterAgent(t *testing.T) {
	tmpDir := t.TempDir()
	authDB, err := auth.OpenDB(tmpDir)
	if err != nil {
		t.Fatalf("failed to open auth DB: %v", err)
	}
	defer authDB.Close()

	policy := intercept.DefaultPolicy()
	policy.AutoRegisterAgents = true
	policy.DefaultAgentScopes = "read"

	g := &Gateway{
		backends:  make(map[string]Backend),
		toolIndex: make(map[string]string),
		policy:    policy,
		authDB:    authDB,
	}

	// Initialize with unknown clientInfo.name (should auto-register)
	params := json.RawMessage(`{"protocolVersion":"2024-11-05","clientInfo":{"name":"new-bot","version":"2.0"}}`)
	resp := g.handleInitialize(json.RawMessage(`1`), params)

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if g.identity == nil {
		t.Fatal("identity should be auto-registered")
	}
	if g.identity.AgentName != "new-bot" {
		t.Errorf("agent name = %q, want new-bot", g.identity.AgentName)
	}
	if g.identity.Source != "auto_register" {
		t.Errorf("source = %q, want auto_register", g.identity.Source)
	}

	// Verify agent was persisted in DB
	agent, err := authDB.GetAgentByName("new-bot")
	if err != nil {
		t.Fatalf("agent not found in DB: %v", err)
	}
	if agent.Type != "generic" {
		t.Errorf("agent type = %q, want generic", agent.Type)
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
