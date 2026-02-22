package intercept

import "testing"

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "anything", true},
		{"Write*", "WriteFile", true},
		{"Write*", "ReadFile", false},
		{"*Shell*", "RunShellCommand", true},
		{"*Shell*", "ReadFile", false},
		{"Delete*", "DeleteFile", true},
		{"Read?", "ReadX", true},
		{"Read?", "ReadXY", false},
		{"fs-server", "fs-server", true},
		{"fs-*", "fs-server", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := GlobMatch(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("GlobMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestEvaluatePolicy(t *testing.T) {
	policy := PolicyConfig{
		Version:  1,
		LogLevel: "info",
		Servers: []ServerPolicy{
			{
				Server:        "builder-*",
				DefaultAction: ActionAllow,
				Tools: []ToolRule{
					{Tool: "DeleteFile", Action: ActionDeny},
				},
			},
			{
				Server:        "*",
				DefaultAction: ActionAllow,
				Tools:         []ToolRule{},
			},
		},
	}

	tests := []struct {
		server, tool string
		want         Verdict
	}{
		{"builder-mcp", "ReadFile", VerdictAllow},
		{"builder-mcp", "DeleteFile", VerdictDeny},
		{"builder-mcp", "", VerdictPassthrough},
		{"other-server", "ReadFile", VerdictAllow},
		{"other-server", "DeleteFile", VerdictAllow}, // no deny rule on wildcard server
	}

	for _, tt := range tests {
		t.Run(tt.server+"_"+tt.tool, func(t *testing.T) {
			got := EvaluatePolicy(policy, tt.server, tt.tool)
			if got != tt.want {
				t.Errorf("EvaluatePolicy(%q, %q) = %v, want %v", tt.server, tt.tool, got, tt.want)
			}
		})
	}
}

func TestInspectRequest(t *testing.T) {
	policy := PolicyConfig{
		Version:  1,
		LogLevel: "info",
		Servers: []ServerPolicy{
			{Server: "*", DefaultAction: ActionAllow, Tools: []ToolRule{
				{Tool: "DeleteFile", Action: ActionDeny},
			}},
		},
	}

	// Tool call that should be allowed
	allowed := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ReadFile","arguments":{"path":"/tmp"}}}`
	r := InspectRequest(allowed, "test", policy)
	if r.Verdict != VerdictAllow {
		t.Errorf("expected allow, got %s", r.Verdict)
	}
	if r.ToolName != "ReadFile" {
		t.Errorf("expected ReadFile, got %s", r.ToolName)
	}
	if r.MessageID != "1" {
		t.Errorf("expected id=1, got %s", r.MessageID)
	}

	// Tool call that should be denied
	denied := `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"DeleteFile","arguments":{"path":"/etc"}}}`
	r = InspectRequest(denied, "test", policy)
	if r.Verdict != VerdictDeny {
		t.Errorf("expected deny, got %s", r.Verdict)
	}

	// Non-tool-call method
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	r = InspectRequest(list, "test", policy)
	if r.Verdict != VerdictPassthrough {
		t.Errorf("expected passthrough, got %s", r.Verdict)
	}

	// Invalid JSON
	r = InspectRequest("not json", "test", policy)
	if r.Verdict != VerdictPassthrough {
		t.Errorf("expected passthrough for invalid JSON, got %s", r.Verdict)
	}
}

func TestBuildDenyResponse(t *testing.T) {
	resp := BuildDenyResponse([]byte(`1`))
	expected := `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Quint: tool call denied by policy"}}`
	if resp != expected {
		t.Errorf("deny response mismatch\nwant: %s\ngot:  %s", expected, resp)
	}

	// String ID
	resp = BuildDenyResponse([]byte(`"abc"`))
	if resp != `{"jsonrpc":"2.0","id":"abc","error":{"code":-32600,"message":"Quint: tool call denied by policy"}}` {
		t.Errorf("string id deny response: %s", resp)
	}

	// Null ID
	resp = BuildDenyResponse(nil)
	if resp != `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Quint: tool call denied by policy"}}` {
		t.Errorf("null id deny response: %s", resp)
	}
}
