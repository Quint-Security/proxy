package intercept

import "testing"

func TestClassifyAction_ToolsCall(t *testing.T) {
	tests := []struct {
		server, tool, method string
		want                 string
	}{
		{"github", "list_repos", "tools/call", "mcp:github:list_repos.list"},
		{"github", "create_file", "tools/call", "mcp:github:create_file.create"},
		{"slack", "send_message", "tools/call", "mcp:slack:send_message.send"},
		{"postgres", "execute_query", "tools/call", "mcp:postgres:execute_query.execute"},
		{"filesystem", "read_file", "tools/call", "mcp:filesystem:read_file.read"},
		{"filesystem", "write_file", "tools/call", "mcp:filesystem:write_file.write"},
		{"filesystem", "delete_file", "tools/call", "mcp:filesystem:delete_file.delete"},
		{"notion", "search_pages", "tools/call", "mcp:notion:search_pages.search"},
		{"custom", "do_something", "tools/call", "mcp:custom:do_something.invoke"},
	}

	for _, tt := range tests {
		got := ClassifyAction(tt.server, tt.tool, tt.method)
		if got != tt.want {
			t.Errorf("ClassifyAction(%q, %q, %q) = %q, want %q", tt.server, tt.tool, tt.method, got, tt.want)
		}
	}
}

func TestClassifyAction_OtherMethods(t *testing.T) {
	got := ClassifyAction("github", "", "resources/read")
	if got != "mcp:github:resource.read" {
		t.Errorf("resources/read got %q", got)
	}

	got = ClassifyAction("github", "", "prompts/get")
	if got != "mcp:github:prompt.get" {
		t.Errorf("prompts/get got %q", got)
	}
}

func TestClassifyAction_SanitizesColons(t *testing.T) {
	got := ClassifyAction("my:server", "my:tool", "tools/call")
	if got != "mcp:my_server:my_tool.invoke" {
		t.Errorf("expected colons sanitized, got %q", got)
	}
}

func TestInferVerb(t *testing.T) {
	tests := []struct {
		toolName string
		want     string
	}{
		{"list_repos", "list"},
		{"get_user", "read"},
		{"create_issue", "create"},
		{"update_record", "update"},
		{"delete_file", "delete"},
		{"send_email", "send"},
		{"run_query", "execute"},
		{"fetch_data", "read"},
		{"unknown_tool", "invoke"},
		{"search", "search"},
	}

	for _, tt := range tests {
		got := inferVerb(tt.toolName)
		if got != tt.want {
			t.Errorf("inferVerb(%q) = %q, want %q", tt.toolName, got, tt.want)
		}
	}
}
