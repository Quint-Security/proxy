package auth

import (
	"testing"
)

func TestExpandScopes(t *testing.T) {
	tests := []struct {
		name     string
		granted  []string
		expected map[string]bool
	}{
		{
			name:    "admin expands to write and read",
			granted: []string{ScopeToolsAdmin},
			expected: map[string]bool{
				ScopeToolsAdmin: true,
				ScopeToolsWrite: true,
				ScopeToolsRead:  true,
			},
		},
		{
			name:    "execute expands to read",
			granted: []string{ScopeToolsExecute},
			expected: map[string]bool{
				ScopeToolsExecute: true,
				ScopeToolsRead:    true,
			},
		},
		{
			name:    "write expands to read",
			granted: []string{ScopeToolsWrite},
			expected: map[string]bool{
				ScopeToolsWrite: true,
				ScopeToolsRead:  true,
			},
		},
		{
			name:    "read has no children",
			granted: []string{ScopeToolsRead},
			expected: map[string]bool{
				ScopeToolsRead: true,
			},
		},
		{
			name:    "admin does not grant execute",
			granted: []string{ScopeToolsAdmin},
			expected: map[string]bool{
				ScopeToolsAdmin: true,
				ScopeToolsWrite: true,
				ScopeToolsRead:  true,
			},
		},
		{
			name:    "multiple scopes combine",
			granted: []string{ScopeToolsAdmin, ScopeToolsExecute},
			expected: map[string]bool{
				ScopeToolsAdmin:   true,
				ScopeToolsExecute: true,
				ScopeToolsWrite:   true,
				ScopeToolsRead:    true,
			},
		},
		{
			name:     "empty scopes",
			granted:  nil,
			expected: map[string]bool{},
		},
		{
			name:    "unknown scope kept as-is",
			granted: []string{"custom:scope"},
			expected: map[string]bool{
				"custom:scope": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandScopes(tt.granted)
			if len(got) != len(tt.expected) {
				t.Errorf("length mismatch: got %v, want %v", got, tt.expected)
				return
			}
			for k, v := range tt.expected {
				if got[k] != v {
					t.Errorf("scope %q: got %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		name     string
		granted  []string
		required string
		want     bool
	}{
		{"admin has read", []string{ScopeToolsAdmin}, ScopeToolsRead, true},
		{"admin has write", []string{ScopeToolsAdmin}, ScopeToolsWrite, true},
		{"admin lacks execute", []string{ScopeToolsAdmin}, ScopeToolsExecute, false},
		{"execute has read", []string{ScopeToolsExecute}, ScopeToolsRead, true},
		{"execute lacks write", []string{ScopeToolsExecute}, ScopeToolsWrite, false},
		{"read lacks write", []string{ScopeToolsRead}, ScopeToolsWrite, false},
		{"read has read", []string{ScopeToolsRead}, ScopeToolsRead, true},
		{"empty lacks everything", nil, ScopeToolsRead, false},
		{"combined covers all", []string{ScopeToolsAdmin, ScopeToolsExecute}, ScopeToolsExecute, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasScope(tt.granted, tt.required); got != tt.want {
				t.Errorf("HasScope(%v, %q) = %v, want %v", tt.granted, tt.required, got, tt.want)
			}
		})
	}
}

func TestRequiredScopeForTool(t *testing.T) {
	tests := []struct {
		tool string
		want string
	}{
		// Admin tools
		{"DeleteFile", ScopeToolsAdmin},
		{"delete_resource", ScopeToolsAdmin},
		{"RemoveUser", ScopeToolsAdmin},
		{"DropTable", ScopeToolsAdmin},

		// Execute tools
		{"ExecuteCommand", ScopeToolsExecute},
		{"ShellRun", ScopeToolsExecute},
		{"BashExec", ScopeToolsExecute},
		{"RunScript", ScopeToolsExecute},

		// Write tools
		{"WriteFile", ScopeToolsWrite},
		{"CreateResource", ScopeToolsWrite},
		{"UpdateRecord", ScopeToolsWrite},
		{"EditDocument", ScopeToolsWrite},

		// Read tools
		{"ReadFile", ScopeToolsRead},
		{"GetUser", ScopeToolsRead},
		{"ListDirectory", ScopeToolsRead},
		{"SearchFiles", ScopeToolsRead},

		// Unknown defaults to write (fail closed)
		{"foo_bar", ScopeToolsWrite},
		{"unknown_tool", ScopeToolsWrite},
		{"notify", ScopeToolsWrite},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			if got := RequiredScopeForTool(tt.tool); got != tt.want {
				t.Errorf("RequiredScopeForTool(%q) = %q, want %q", tt.tool, got, tt.want)
			}
		})
	}
}

func TestEnforceScope(t *testing.T) {
	agent := &Identity{
		SubjectID: "agent_123",
		AgentID:   "agent_123",
		AgentName: "test-bot",
		Scopes:    []string{ScopeToolsRead},
		IsAgent:   true,
	}

	nonAgent := &Identity{
		SubjectID: "key_456",
		IsAgent:   false,
	}

	// Agent with read scope can read
	if scope, ok := EnforceScope(agent, "list_directory"); !ok {
		t.Errorf("agent with tools:read should access list_directory, got denied (needs %s)", scope)
	}

	// Agent with read scope cannot write
	if _, ok := EnforceScope(agent, "write_file"); ok {
		t.Error("agent with tools:read should NOT access write_file")
	}

	// Non-agent always passes
	if _, ok := EnforceScope(nonAgent, "DeleteEverything"); !ok {
		t.Error("non-agent should always pass scope enforcement")
	}

	// Nil identity always passes
	if _, ok := EnforceScope(nil, "DeleteEverything"); !ok {
		t.Error("nil identity should always pass scope enforcement")
	}
}

func TestParseScopes(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"tools:read", []string{"tools:read"}},
		{"tools:read,tools:write", []string{"tools:read", "tools:write"}},
		{" tools:read , tools:write ", []string{"tools:read", "tools:write"}},
		{",,tools:read,,", []string{"tools:read"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseScopes(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("ParseScopes(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseScopes(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}
