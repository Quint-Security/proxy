package cloud

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Empty / wildcard
		{"", "anything", true},
		{"*", "anything", true},
		// Exact match (case-insensitive)
		{"Bash", "Bash", true},
		{"Bash", "bash", true},
		{"bash", "BASH", true},
		{"Bash", "Read", false},
		// Prefix match
		{"api.*", "api.github.com:POST./repos", true},
		{"api.*", "cdn.example.com", false},
		// Suffix match
		{"*.github.com*", "api.github.com:POST./repos", true},
		{"*Bar", "FooBar", true},
		{"*bar", "FooBar", true},
		{"*Bar", "FooBaz", false},
		// Contains match
		{"*github*", "api.github.com:POST./repos", true},
		{"*github*", "example.com", false},
		{"*mid*", "prefix-mid-suffix", true},
		{"*mid*", "nomatch", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := globMatch(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchesAnyCondition(t *testing.T) {
	tests := []struct {
		conditions []string
		argsJSON   string
		want       bool
	}{
		{[]string{"/etc/passwd"}, `{"command":"cat /etc/passwd"}`, true},
		{[]string{"/etc/*"}, `{"command":"cat /etc/shadow"}`, true},
		{[]string{"rm -rf"}, `{"command":"rm -rf /"}`, true},
		{[]string{"secret"}, `{"key":"not-here"}`, false},
		{[]string{}, `{"key":"value"}`, false},
		{[]string{"test"}, "", false},
	}

	for i, tt := range tests {
		got := matchesAnyCondition(tt.conditions, tt.argsJSON)
		if got != tt.want {
			t.Errorf("case %d: matchesAnyCondition(%v, %q) = %v, want %v", i, tt.conditions, tt.argsJSON, got, tt.want)
		}
	}
}

func TestEnforcerEvaluate(t *testing.T) {
	e := NewEnforcer("")
	e.Update([]CloudPolicy{
		{
			ID:       "pol-1",
			Name:     "Block dangerous tools",
			Enabled:  true,
			Priority: 100,
			Rules: []PolicyRule{
				{Tool: "Bash", Agent: "*", Action: "block", Conditions: []string{"rm -rf"}},
				{Tool: "Bash", Agent: "*", Action: "flag"},
			},
		},
		{
			ID:       "pol-2",
			Name:     "Block all for test-agent",
			Enabled:  true,
			Priority: 50,
			Rules: []PolicyRule{
				{Tool: "*", Agent: "test-agent", Action: "block"},
			},
		},
		{
			ID:       "pol-disabled",
			Name:     "Disabled policy",
			Enabled:  false,
			Priority: 200,
			Rules: []PolicyRule{
				{Tool: "*", Agent: "*", Action: "block"},
			},
		},
	}, "hash-1")

	tests := []struct {
		name     string
		tool     string
		agent    string
		args     string
		wantAct  string
		wantPol  string
		wantRule int
	}{
		{
			name:     "Bash with rm -rf matches block condition",
			tool:     "Bash",
			agent:    "some-agent",
			args:     `{"command":"rm -rf /tmp"}`,
			wantAct:  "block",
			wantPol:  "Block dangerous tools",
			wantRule: 0,
		},
		{
			name:     "Bash without dangerous args matches flag",
			tool:     "Bash",
			agent:    "some-agent",
			args:     `{"command":"ls"}`,
			wantAct:  "flag",
			wantPol:  "Block dangerous tools",
			wantRule: 1,
		},
		{
			name:     "Read tool for some-agent is allowed",
			tool:     "Read",
			agent:    "some-agent",
			args:     `{}`,
			wantAct:  "allow",
			wantPol:  "",
			wantRule: -1,
		},
		{
			name:     "Any tool for test-agent is blocked by lower priority",
			tool:     "Read",
			agent:    "test-agent",
			args:     `{}`,
			wantAct:  "block",
			wantPol:  "Block all for test-agent",
			wantRule: 0,
		},
		{
			name:     "Disabled policy does not match",
			tool:     "Write",
			agent:    "other-agent",
			args:     `{}`,
			wantAct:  "allow",
			wantPol:  "",
			wantRule: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.Evaluate(tt.tool, tt.agent, tt.args)
			if result.Action != tt.wantAct {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAct)
			}
			if result.PolicyName != tt.wantPol {
				t.Errorf("PolicyName = %q, want %q", result.PolicyName, tt.wantPol)
			}
			if result.RuleIndex != tt.wantRule {
				t.Errorf("RuleIndex = %d, want %d", result.RuleIndex, tt.wantRule)
			}
		})
	}
}

func TestEnforcerPriorityOrder(t *testing.T) {
	e := NewEnforcer("")
	// Low priority added first, high priority added second —
	// Update should sort them correctly.
	e.Update([]CloudPolicy{
		{
			ID:       "low",
			Name:     "Low priority",
			Enabled:  true,
			Priority: 10,
			Rules:    []PolicyRule{{Tool: "Bash", Agent: "*", Action: "flag"}},
		},
		{
			ID:       "high",
			Name:     "High priority",
			Enabled:  true,
			Priority: 100,
			Rules:    []PolicyRule{{Tool: "Bash", Agent: "*", Action: "block"}},
		},
	}, "hash-2")

	result := e.Evaluate("Bash", "agent", "")
	if result.Action != "block" {
		t.Errorf("expected high-priority block, got %q", result.Action)
	}
	if result.PolicyName != "High priority" {
		t.Errorf("expected 'High priority' policy, got %q", result.PolicyName)
	}
}

func TestEnforcerDiskCache(t *testing.T) {
	tmpDir := t.TempDir()

	// Create enforcer, update policies, verify disk cache
	e1 := NewEnforcer(tmpDir)
	e1.Update([]CloudPolicy{
		{
			ID:       "pol-cached",
			Name:     "Cached policy",
			Enabled:  true,
			Priority: 50,
			Rules:    []PolicyRule{{Tool: "Bash", Agent: "*", Action: "block"}},
		},
	}, "hash-cached")

	// Verify cache file exists
	cachePath := filepath.Join(tmpDir, "cloud_policies.json")
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Fatal("cache file not created")
	}

	// Create a new enforcer from the same dir — should load from cache
	e2 := NewEnforcer(tmpDir)
	if e2.Hash() != "hash-cached" {
		t.Errorf("hash = %q, want %q", e2.Hash(), "hash-cached")
	}
	if e2.PolicyCount() != 1 {
		t.Errorf("policy count = %d, want 1", e2.PolicyCount())
	}

	result := e2.Evaluate("Bash", "any-agent", "")
	if result.Action != "block" {
		t.Errorf("cached policy action = %q, want 'block'", result.Action)
	}
}

func TestEnforcerEmptyPolicies(t *testing.T) {
	e := NewEnforcer("")
	result := e.Evaluate("Bash", "agent", `{"command":"rm -rf /"}`)
	if result.Action != "allow" {
		t.Errorf("with no policies, expected allow, got %q", result.Action)
	}
	if result.RuleIndex != -1 {
		t.Errorf("with no policies, expected RuleIndex=-1, got %d", result.RuleIndex)
	}
}
