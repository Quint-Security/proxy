package gateway

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

// mockBackend implements the Backend interface for testing.
type mockBackend struct {
	name  string
	tools []Tool
}

func (m *mockBackend) Name() string  { return m.name }
func (m *mockBackend) Start() error  { return nil }
func (m *mockBackend) Stop()         {}
func (m *mockBackend) Tools() []Tool { return m.tools }
func (m *mockBackend) Call(id json.RawMessage, toolName string, arguments json.RawMessage) (json.RawMessage, error) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"result": map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": fmt.Sprintf("mock response from %s.%s", m.name, toolName)},
			},
		},
	}
	data, _ := json.Marshal(resp)
	return data, nil
}
func (m *mockBackend) Forward(msg json.RawMessage) (json.RawMessage, error) {
	return msg, nil
}

// TestIntegrationFullFlow tests: initialize → identity resolution → tool call → audit log
func TestIntegrationFullFlow(t *testing.T) {
	tmpDir := t.TempDir()

	// --- Setup auth DB with a registered agent ---
	authDB, err := auth.OpenDB(tmpDir)
	if err != nil {
		t.Fatalf("auth DB: %v", err)
	}
	defer authDB.Close()

	agent, _, err := authDB.CreateAgent("test-reader", "generic", "A test agent", "tools:read,tools:write", "test-creator")
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	t.Logf("registered agent: id=%s name=%s", agent.ID, agent.Name)

	// --- Setup audit logger ---
	kp, err := crypto.EnsureKeyPair(tmpDir, "test-passphrase")
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	auditDB, err := audit.OpenDB(tmpDir)
	if err != nil {
		t.Fatalf("audit DB: %v", err)
	}
	defer auditDB.Close()

	logger := audit.NewLogger(auditDB, kp.PrivateKey, kp.PublicKey, map[string]any{"version": 1})

	// --- Setup risk engine ---
	riskEngine := risk.NewEngineFromPolicy(nil, nil)

	// --- Setup policy ---
	policy := intercept.DefaultPolicy()
	policy.AutoRegisterAgents = true
	policy.DefaultAgentScopes = "read"

	// --- Build gateway with mock backend ---
	mock := &mockBackend{
		name: "github",
		tools: []Tool{
			{Name: "list_repos", Description: "List repositories"},
			{Name: "create_issue", Description: "Create an issue"},
		},
	}

	g := &Gateway{
		backends:          map[string]Backend{"github": mock},
		toolIndex:         map[string]string{"github.list_repos": "github", "github.create_issue": "github"},
		allTools:          []Tool{{Name: "github.list_repos"}, {Name: "github.create_issue"}},
		policy:            policy,
		logger:            logger,
		riskEngine:        riskEngine,
		identity:          nil, // no startup identity — will be resolved from clientInfo
		sessionTracker:    risk.NewSessionTracker(20, 0),
		spawnDetector:     intercept.NewSpawnDetector(nil),
		correlationEngine: intercept.NewCorrelationEngine(),
		authDB:            authDB,
	}

	// =============================================
	// PHASE 1: Initialize with clientInfo matching registered agent
	// =============================================
	t.Run("initialize_resolves_identity", func(t *testing.T) {
		initMsg := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test-reader","version":"1.0"}}}`
		resp := g.handleMessage(initMsg)

		if resp == "" {
			t.Fatal("empty response from initialize")
		}

		var parsed map[string]any
		if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if parsed["error"] != nil {
			t.Fatalf("initialize returned error: %v", parsed["error"])
		}

		// Verify identity was resolved
		if g.identity == nil {
			t.Fatal("identity not resolved after initialize")
		}
		if g.identity.AgentName != "test-reader" {
			t.Errorf("agent name = %q, want test-reader", g.identity.AgentName)
		}
		if g.identity.Source != "client_info" {
			t.Errorf("source = %q, want client_info", g.identity.Source)
		}
		t.Logf("identity resolved: agent=%s source=%s", g.identity.AgentName, g.identity.Source)
	})

	// =============================================
	// PHASE 2: Tool call — should be logged with resolved identity
	// =============================================
	t.Run("tool_call_logged_with_identity", func(t *testing.T) {
		callMsg := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"github.list_repos","arguments":{"org":"test-org"}}}`
		resp := g.handleMessage(callMsg)

		if resp == "" {
			t.Fatal("empty response from tools/call")
		}

		var parsed map[string]any
		if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if parsed["error"] != nil {
			t.Fatalf("tools/call returned error: %v", parsed["error"])
		}

		t.Logf("tool call response: %s", truncateStr(resp, 120))

		// Query audit DB for events
		entries, total, err := auditDB.Query(audit.QueryOpts{Limit: 10})
		if err != nil {
			t.Fatalf("audit query: %v", err)
		}
		t.Logf("audit DB has %d entries", total)

		if total == 0 {
			t.Fatal("no audit entries — events not logged!")
		}

		// Find the request entry with agent identity
		found := false
		for _, e := range entries {
			if e.Direction == "request" && e.ToolName != nil && *e.ToolName == "list_repos" {
				found = true
				t.Logf("  entry: tool=%s agent=%v verdict=%s risk=%v",
					*e.ToolName, ptrStr(e.AgentName), e.Verdict, e.RiskScore)

				if e.AgentName == nil || *e.AgentName != "test-reader" {
					t.Errorf("agent_name = %v, want test-reader", ptrStr(e.AgentName))
				}
				if e.AgentID == nil || *e.AgentID != agent.ID {
					t.Errorf("agent_id = %v, want %s", ptrStr(e.AgentID), agent.ID)
				}
			}
		}
		if !found {
			t.Error("no audit entry found for list_repos tool call")
			for _, e := range entries {
				t.Logf("  entry: dir=%s method=%s tool=%v verdict=%s", e.Direction, e.Method, ptrStr(e.ToolName), e.Verdict)
			}
		}
	})

	// =============================================
	// PHASE 3: Second tool call — verify session tracking
	// =============================================
	t.Run("second_tool_call_tracked", func(t *testing.T) {
		callMsg := `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"title":"test issue","body":"testing"}}}`
		resp := g.handleMessage(callMsg)

		if resp == "" {
			t.Fatal("empty response from second tools/call")
		}

		var parsed map[string]any
		json.Unmarshal([]byte(resp), &parsed)
		if parsed["error"] != nil {
			t.Fatalf("second tools/call returned error: %v", parsed["error"])
		}

		// Verify preceding actions are tracked
		preceding := g.sessionTracker.Recent(g.identity.SubjectID)
		t.Logf("preceding actions: %v", preceding)
		if len(preceding) < 2 {
			t.Errorf("expected at least 2 preceding actions, got %d", len(preceding))
		}
	})

	// =============================================
	// PHASE 4: New session with unknown agent (auto-register)
	// =============================================
	t.Run("auto_register_unknown_agent", func(t *testing.T) {
		initMsg := `{"jsonrpc":"2.0","id":20,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"brand-new-agent","version":"0.1"}}}`
		resp := g.handleMessage(initMsg)

		if resp == "" {
			t.Fatal("empty response from initialize")
		}

		if g.identity == nil {
			t.Fatal("identity not resolved for auto-registered agent")
		}
		if g.identity.AgentName != "brand-new-agent" {
			t.Errorf("agent name = %q, want brand-new-agent", g.identity.AgentName)
		}
		if g.identity.Source != "auto_register" {
			t.Errorf("source = %q, want auto_register", g.identity.Source)
		}

		// Verify agent was persisted
		a, err := authDB.GetAgentByName("brand-new-agent")
		if err != nil {
			t.Fatalf("auto-registered agent not in DB: %v", err)
		}
		t.Logf("auto-registered: id=%s type=%s scopes=%s", a.ID, a.Type, a.Scopes)
	})

	// =============================================
	// PHASE 5: Verify audit chain integrity
	// =============================================
	t.Run("audit_chain_integrity", func(t *testing.T) {
		verified, brokenAt, err := auditDB.VerifyChain()
		if err != nil {
			t.Fatalf("chain verify: %v", err)
		}
		if brokenAt > 0 {
			t.Errorf("chain broken at entry %d", brokenAt)
		}
		t.Logf("audit chain: %d entries verified, integrity OK", verified)
	})

	// =============================================
	// PHASE 6: Auto-registered agent can make read tool calls
	// =============================================
	t.Run("auto_registered_agent_can_call_tools", func(t *testing.T) {
		// g.identity is now "brand-new-agent" with auto-registered scopes
		callMsg := `{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"github.list_repos","arguments":{"org":"acme"}}}`
		resp := g.handleMessage(callMsg)

		var parsed map[string]any
		json.Unmarshal([]byte(resp), &parsed)
		if parsed["error"] != nil {
			t.Fatalf("auto-registered agent tool call denied: %v", parsed["error"])
		}
		t.Logf("auto-registered agent successfully called list_repos")
	})

	// Print summary
	entries, total, _ := auditDB.Query(audit.QueryOpts{Limit: 50})
	t.Logf("\n=== AUDIT LOG SUMMARY (%d entries) ===", total)
	for _, e := range entries {
		tool := "-"
		if e.ToolName != nil {
			tool = *e.ToolName
		}
		agent := "-"
		if e.AgentName != nil {
			agent = *e.AgentName
		}
		riskStr := "-"
		if e.RiskScore != nil {
			riskStr = fmt.Sprintf("%d", *e.RiskScore)
		}
		t.Logf("  [%s] %s %s tool=%s agent=%s risk=%s verdict=%s",
			e.Timestamp[:19], e.Direction, e.Method, tool, agent, riskStr, e.Verdict)
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func ptrStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
