package dashboard

import (
	"testing"

	"github.com/Quint-Security/quint-proxy/internal/audit"
)

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }

func TestBuildAgentGraphs_ForwardProxyHTTPFiltered(t *testing.T) {
	// Simulate forward proxy audit entries: all tool names are http: prefixed.
	// The graph should contain ONLY agent nodes (no tool call sub-nodes).
	parentAgent := "agent-parent-001"
	parentName := "claude-code-1"
	child1Agent := "agent-child-001"
	child1Name := "claude-code-2"
	child2Agent := "agent-child-002"
	child2Name := "claude-code-3"
	entries := []audit.Entry{
		// Parent agent: multiple HTTP requests
		{ID: 1, ServerName: "api.anthropic.com", Direction: "request", Method: "POST",
			ToolName: strPtr("http:api.anthropic.com:post.messages"), Verdict: "allow",
			AgentID: &parentAgent, AgentName: &parentName,
			Timestamp: "2026-03-04T10:00:00Z",
		},
		{ID: 2, ServerName: "api.anthropic.com", Direction: "response", Method: "POST",
			ToolName: strPtr("http:api.anthropic.com:post.messages"), Verdict: "passthrough",
			AgentID: &parentAgent, AgentName: &parentName,
			Timestamp: "2026-03-04T10:00:01Z",
		},
		{ID: 3, ServerName: "api.anthropic.com", Direction: "request", Method: "POST",
			ToolName: strPtr("http:api.anthropic.com:post.messages"), Verdict: "allow",
			AgentID: &parentAgent, AgentName: &parentName,
			Timestamp: "2026-03-04T10:00:02Z",
		},
		// Child 1: HTTP requests with parent reference
		{ID: 10, ServerName: "www.google.com", Direction: "request", Method: "GET",
			ToolName: strPtr("http:www.google.com:get.search"), Verdict: "allow",
			AgentID: &child1Agent, AgentName: &child1Name,
			ParentAgentID: &parentAgent, AgentDepth: intPtr(1),
			Timestamp: "2026-03-04T10:01:00Z",
		},
		{ID: 11, ServerName: "www.google.com", Direction: "response", Method: "GET",
			ToolName: strPtr("http:www.google.com:get.search"), Verdict: "passthrough",
			AgentID: &child1Agent, AgentName: &child1Name,
			ParentAgentID: &parentAgent, AgentDepth: intPtr(1),
			Timestamp: "2026-03-04T10:01:01Z",
		},
		// Child 2: HTTP requests
		{ID: 20, ServerName: "www.google.com", Direction: "request", Method: "GET",
			ToolName: strPtr("http:www.google.com:get.search"), Verdict: "allow",
			AgentID: &child2Agent, AgentName: &child2Name,
			ParentAgentID: &parentAgent, AgentDepth: intPtr(1),
			Timestamp: "2026-03-04T10:02:00Z",
		},
	}

	// Relationship rows from agent_relationships table
	relationships := []audit.AgentRelationshipRow{
		{ParentAgent: parentAgent, ChildAgent: child1Agent, Confidence: 0.95, Depth: 1,
			FirstSeen: "2026-03-04T10:01:00Z", LastSeen: "2026-03-04T10:01:01Z"},
		{ParentAgent: parentAgent, ChildAgent: child2Agent, Confidence: 0.95, Depth: 1,
			FirstSeen: "2026-03-04T10:02:00Z", LastSeen: "2026-03-04T10:02:00Z"},
	}

	graphs := buildAgentGraphs(entries, relationships)

	if len(graphs) != 1 {
		t.Fatalf("expected 1 graph, got %d", len(graphs))
	}

	g := graphs[0]
	// Should have exactly 3 nodes: 1 parent (orchestrator) + 2 children (workers)
	// NO tool call sub-nodes because all tool names are http: prefixed.
	if g.TotalNodes != 3 {
		t.Errorf("expected 3 nodes (parent + 2 children), got %d", g.TotalNodes)
		for _, n := range g.Nodes {
			t.Logf("  node: id=%s agent=%s type=%s tool=%s", n.ID, n.AgentName, n.Type, n.Metadata.Tool)
		}
	}

	// Verify node types
	types := map[string]int{}
	for _, n := range g.Nodes {
		types[n.Type]++
	}
	if types["orchestrator"] != 1 {
		t.Errorf("expected 1 orchestrator, got %d", types["orchestrator"])
	}
	if types["worker"] != 2 {
		t.Errorf("expected 2 workers, got %d", types["worker"])
	}

	// Root should be the parent agent
	if g.RootAgentID != parentAgent {
		t.Errorf("expected root agent %q, got %q", parentAgent, g.RootAgentID)
	}

	// Children should have parentId set
	for _, n := range g.Nodes {
		if n.Type == "worker" && n.ParentID == nil {
			t.Errorf("worker node %s should have a parent", n.AgentName)
		}
	}
}

func TestBuildAgentGraphs_MixedMCPAndHTTP(t *testing.T) {
	// MCP gateway entries should still create tool sub-nodes.
	// Only http: prefixed entries should be filtered.
	agentID := "agent-001"
	agentName := "claude-code-1"

	entries := []audit.Entry{
		// MCP tool call — should create a sub-node
		{ID: 1, ServerName: "filesystem", Direction: "request", Method: "tools/call",
			ToolName: strPtr("read_file"), Verdict: "allow",
			AgentID: &agentID, AgentName: &agentName,
			Timestamp: "2026-03-04T10:00:00Z",
		},
		// HTTP request — should NOT create a sub-node
		{ID: 2, ServerName: "api.anthropic.com", Direction: "request", Method: "POST",
			ToolName: strPtr("http:api.anthropic.com:post.messages"), Verdict: "allow",
			AgentID: &agentID, AgentName: &agentName,
			Timestamp: "2026-03-04T10:00:01Z",
		},
		// Another MCP tool call
		{ID: 3, ServerName: "filesystem", Direction: "request", Method: "tools/call",
			ToolName: strPtr("write_file"), Verdict: "allow",
			AgentID: &agentID, AgentName: &agentName,
			Timestamp: "2026-03-04T10:00:02Z",
		},
	}

	graphs := buildAgentGraphs(entries, nil)

	if len(graphs) != 1 {
		t.Fatalf("expected 1 graph, got %d", len(graphs))
	}

	g := graphs[0]
	// 1 agent node + 2 MCP tool nodes = 3 total (HTTP entry excluded)
	if g.TotalNodes != 3 {
		t.Errorf("expected 3 nodes (1 agent + 2 MCP tools), got %d", g.TotalNodes)
		for _, n := range g.Nodes {
			t.Logf("  node: id=%s agent=%s type=%s tool=%s", n.ID, n.AgentName, n.Type, n.Metadata.Tool)
		}
	}
}
