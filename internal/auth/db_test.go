package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := OpenDB(dir)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCreateAndListAgents(t *testing.T) {
	db := testDB(t)

	agent, rawKey, err := db.CreateAgent("test-bot", "research", "a test agent", "tools:read", "operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	if agent.Name != "test-bot" {
		t.Errorf("name = %q, want test-bot", agent.Name)
	}
	if agent.Type != "research" {
		t.Errorf("type = %q, want research", agent.Type)
	}
	if agent.Scopes != "tools:read" {
		t.Errorf("scopes = %q, want tools:read", agent.Scopes)
	}
	if agent.Status != "active" {
		t.Errorf("status = %q, want active", agent.Status)
	}
	if rawKey == "" {
		t.Error("rawKey is empty")
	}

	agents, err := db.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("got %d agents, want 1", len(agents))
	}
	if agents[0].ID != agent.ID {
		t.Errorf("listed agent ID = %q, want %q", agents[0].ID, agent.ID)
	}
}

func TestCreateAgentDuplicateName(t *testing.T) {
	db := testDB(t)

	_, _, err := db.CreateAgent("dup-bot", "generic", "", "tools:read", "operator")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, _, err = db.CreateAgent("dup-bot", "generic", "", "tools:read", "operator")
	if err == nil {
		t.Error("expected error for duplicate agent name")
	}
}

func TestGetAgentByName(t *testing.T) {
	db := testDB(t)

	created, _, err := db.CreateAgent("lookup-bot", "generic", "", "tools:write", "operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	found, err := db.GetAgentByName("lookup-bot")
	if err != nil {
		t.Fatalf("GetAgentByName: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("ID mismatch: got %q, want %q", found.ID, created.ID)
	}

	_, err = db.GetAgentByName("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestGetAgentByApiKeyID(t *testing.T) {
	db := testDB(t)

	agent, _, err := db.CreateAgent("key-bot", "generic", "", "tools:read", "operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	found, err := db.GetAgentByApiKeyID(agent.ApiKeyID)
	if err != nil {
		t.Fatalf("GetAgentByApiKeyID: %v", err)
	}
	if found.Name != "key-bot" {
		t.Errorf("name = %q, want key-bot", found.Name)
	}
}

func TestUpdateAgentStatus(t *testing.T) {
	db := testDB(t)

	_, _, err := db.CreateAgent("status-bot", "generic", "", "tools:read", "operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Suspend
	if err := db.UpdateAgentStatus("status-bot", "suspended"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	agent, _ := db.GetAgentByName("status-bot")
	if agent.Status != "suspended" {
		t.Errorf("status = %q, want suspended", agent.Status)
	}

	// Revoke
	if err := db.UpdateAgentStatus("status-bot", "revoked"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	agent, _ = db.GetAgentByName("status-bot")
	if agent.Status != "revoked" {
		t.Errorf("status = %q, want revoked", agent.Status)
	}

	// Nonexistent
	if err := db.UpdateAgentStatus("ghost", "suspended"); err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestResolveIdentityAgent(t *testing.T) {
	db := testDB(t)

	_, rawKey, err := db.CreateAgent("resolve-bot", "generic", "", "tools:read,tools:execute", "operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	identity, authResult := db.ResolveIdentity(rawKey)
	if identity == nil {
		t.Fatal("ResolveIdentity returned nil")
	}
	if authResult == nil {
		t.Fatal("AuthResult returned nil")
	}
	if !identity.IsAgent {
		t.Error("expected IsAgent = true")
	}
	if identity.AgentName != "resolve-bot" {
		t.Errorf("AgentName = %q, want resolve-bot", identity.AgentName)
	}
	if len(identity.Scopes) != 2 {
		t.Errorf("got %d scopes, want 2", len(identity.Scopes))
	}
}

func TestResolveIdentityRawKey(t *testing.T) {
	db := testDB(t)

	// Create a raw API key (not attached to any agent)
	rawKey, err := db.GenerateApiKey("test-key", "user_1", "tools:admin")
	if err != nil {
		t.Fatalf("GenerateApiKey: %v", err)
	}

	identity, authResult := db.ResolveIdentity(rawKey)
	if identity == nil {
		t.Fatal("ResolveIdentity returned nil")
	}
	if authResult == nil {
		t.Fatal("AuthResult returned nil")
	}
	if identity.IsAgent {
		t.Error("expected IsAgent = false for raw API key")
	}
	if identity.AgentID != "" {
		t.Errorf("AgentID should be empty, got %q", identity.AgentID)
	}
}

func TestResolveIdentitySuspendedAgent(t *testing.T) {
	db := testDB(t)

	_, rawKey, err := db.CreateAgent("sus-bot", "generic", "", "tools:read", "operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	db.UpdateAgentStatus("sus-bot", "suspended")

	identity, _ := db.ResolveIdentity(rawKey)
	if identity == nil {
		t.Fatal("ResolveIdentity returned nil (key should still be valid)")
	}
	if identity.IsAgent {
		t.Error("suspended agent should not resolve as IsAgent")
	}
}

func TestResolveIdentityRevokedAgent(t *testing.T) {
	db := testDB(t)

	_, rawKey, err := db.CreateAgent("rev-bot", "generic", "", "tools:read", "operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	db.UpdateAgentStatus("rev-bot", "revoked")

	identity, _ := db.ResolveIdentity(rawKey)
	if identity != nil {
		t.Error("revoked agent key should return nil identity")
	}
}

func TestResolveIdentityBadToken(t *testing.T) {
	db := testDB(t)

	identity, _ := db.ResolveIdentity("qk_nonexistent")
	if identity != nil {
		t.Error("bad token should return nil")
	}
}

func TestResolveAgentByName(t *testing.T) {
	db := testDB(t)

	_, _, err := db.CreateAgent("named-bot", "generic", "", "tools:read", "operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	identity, err := db.ResolveAgentByName("named-bot")
	if err != nil {
		t.Fatalf("ResolveAgentByName: %v", err)
	}
	if !identity.IsAgent {
		t.Error("expected IsAgent = true")
	}
	if identity.AgentName != "named-bot" {
		t.Errorf("AgentName = %q, want named-bot", identity.AgentName)
	}

	// Suspended agent
	db.UpdateAgentStatus("named-bot", "suspended")
	_, err = db.ResolveAgentByName("named-bot")
	if err == nil {
		t.Error("expected error for suspended agent")
	}

	// Nonexistent
	_, err = db.ResolveAgentByName("ghost")
	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestOpenDBCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	db, err := OpenDB(dir)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	db.Close()

	if _, err := os.Stat(filepath.Join(dir, "auth.db")); err != nil {
		t.Errorf("auth.db not created: %v", err)
	}
}
