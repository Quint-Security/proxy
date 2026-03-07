package forwardproxy

import (
	"testing"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/auth"
)

func TestTunnelTracker_NewSessionAfterAllClosed(t *testing.T) {
	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)

	// Use a very short burst window (50ms) so we don't need big sleeps.
	tracker := newTunnelTracker(50)

	key := "127.0.0.1:claude-code:anthropic"
	baseIdentity := resolver.ResolveForHTTP("127.0.0.1:50000", "claude-code/1.0", "anthropic")
	if baseIdentity == nil {
		t.Fatal("expected non-nil base identity")
	}

	// Session 1: open a tunnel
	id1, _, isNew := tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", false)
	if isNew {
		t.Error("first resolve should not be new")
	}
	if id1.AgentName != baseIdentity.AgentName {
		t.Errorf("first resolve should return base identity, got %q vs %q", id1.AgentName, baseIdentity.AgentName)
	}

	// Close all tunnels (session ends)
	tracker.release(key)

	// Wait longer than burst window
	time.Sleep(80 * time.Millisecond)

	// Session 2: new CONNECT arrives — should get a NEW identity
	id2, _, isNew := tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", false)
	if !isNew {
		t.Error("resolve after session gap should detect new session")
	}
	if id2.AgentName == id1.AgentName {
		t.Errorf("new session should get different identity, both got %q", id1.AgentName)
	}
	if id2.AgentID == id1.AgentID {
		t.Errorf("new session should get different agent ID, both got %q", id1.AgentID)
	}

	t.Logf("Session 1: %s (%s)", id1.AgentName, id1.AgentID)
	t.Logf("Session 2: %s (%s)", id2.AgentName, id2.AgentID)
}

func TestTunnelTracker_RapidReconnectSameSession(t *testing.T) {
	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)

	// 200ms burst window
	tracker := newTunnelTracker(200)

	key := "127.0.0.1:claude-code:anthropic"
	baseIdentity := resolver.ResolveForHTTP("127.0.0.1:50000", "claude-code/1.0", "anthropic")

	// Open and close a tunnel
	id1, _, _ := tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", false)
	tracker.release(key)

	// Reconnect immediately (within burst window) — should reuse identity
	id2, _, isNew := tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", false)
	if isNew {
		t.Error("rapid reconnect should NOT create a new session")
	}
	if id2.AgentName != id1.AgentName {
		t.Errorf("rapid reconnect should reuse identity, got %q vs %q", id2.AgentName, id1.AgentName)
	}
}

func TestTunnelTracker_MultipleSessions(t *testing.T) {
	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)

	tracker := newTunnelTracker(50)

	key := "127.0.0.1:claude-code:anthropic"
	baseIdentity := resolver.ResolveForHTTP("127.0.0.1:50000", "claude-code/1.0", "anthropic")

	sessions := make([]*auth.Identity, 0, 4)

	for i := 0; i < 4; i++ {
		id, _, _ := tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", false)
		sessions = append(sessions, id)
		tracker.release(key)
		time.Sleep(80 * time.Millisecond) // gap > burst window
	}

	// Each session should have a distinct identity
	seen := make(map[string]bool)
	for i, s := range sessions {
		if seen[s.AgentID] {
			t.Errorf("session %d reused agent ID %s", i, s.AgentID)
		}
		seen[s.AgentID] = true
		t.Logf("Session %d: %s (%s)", i+1, s.AgentName, s.AgentID)
	}

	// First session uses the base identity
	if sessions[0].AgentID != baseIdentity.AgentID {
		t.Errorf("first session should use base identity")
	}
}

func TestTunnelTracker_ResolveForHTTP_UpdatedAfterRotation(t *testing.T) {
	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)

	tracker := newTunnelTracker(50)

	key := "127.0.0.1:claude-code:anthropic"
	baseIdentity := resolver.ResolveForHTTP("127.0.0.1:50000", "claude-code/1.0", "anthropic")

	// Session 1
	tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", false)
	tracker.release(key)
	time.Sleep(80 * time.Millisecond)

	// Session 2 — triggers identity rotation
	id2, _, _ := tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", false)

	// ResolveForHTTP should now return the rotated identity
	cached := resolver.ResolveForHTTP("127.0.0.1:50000", "claude-code/1.0", "anthropic")
	if cached.AgentID != id2.AgentID {
		t.Errorf("ResolveForHTTP should return rotated identity, got %q want %q",
			cached.AgentID, id2.AgentID)
	}
}

func TestTunnelTracker_ChildStillWorksWithActiveTunnels(t *testing.T) {
	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)

	// 50ms burst window
	tracker := newTunnelTracker(50)

	key := "127.0.0.1:claude-code:anthropic"
	baseIdentity := resolver.ResolveForHTTP("127.0.0.1:50000", "claude-code/1.0", "anthropic")

	// Parent session still active
	parentID, _, _ := tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", false)

	// Wait past burst window
	time.Sleep(80 * time.Millisecond)

	// New CONNECT with parent still active and trace header → child
	childID, parentAgentID, isNew := tracker.resolve(key, baseIdentity, resolver, "claude-code/1.0", true)
	if !isNew {
		t.Error("should detect child agent")
	}
	if childID.AgentID == parentID.AgentID {
		t.Error("child should have different ID than parent")
	}
	if parentAgentID == "" {
		t.Error("child should report parent agent ID")
	}

	t.Logf("Parent: %s, Child: %s (parent=%s)", parentID.AgentName, childID.AgentName, parentAgentID)
}
