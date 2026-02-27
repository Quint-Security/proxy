package risk

import (
	"testing"
	"time"
)

func TestSessionTracker_RecordAndRecent(t *testing.T) {
	tracker := NewSessionTracker(5, 10*time.Minute)

	tracker.Record("agent-1", "mcp:github:list_repos.list")
	tracker.Record("agent-1", "mcp:github:create_file.create")
	tracker.Record("agent-1", "mcp:slack:send_message.send")

	recent := tracker.Recent("agent-1")
	if len(recent) != 3 {
		t.Fatalf("expected 3 recent actions, got %d", len(recent))
	}
	if recent[0] != "mcp:github:list_repos.list" {
		t.Errorf("expected first action mcp:github:list_repos.list, got %s", recent[0])
	}
	if recent[2] != "mcp:slack:send_message.send" {
		t.Errorf("expected last action mcp:slack:send_message.send, got %s", recent[2])
	}
}

func TestSessionTracker_MaxActions(t *testing.T) {
	tracker := NewSessionTracker(3, 10*time.Minute)

	tracker.Record("agent-1", "action-1")
	tracker.Record("agent-1", "action-2")
	tracker.Record("agent-1", "action-3")
	tracker.Record("agent-1", "action-4")
	tracker.Record("agent-1", "action-5")

	recent := tracker.Recent("agent-1")
	if len(recent) != 3 {
		t.Fatalf("expected 3 recent actions (max), got %d", len(recent))
	}
	if recent[0] != "action-3" {
		t.Errorf("expected oldest kept action action-3, got %s", recent[0])
	}
}

func TestSessionTracker_WindowExpiry(t *testing.T) {
	tracker := NewSessionTracker(20, 50*time.Millisecond)

	tracker.Record("agent-1", "old-action")
	time.Sleep(60 * time.Millisecond)
	tracker.Record("agent-1", "new-action")

	recent := tracker.Recent("agent-1")
	if len(recent) != 1 {
		t.Fatalf("expected 1 recent action (old expired), got %d", len(recent))
	}
	if recent[0] != "new-action" {
		t.Errorf("expected new-action, got %s", recent[0])
	}
}

func TestSessionTracker_SeparateSessions(t *testing.T) {
	tracker := NewSessionTracker(20, 10*time.Minute)

	tracker.Record("agent-1", "action-a")
	tracker.Record("agent-2", "action-b")

	r1 := tracker.Recent("agent-1")
	r2 := tracker.Recent("agent-2")

	if len(r1) != 1 || r1[0] != "action-a" {
		t.Errorf("agent-1 expected [action-a], got %v", r1)
	}
	if len(r2) != 1 || r2[0] != "action-b" {
		t.Errorf("agent-2 expected [action-b], got %v", r2)
	}
}

func TestSessionTracker_EmptySession(t *testing.T) {
	tracker := NewSessionTracker(20, 10*time.Minute)

	recent := tracker.Recent("nonexistent")
	if recent != nil {
		t.Errorf("expected nil for unknown session, got %v", recent)
	}
}
