package intercept

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// AddSignal basics
// ---------------------------------------------------------------------------

func TestCorrelationEngine_AddSignal_NewRelationship(t *testing.T) {
	ce := NewCorrelationEngine()

	rel := ce.AddSignal(RelationshipSignal{
		Type:        SignalSpawn,
		ParentAgent: "parent-1",
		ChildAgent:  "child-1",
		Confidence:  0.85,
		Source:      "test-pattern",
		Timestamp:   time.Now(),
	})

	if rel == nil {
		t.Fatal("expected relationship")
	}
	if rel.ParentAgent != "parent-1" || rel.ChildAgent != "child-1" {
		t.Errorf("agents: %s→%s", rel.ParentAgent, rel.ChildAgent)
	}
	if rel.Confidence != 0.85 {
		t.Errorf("confidence=%f, want 0.85", rel.Confidence)
	}
	if rel.SignalCount != 1 {
		t.Errorf("signal_count=%d, want 1", rel.SignalCount)
	}
	if rel.Depth != 1 {
		t.Errorf("depth=%d, want 1", rel.Depth)
	}
}

func TestCorrelationEngine_AddSignal_MergesConfidence(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "p", ChildAgent: "c",
		Confidence: 0.70, Timestamp: now,
	})
	rel := ce.AddSignal(RelationshipSignal{
		Type: SignalContext, ParentAgent: "p", ChildAgent: "c",
		Confidence: 0.95, Timestamp: now.Add(time.Second),
	})

	if rel.SignalCount != 2 {
		t.Errorf("signal_count=%d, want 2", rel.SignalCount)
	}
	// Merged confidence should be >= max(0.70, 0.95)
	if rel.Confidence < 0.95 {
		t.Errorf("merged confidence=%f, should be >= 0.95", rel.Confidence)
	}
}

// ---------------------------------------------------------------------------
// AddSpawnEvent with temporal deduplication
// ---------------------------------------------------------------------------

func TestCorrelationEngine_AddSpawnEvent_Basic(t *testing.T) {
	ce := NewCorrelationEngine()

	ev := &SpawnEvent{
		PatternID:   "openai-handoff",
		ParentAgent: "parent-1",
		ChildHint:   "child-agent",
		SpawnType:   "delegation",
		Confidence:  0.90,
		ToolName:    "transfer_to_child",
		ServerName:  "openai",
		DetectedAt:  time.Now(),
	}

	rel := ce.AddSpawnEvent(ev)
	if rel == nil {
		t.Fatal("expected relationship from spawn event")
	}
	if rel.ChildAgent != "child-agent" {
		t.Errorf("child=%s, want child-agent", rel.ChildAgent)
	}
	if rel.SpawnType != "delegation" {
		t.Errorf("spawn_type=%s, want delegation", rel.SpawnType)
	}
}

func TestCorrelationEngine_AddSpawnEvent_DedupSuppressesDuplicates(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	ev1 := &SpawnEvent{
		PatternID:   "shell-agent-spawn",
		ParentAgent: "parent-1",
		ChildHint:   "child:shell:exec:abc123",
		SpawnType:   "fork",
		Confidence:  0.70,
		ToolName:    "exec",
		ServerName:  "shell",
		DetectedAt:  now,
	}

	// First call — should succeed
	rel := ce.AddSpawnEvent(ev1)
	if rel == nil {
		t.Fatal("first spawn event should create relationship")
	}

	// Second call within dedup window (same parent+tool+pattern) — should be suppressed
	ev2 := &SpawnEvent{
		PatternID:   "shell-agent-spawn",
		ParentAgent: "parent-1",
		ChildHint:   "child:shell:exec:def456",
		SpawnType:   "fork",
		Confidence:  0.70,
		ToolName:    "exec",
		ServerName:  "shell",
		DetectedAt:  now.Add(500 * time.Millisecond), // within 2s window
	}

	rel2 := ce.AddSpawnEvent(ev2)
	if rel2 != nil {
		t.Error("second spawn within dedup window should be suppressed")
	}
}

func TestCorrelationEngine_AddSpawnEvent_DedupAllowsAfterWindow(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	ev1 := &SpawnEvent{
		PatternID:   "shell-agent-spawn",
		ParentAgent: "parent-1",
		ChildHint:   "child-1",
		Confidence:  0.70,
		ToolName:    "exec",
		DetectedAt:  now,
	}

	rel := ce.AddSpawnEvent(ev1)
	if rel == nil {
		t.Fatal("first event should create relationship")
	}

	// After dedup window — should succeed
	ev2 := &SpawnEvent{
		PatternID:   "shell-agent-spawn",
		ParentAgent: "parent-1",
		ChildHint:   "child-2",
		Confidence:  0.70,
		ToolName:    "exec",
		DetectedAt:  now.Add(3 * time.Second), // beyond 2s window
	}

	rel2 := ce.AddSpawnEvent(ev2)
	if rel2 == nil {
		t.Error("spawn after dedup window should not be suppressed")
	}
}

func TestCorrelationEngine_AddSpawnEvent_DifferentToolsNotDeduplicated(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	ev1 := &SpawnEvent{
		PatternID:   "shell-agent-spawn",
		ParentAgent: "parent-1",
		ChildHint:   "child-1",
		Confidence:  0.70,
		ToolName:    "exec_command",
		DetectedAt:  now,
	}

	ev2 := &SpawnEvent{
		PatternID:   "generic-create-agent",
		ParentAgent: "parent-1",
		ChildHint:   "child-2",
		Confidence:  0.85,
		ToolName:    "create_agent",
		DetectedAt:  now.Add(100 * time.Millisecond), // within 2s but different tool+pattern
	}

	rel1 := ce.AddSpawnEvent(ev1)
	rel2 := ce.AddSpawnEvent(ev2)

	if rel1 == nil || rel2 == nil {
		t.Fatal("different tools should not be deduplicated")
	}
}

func TestCorrelationEngine_AddSpawnEvent_DifferentParentsNotDeduplicated(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	ev1 := &SpawnEvent{
		PatternID:   "openai-handoff",
		ParentAgent: "parent-1",
		ChildHint:   "child-a",
		Confidence:  0.90,
		ToolName:    "transfer_to_alice",
		DetectedAt:  now,
	}

	ev2 := &SpawnEvent{
		PatternID:   "openai-handoff",
		ParentAgent: "parent-2", // different parent
		ChildHint:   "child-b",
		Confidence:  0.90,
		ToolName:    "transfer_to_alice",
		DetectedAt:  now.Add(100 * time.Millisecond),
	}

	rel1 := ce.AddSpawnEvent(ev1)
	rel2 := ce.AddSpawnEvent(ev2)

	if rel1 == nil || rel2 == nil {
		t.Fatal("different parents should not be deduplicated")
	}
}

func TestCorrelationEngine_AddSpawnEvent_NilEvent(t *testing.T) {
	ce := NewCorrelationEngine()
	rel := ce.AddSpawnEvent(nil)
	if rel != nil {
		t.Error("nil event should return nil")
	}
}

// ---------------------------------------------------------------------------
// ChildCount
// ---------------------------------------------------------------------------

func TestCorrelationEngine_ChildCount(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	// Add 3 distinct children for parent-1
	for i := 0; i < 3; i++ {
		ce.AddSignal(RelationshipSignal{
			Type:        SignalSpawn,
			ParentAgent: "parent-1",
			ChildAgent:  fmt.Sprintf("child-%d", i),
			Confidence:  0.85,
			Timestamp:   now.Add(time.Duration(i) * time.Second),
		})
	}

	// Add 1 child for parent-2
	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "parent-2", ChildAgent: "child-x",
		Confidence: 0.85, Timestamp: now,
	})

	if count := ce.ChildCount("parent-1"); count != 3 {
		t.Errorf("parent-1 child count=%d, want 3", count)
	}
	if count := ce.ChildCount("parent-2"); count != 1 {
		t.Errorf("parent-2 child count=%d, want 1", count)
	}
	if count := ce.ChildCount("nonexistent"); count != 0 {
		t.Errorf("nonexistent child count=%d, want 0", count)
	}
}

func TestCorrelationEngine_ChildCount_NoDuplicates(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	// Same parent→child signal sent 5 times
	for i := 0; i < 5; i++ {
		ce.AddSignal(RelationshipSignal{
			Type:        SignalSpawn,
			ParentAgent: "parent-1",
			ChildAgent:  "same-child",
			Confidence:  0.85,
			Timestamp:   now.Add(time.Duration(i) * time.Second),
		})
	}

	if count := ce.ChildCount("parent-1"); count != 1 {
		t.Errorf("child count=%d, want 1 (same child counted once)", count)
	}

	// But signal count should be 5
	rel := ce.GetRelationship("parent-1", "same-child")
	if rel == nil {
		t.Fatal("expected relationship")
	}
	if rel.SignalCount != 5 {
		t.Errorf("signal_count=%d, want 5", rel.SignalCount)
	}
}

// ---------------------------------------------------------------------------
// Child count accuracy — the miscounting scenario
// ---------------------------------------------------------------------------

func TestCorrelationEngine_ChildCount_AccurateForDistinctSpawns(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	// Simulate a parent spawning 5 distinct children via different tools
	children := []struct {
		tool  string
		child string
	}{
		{"transfer_to_alice", "alice"},
		{"transfer_to_bob", "bob"},
		{"create_agent", "worker-1"},
		{"delegate_work", "analyst"},
		{"send_task", "processor"},
	}

	for i, c := range children {
		ev := &SpawnEvent{
			PatternID:   "test",
			ParentAgent: "orchestrator",
			ChildHint:   c.child,
			SpawnType:   "delegation",
			Confidence:  0.85,
			ToolName:    c.tool,
			DetectedAt:  now.Add(time.Duration(i) * 3 * time.Second), // spaced beyond dedup window
		}
		ce.AddSpawnEvent(ev)
	}

	count := ce.ChildCount("orchestrator")
	if count != 5 {
		t.Errorf("expected exactly 5 children, got %d", count)
	}
}

func TestCorrelationEngine_ChildCount_RapidDuplicatesNotOvercounted(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	// Simulate rapid duplicate spawns (the old bug: 15 counted when only 5)
	// Same parent calls exec_command 15 times rapidly
	for i := 0; i < 15; i++ {
		ev := &SpawnEvent{
			PatternID:   "shell-agent-spawn",
			ParentAgent: "parent-1",
			ChildHint:   fmt.Sprintf("child:shell:exec:%d", i),
			SpawnType:   "fork",
			Confidence:  0.70,
			ToolName:    "exec_command",
			DetectedAt:  now.Add(time.Duration(i) * 100 * time.Millisecond), // 100ms apart — within dedup window
		}
		ce.AddSpawnEvent(ev)
	}

	count := ce.ChildCount("parent-1")
	if count > 1 {
		t.Errorf("rapid duplicate spawns should be deduplicated: got %d children, want 1", count)
	}
}

// ---------------------------------------------------------------------------
// Depth tracking
// ---------------------------------------------------------------------------

func TestCorrelationEngine_DepthTracking(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	// Root spawns child-1 (depth 1)
	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "root", ChildAgent: "child-1",
		Confidence: 0.9, Timestamp: now,
	})
	if depth := ce.GetDepth("child-1"); depth != 1 {
		t.Errorf("child-1 depth=%d, want 1", depth)
	}

	// child-1 spawns child-2 (depth 2)
	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "child-1", ChildAgent: "child-2",
		Confidence: 0.9, Timestamp: now.Add(time.Second),
	})
	if depth := ce.GetDepth("child-2"); depth != 2 {
		t.Errorf("child-2 depth=%d, want 2", depth)
	}

	// child-2 spawns child-3 (depth 3)
	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "child-2", ChildAgent: "child-3",
		Confidence: 0.9, Timestamp: now.Add(2 * time.Second),
	})
	if depth := ce.GetDepth("child-3"); depth != 3 {
		t.Errorf("child-3 depth=%d, want 3", depth)
	}
}

func TestCorrelationEngine_GetDepth_UnknownAgent(t *testing.T) {
	ce := NewCorrelationEngine()
	if depth := ce.GetDepth("nonexistent"); depth != 0 {
		t.Errorf("unknown agent depth=%d, want 0", depth)
	}
}

// ---------------------------------------------------------------------------
// GetParent / GetChildren
// ---------------------------------------------------------------------------

func TestCorrelationEngine_GetParent(t *testing.T) {
	ce := NewCorrelationEngine()
	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "root", ChildAgent: "child-1",
		Confidence: 0.9, Timestamp: time.Now(),
	})

	parent := ce.GetParent("child-1")
	if parent == nil {
		t.Fatal("expected parent for child-1")
	}
	if parent.ParentAgent != "root" {
		t.Errorf("parent=%s, want root", parent.ParentAgent)
	}

	// Root has no parent
	if p := ce.GetParent("root"); p != nil {
		t.Error("root should have no parent")
	}
}

func TestCorrelationEngine_GetChildren(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "root", ChildAgent: "child-1",
		Confidence: 0.9, Timestamp: now,
	})
	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "root", ChildAgent: "child-2",
		Confidence: 0.9, Timestamp: now.Add(time.Second),
	})

	children := ce.GetChildren("root")
	if len(children) != 2 {
		t.Errorf("expected 2 children, got %d", len(children))
	}
}

// ---------------------------------------------------------------------------
// AllRelationships
// ---------------------------------------------------------------------------

func TestCorrelationEngine_AllRelationships(t *testing.T) {
	ce := NewCorrelationEngine()
	now := time.Now()

	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "p1", ChildAgent: "c1",
		Confidence: 0.8, Timestamp: now,
	})
	ce.AddSignal(RelationshipSignal{
		Type: SignalSpawn, ParentAgent: "p2", ChildAgent: "c2",
		Confidence: 0.9, Timestamp: now,
	})

	all := ce.AllRelationships()
	if len(all) != 2 {
		t.Errorf("expected 2 relationships, got %d", len(all))
	}
}

// ---------------------------------------------------------------------------
// Signature signal (HMAC-verified spawn ticket)
// ---------------------------------------------------------------------------

func TestCorrelationEngine_AddSignatureSignal(t *testing.T) {
	ce := NewCorrelationEngine()

	rel := ce.AddSignatureSignal("parent-1", "child-verified", "trace-123", 2, "delegation")
	if rel == nil {
		t.Fatal("expected relationship")
	}
	if rel.Confidence != 1.0 {
		t.Errorf("signature confidence=%f, want 1.0", rel.Confidence)
	}
	if rel.Depth != 2 {
		t.Errorf("depth=%d, want 2", rel.Depth)
	}
	if rel.SpawnType != "delegation" {
		t.Errorf("spawn_type=%s, want delegation", rel.SpawnType)
	}
}

// ---------------------------------------------------------------------------
// mergeConfidence
// ---------------------------------------------------------------------------

func TestMergeConfidence(t *testing.T) {
	tests := []struct {
		existing, new float64
		wantMin       float64
	}{
		{0.70, 0.95, 0.95},  // max is 0.95
		{0.95, 0.70, 0.95},  // same
		{0.50, 0.50, 0.50},  // equal
		{0.99, 0.99, 0.99},  // high
		{1.0, 1.0, 1.0},     // max
	}

	for _, tt := range tests {
		got := mergeConfidence(tt.existing, tt.new)
		if got < tt.wantMin {
			t.Errorf("mergeConfidence(%f, %f) = %f, want >= %f", tt.existing, tt.new, got, tt.wantMin)
		}
		if got > 1.0 {
			t.Errorf("mergeConfidence(%f, %f) = %f, should not exceed 1.0", tt.existing, tt.new, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestCorrelationEngine_ConcurrentAccess(t *testing.T) {
	ce := NewCorrelationEngine()
	var wg sync.WaitGroup

	// Spawn 20 goroutines adding signals concurrently
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ev := &SpawnEvent{
				PatternID:   "test",
				ParentAgent: fmt.Sprintf("parent-%d", idx%5),
				ChildHint:   fmt.Sprintf("child-%d", idx),
				SpawnType:   "delegation",
				Confidence:  0.85,
				ToolName:    fmt.Sprintf("tool-%d", idx),
				DetectedAt:  time.Now().Add(time.Duration(idx) * 3 * time.Second),
			}
			ce.AddSpawnEvent(ev)

			// Also read concurrently
			ce.ChildCount(fmt.Sprintf("parent-%d", idx%5))
			ce.GetDepth(fmt.Sprintf("child-%d", idx))
			ce.AllRelationships()
		}(i)
	}

	wg.Wait()

	// No panic = success. Also check consistency.
	all := ce.AllRelationships()
	if len(all) == 0 {
		t.Error("expected some relationships after concurrent access")
	}
}
