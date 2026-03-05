package forwardproxy

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

func setupTestProxy(t *testing.T) *Proxy {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")

	authDB, err := auth.OpenDB(dataDir)
	if err != nil {
		t.Fatalf("open auth db: %v", err)
	}
	t.Cleanup(func() { authDB.Close() })

	auditDB, err := audit.OpenDB(dataDir)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { auditDB.Close() })

	logger := audit.NewLogger(auditDB, "", "", nil)

	return &Proxy{
		logger:            logger,
		auditDB:           auditDB,
		authDB:            authDB,
		identityResolver:  NewIdentityResolver(authDB),
		correlationEngine: intercept.NewCorrelationEngine(),
		tunnelTracker:     newTunnelTracker(2000),
	}
}

func TestAssignTrace(t *testing.T) {
	p := setupTestProxy(t)

	identity := &auth.Identity{
		AgentID:   "agent-123",
		AgentName: "claude-code-1",
		SubjectID: "subject-123",
	}

	tc := p.assignTrace(identity)
	if tc == nil {
		t.Fatal("expected non-nil trace context")
	}
	if tc.TraceID == "" {
		t.Error("expected non-empty trace ID")
	}
	if tc.Depth != 0 {
		t.Errorf("expected depth 0, got %d", tc.Depth)
	}

	// Verify trace map stores the mapping
	val, ok := p.traceMap.Load(tc.TraceID)
	if !ok {
		t.Fatal("expected trace ID to be stored in traceMap")
	}
	if val.(string) != "agent-123" {
		t.Errorf("expected agentID %q in traceMap, got %q", "agent-123", val.(string))
	}
}

func TestAssignTrace_SameAgentReuseTrace(t *testing.T) {
	p := setupTestProxy(t)

	identity := &auth.Identity{
		AgentID:   "agent-reuse",
		AgentName: "claude-code-1",
		SubjectID: "subject-reuse",
	}

	tc1 := p.assignTrace(identity)
	tc2 := p.assignTrace(identity)
	tc3 := p.assignTrace(identity)

	// All calls should return the same trace context
	if tc1.TraceID != tc2.TraceID || tc2.TraceID != tc3.TraceID {
		t.Errorf("expected same trace for same agent, got %q, %q, %q", tc1.TraceID, tc2.TraceID, tc3.TraceID)
	}
}

func TestAssignTrace_DifferentAgentsGetDifferentTraces(t *testing.T) {
	p := setupTestProxy(t)

	id1 := &auth.Identity{AgentID: "agent-a"}
	id2 := &auth.Identity{AgentID: "agent-b"}

	tc1 := p.assignTrace(id1)
	tc2 := p.assignTrace(id2)

	if tc1.TraceID == tc2.TraceID {
		t.Error("different agents should get different trace IDs")
	}
}

func TestAssignTrace_NilIdentity(t *testing.T) {
	p := setupTestProxy(t)

	tc := p.assignTrace(nil)
	if tc == nil {
		t.Fatal("expected non-nil trace context even for nil identity")
	}
	if tc.TraceID == "" {
		t.Error("expected non-empty trace ID")
	}

	// Should NOT store in traceMap when identity is nil
	_, ok := p.traceMap.Load(tc.TraceID)
	if ok {
		t.Error("expected no traceMap entry for nil identity")
	}
}

func TestResolveParentFromTrace_NoHeader(t *testing.T) {
	p := setupTestProxy(t)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	parentID, tc := p.resolveParentFromTrace(req)

	if parentID != "" {
		t.Errorf("expected empty parentID, got %q", parentID)
	}
	if tc != nil {
		t.Errorf("expected nil trace context, got %+v", tc)
	}
}

func TestResolveParentFromTrace_WithHeader(t *testing.T) {
	p := setupTestProxy(t)

	// First, create a parent agent and assign a trace
	parentIdentity := &auth.Identity{AgentID: "parent-agent-1"}
	parentTC := p.assignTrace(parentIdentity)

	// Now simulate a child request with the parent's trace header
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("X-Quint-Trace", parentTC.String())

	parentID, tc := p.resolveParentFromTrace(req)

	if parentID != "parent-agent-1" {
		t.Errorf("expected parent %q, got %q", "parent-agent-1", parentID)
	}
	if tc == nil {
		t.Fatal("expected non-nil trace context")
	}
	if tc.TraceID != parentTC.TraceID {
		t.Errorf("expected trace ID %q, got %q", parentTC.TraceID, tc.TraceID)
	}
	if tc.Depth != 0 {
		t.Errorf("expected parsed depth 0, got %d", tc.Depth)
	}
}

func TestTraceDepthIncrement(t *testing.T) {
	p := setupTestProxy(t)

	// Parent at depth 0
	parentIdentity := &auth.Identity{AgentID: "parent-1"}
	parentTC := p.assignTrace(parentIdentity)
	if parentTC.Depth != 0 {
		t.Fatalf("expected parent depth 0, got %d", parentTC.Depth)
	}

	// Simulate child request
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("X-Quint-Trace", parentTC.String())

	parentID, tc := p.resolveParentFromTrace(req)
	if parentID == "" {
		t.Fatal("expected non-empty parent ID")
	}

	// Child depth should be parent depth + 1
	childDepth := tc.Depth + 1
	childTC := &intercept.TraceContext{TraceID: tc.TraceID, Depth: childDepth}

	if childTC.Depth != 1 {
		t.Errorf("expected child depth 1, got %d", childTC.Depth)
	}

	// Simulate grandchild with child's trace
	req2, _ := http.NewRequest("GET", "https://example.com", nil)
	req2.Header.Set("X-Quint-Trace", childTC.String())

	// Store child in trace map so grandchild can resolve
	p.traceMap.Store(childTC.TraceID, "child-1")

	parentID2, tc2 := p.resolveParentFromTrace(req2)
	if parentID2 != "child-1" {
		t.Errorf("expected parent %q, got %q", "child-1", parentID2)
	}
	grandchildDepth := tc2.Depth + 1
	if grandchildDepth != 2 {
		t.Errorf("expected grandchild depth 2, got %d", grandchildDepth)
	}
}

func TestResolveParentFromTrace_UnknownTraceID(t *testing.T) {
	p := setupTestProxy(t)

	// Send a trace header with a trace ID not in our map
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("X-Quint-Trace", "unknown-trace-id.0")

	parentID, tc := p.resolveParentFromTrace(req)

	// Trace context should be parsed but parent should be empty
	if parentID != "" {
		t.Errorf("expected empty parentID for unknown trace, got %q", parentID)
	}
	if tc == nil {
		t.Fatal("expected non-nil trace context")
	}
	if tc.TraceID != "unknown-trace-id" {
		t.Errorf("expected trace ID %q, got %q", "unknown-trace-id", tc.TraceID)
	}
}

func TestTraceInjection_HeaderFormat(t *testing.T) {
	// Verify the trace context string format matches X-Quint-Trace spec
	tc := &intercept.TraceContext{TraceID: "abc-123", Depth: 2}
	got := tc.String()
	want := "abc-123.2"
	if got != want {
		t.Errorf("trace header = %q, want %q", got, want)
	}
}

func TestTunnelIdentity_SameIPReusesAgent(t *testing.T) {
	p := setupTestProxy(t)

	// Simulate multiple TCP connections from the same source IP (different ports).
	// All should resolve to the same agent identity.
	id1 := p.identityResolver.ResolveForHTTP("192.168.1.100:50001", "claude-code/1.2.3 node/20", "")
	id2 := p.identityResolver.ResolveForHTTP("192.168.1.100:50002", "claude-code/1.2.3 node/20", "")
	id3 := p.identityResolver.ResolveForHTTP("192.168.1.100:50003", "claude-code/1.2.3 node/20", "")

	if id1 == nil || id2 == nil || id3 == nil {
		t.Fatal("expected non-nil identities")
	}
	if id1.AgentID != id2.AgentID || id2.AgentID != id3.AgentID {
		t.Errorf("same IP should reuse identity: got %q, %q, %q", id1.AgentName, id2.AgentName, id3.AgentName)
	}
}

func TestTunnelIdentity_ChildGetsNewAgent(t *testing.T) {
	p := setupTestProxy(t)

	// Parent connects — gets IP-cached identity
	parentID := p.identityResolver.ResolveForHTTP("127.0.0.1:50001", "claude-code/1.2.3", "")
	if parentID == nil {
		t.Fatal("expected non-nil parent identity")
	}

	// Child connects from same IP but should get a NEW identity
	childID := p.identityResolver.ResolveFromHeaders("claude-code/1.2.3", "", "127.0.0.1:child-test")
	if childID == nil {
		t.Fatal("expected non-nil child identity")
	}

	if parentID.AgentID == childID.AgentID {
		t.Error("child should have a different agent ID than parent")
	}
	if parentID.AgentName == childID.AgentName {
		t.Errorf("child should have a different name: parent=%q child=%q", parentID.AgentName, childID.AgentName)
	}
}

func TestTunnelTracker_BurstIsSameAgent(t *testing.T) {
	p := setupTestProxy(t)
	parentID := p.identityResolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	// Rapid CONNECTs within burst window → same identity (using ip:toolName key)
	trackerKey := "10.0.0.1:claude-code"
	id1, pid1, new1 := p.tunnelTracker.resolve(trackerKey, parentID, p.identityResolver, "claude-code/1.0", false)
	id2, pid2, new2 := p.tunnelTracker.resolve(trackerKey, parentID, p.identityResolver, "claude-code/1.0", false)
	id3, pid3, new3 := p.tunnelTracker.resolve(trackerKey, parentID, p.identityResolver, "claude-code/1.0", false)

	if new1 || new2 || new3 {
		t.Error("rapid CONNECTs should not be new agents")
	}
	if pid1 != "" || pid2 != "" || pid3 != "" {
		t.Error("rapid CONNECTs should have no parent")
	}
	if id1.AgentID != id2.AgentID || id2.AgentID != id3.AgentID {
		t.Errorf("burst should reuse identity: got %q, %q, %q", id1.AgentName, id2.AgentName, id3.AgentName)
	}
}

func TestTunnelTracker_GapWithTrace_CreatesChild(t *testing.T) {
	// Temporal gap + parent trace → child subprocess named {parent}-child-{N}
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code"

	// First CONNECT establishes parent
	id1, _, isNew := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if isNew {
		t.Fatal("first CONNECT should not be new")
	}
	if id1.AgentID != parentID.AgentID {
		t.Errorf("first CONNECT should use parent identity: got %q, want %q", id1.AgentName, parentID.AgentName)
	}

	// Simulate temporal gap
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	// CONNECT with gap + parent trace → child
	id2, pid2, isNew2 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", true)
	if !isNew2 {
		t.Fatal("CONNECT after gap should be detected as new")
	}
	if pid2 != parentID.AgentID {
		t.Errorf("child parent should be %q, got %q", parentID.AgentID, pid2)
	}
	if id2.AgentID == parentID.AgentID {
		t.Error("child should have a different identity than parent")
	}
	// Verify derived child naming convention
	if !strings.HasPrefix(id2.AgentName, "derived_") {
		t.Errorf("child name should start with 'derived_', got %q", id2.AgentName)
	}
	if !strings.Contains(id2.AgentName, parentID.AgentName) {
		t.Errorf("child name should contain parent name %q, got %q", parentID.AgentName, id2.AgentName)
	}
}

func TestTunnelTracker_GapWithoutTrace_CreatesInferredChild(t *testing.T) {
	// Temporal gap + NO parent trace + active tunnels → inferred child (not peer)
	// This handles cases like Codex spawning sub-agents without X-Quint-Trace.
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code"

	// First CONNECT establishes first instance (activeTunnels=1)
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)

	// Simulate temporal gap (parent tunnel still active)
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	// CONNECT with gap + NO trace + active tunnels → inferred child
	child, childParent, isNew := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if !isNew {
		t.Fatal("CONNECT after gap should be detected as new")
	}
	if childParent == "" {
		t.Error("inferred child should have a parent")
	}
	if childParent != parentID.AgentID {
		t.Errorf("inferred child parent should be %q, got %q", parentID.AgentID, childParent)
	}
	if child.AgentID == parentID.AgentID {
		t.Error("inferred child should have a different identity than parent")
	}
	// Inferred child gets derived naming (like confirmed children)
	if !strings.HasPrefix(child.AgentName, "derived_") {
		t.Errorf("inferred child name should start with 'derived_', got %q", child.AgentName)
	}
	if child.Source != "inferred_child" {
		t.Errorf("inferred child Source should be 'inferred_child', got %q", child.Source)
	}
}

func TestTunnelTracker_ReleasedTunnelsResetToParent(t *testing.T) {
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code"

	// Establish parent
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)

	// Release all tunnels
	tracker.release(trackerKey)

	// Force gap
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	// Next CONNECT with 0 active tunnels + gap → should reuse parent (reconnect)
	id2, _, isNew := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if isNew {
		t.Error("reconnect after all tunnels closed should not be new")
	}
	if id2.AgentID != parentID.AgentID {
		t.Errorf("reconnect should use parent identity: got %q, want %q", id2.AgentName, parentID.AgentName)
	}
}

func TestTunnelTracker_ChildNaming(t *testing.T) {
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code"

	// Establish parent
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)

	// Simulate gap to create first child (with parent trace)
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	child1, _, isNew1 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", true)
	if !isNew1 {
		t.Fatal("expected new agent detection")
	}
	if !strings.HasPrefix(child1.AgentName, "derived_") {
		t.Errorf("child1 name should start with 'derived_', got %q", child1.AgentName)
	}

	// Simulate another gap for second child (with parent trace)
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	child2, _, isNew2 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", true)
	if !isNew2 {
		t.Fatal("expected new agent detection for second child")
	}
	if !strings.HasPrefix(child2.AgentName, "derived_") {
		t.Errorf("child2 name should start with 'derived_', got %q", child2.AgentName)
	}
	if child1.AgentName == child2.AgentName {
		t.Errorf("children should have different names, both got %q", child1.AgentName)
	}
}

func TestTunnelTracker_MixedChildrenTypes(t *testing.T) {
	// Verify that confirmed children (with trace) and inferred children (no trace)
	// both get parent links and derived naming, but with different Source values.
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code"

	// Establish first instance (activeTunnels=1)
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)

	// Inferred child (no trace, but parent active) → derived name + parent link
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()
	inferredChild, inferredParent, _ := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if inferredParent == "" {
		t.Error("inferred child should have a parent")
	}
	if inferredChild.Source != "inferred_child" {
		t.Errorf("inferred child Source should be 'inferred_child', got %q", inferredChild.Source)
	}

	// Confirmed child (with trace) → derived name + parent link
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()
	confirmedChild, confirmedParent, _ := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", true)
	if confirmedParent == "" {
		t.Error("confirmed child should have a parent")
	}

	// Both should be different from each other and from the original
	if inferredChild.AgentID == parentID.AgentID {
		t.Error("inferred child should differ from parent")
	}
	if confirmedChild.AgentID == parentID.AgentID {
		t.Error("confirmed child should differ from parent")
	}
	if inferredChild.AgentID == confirmedChild.AgentID {
		t.Error("inferred and confirmed children should differ from each other")
	}
	// Both should have derived naming
	if !strings.HasPrefix(inferredChild.AgentName, "derived_") {
		t.Errorf("inferred child should have derived name, got %q", inferredChild.AgentName)
	}
	if !strings.HasPrefix(confirmedChild.AgentName, "derived_") {
		t.Errorf("confirmed child should have derived name, got %q", confirmedChild.AgentName)
	}
}

// --- Concurrency-based sub-agent detection tests ---

func TestTunnelTracker_ConcurrentBurstDuringStabilization(t *testing.T) {
	// 4 CONNECTs within stabilization window → all same identity, peakTunnels=4
	tracker := newTunnelTracker(2000)

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code:anthropic"

	// 4 rapid CONNECTs within stabilization window
	var ids [4]*auth.Identity
	for i := 0; i < 4; i++ {
		id, parentAgent, isNew := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
		ids[i] = id
		if isNew {
			t.Errorf("CONNECT %d should not be new during stabilization", i)
		}
		if parentAgent != "" {
			t.Errorf("CONNECT %d should have no parent during stabilization", i)
		}
	}

	// All should have the same identity
	for i := 1; i < 4; i++ {
		if ids[i].AgentID != ids[0].AgentID {
			t.Errorf("CONNECT %d identity %q should match first %q", i, ids[i].AgentName, ids[0].AgentName)
		}
	}

	// Peak should be 4 (1 from first + 3 more)
	tracker.mu.Lock()
	peak := tracker.ipState[trackerKey].peakTunnels
	tracker.mu.Unlock()
	if peak != 4 {
		t.Errorf("expected peakTunnels=4, got %d", peak)
	}
}

func TestTunnelTracker_SpikeAfterBaseline(t *testing.T) {
	// Establish baseline of 3 tunnels, then a 5th arrives → sub-agent
	tracker := newTunnelTracker(2000)

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code:anthropic"

	// Open 3 tunnels during stabilization
	for i := 0; i < 3; i++ {
		tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	}

	// Force stabilization to complete
	tracker.mu.Lock()
	tracker.ipState[trackerKey].firstConnect = time.Now().Add(-15 * time.Second)
	tracker.mu.Unlock()

	// 4th CONNECT triggers baseline set (baseline=3); within threshold → same agent
	id4, _, isNew4 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if isNew4 {
		t.Error("4th CONNECT should set baseline but not be a spike")
	}
	if id4.AgentID != parentID.AgentID {
		t.Errorf("4th CONNECT should reuse parent identity, got %q", id4.AgentName)
	}

	// 5th CONNECT → activeTunnels=4, baseline=3, spike threshold=2
	// 4 >= 3+2 = 5? No. Need more.
	id5, _, isNew5 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if isNew5 {
		t.Error("5th CONNECT (active=5, baseline=3, need >= 5) should be a spike")
	}
	_ = id5

	// 6th CONNECT → activeTunnels=5, baseline=3, 5 >= 3+2 → spike!
	id6, parentAgent6, isNew6 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if !isNew6 {
		t.Error("6th CONNECT (active=5 >= baseline 3 + threshold 2) should be detected as sub-agent")
	}
	if parentAgent6 != parentID.AgentID {
		t.Errorf("sub-agent parent should be %q, got %q", parentID.AgentID, parentAgent6)
	}
	if id6.AgentID == parentID.AgentID {
		t.Error("sub-agent should have a different identity than parent")
	}
	if !strings.HasPrefix(id6.AgentName, "derived_") {
		t.Errorf("sub-agent name should start with 'derived_', got %q", id6.AgentName)
	}
}

func TestTunnelTracker_NoSpikeWithinBaseline(t *testing.T) {
	// Baseline=4, 4th CONNECT within baseline → same identity (no spike)
	tracker := newTunnelTracker(2000)

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code:anthropic"

	// Open 4 tunnels during stabilization to establish baseline=4
	for i := 0; i < 4; i++ {
		tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	}

	// Force stabilization to complete
	tracker.mu.Lock()
	tracker.ipState[trackerKey].firstConnect = time.Now().Add(-15 * time.Second)
	tracker.mu.Unlock()

	// Release 2 tunnels, then re-connect → should be within baseline
	tracker.release(trackerKey)
	tracker.release(trackerKey)

	// Next 2 CONNECTs should be normal (active goes from 2→3→4, all < 4+2=6)
	id1, _, isNew1 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	id2, _, isNew2 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)

	if isNew1 || isNew2 {
		t.Error("CONNECTs within baseline should not be detected as new agents")
	}
	if id1.AgentID != parentID.AgentID || id2.AgentID != parentID.AgentID {
		t.Error("CONNECTs within baseline should reuse parent identity")
	}
}

func TestTunnelTracker_ModelConfirmation(t *testing.T) {
	tracker := newTunnelTracker(2000)

	trackerKey := "10.0.0.1:claude-code:anthropic"
	childIdentity := &auth.Identity{AgentID: "child-1", AgentName: "derived_claude-code_1"}

	// Set up state with parent and a pending child
	tracker.mu.Lock()
	tracker.ipState[trackerKey] = &ipTunnelState{
		parentID:    &auth.Identity{AgentID: "parent-1", AgentName: "claude-code"},
		currentID:   childIdentity,
		parentModel: "claude-opus-4-6",
		pendingChildren: []*pendingChild{
			{identity: childIdentity, confirmed: false},
		},
	}
	tracker.mu.Unlock()

	// Confirm with a lighter model
	tracker.confirmModel(trackerKey, "child-1", "claude-haiku-4-5-20251001")

	tracker.mu.Lock()
	confirmed := tracker.ipState[trackerKey].pendingChildren[0].confirmed
	tracker.mu.Unlock()

	if !confirmed {
		t.Error("pending child should be confirmed after model divergence")
	}
}

func TestTunnelTracker_ModelConfirmation_SameModel(t *testing.T) {
	tracker := newTunnelTracker(2000)

	trackerKey := "10.0.0.1:claude-code:anthropic"
	childIdentity := &auth.Identity{AgentID: "child-1", AgentName: "derived_claude-code_1"}

	tracker.mu.Lock()
	tracker.ipState[trackerKey] = &ipTunnelState{
		parentID:    &auth.Identity{AgentID: "parent-1", AgentName: "claude-code"},
		currentID:   childIdentity,
		parentModel: "claude-opus-4-6",
		pendingChildren: []*pendingChild{
			{identity: childIdentity, confirmed: false},
		},
	}
	tracker.mu.Unlock()

	// Same model as parent → no confirmation
	tracker.confirmModel(trackerKey, "child-1", "claude-opus-4-6")

	tracker.mu.Lock()
	confirmed := tracker.ipState[trackerKey].pendingChildren[0].confirmed
	tracker.mu.Unlock()

	if confirmed {
		t.Error("pending child should NOT be confirmed when model matches parent")
	}
}

func TestModelDivergencePatterns(t *testing.T) {
	tests := []struct {
		parent string
		child  string
		want   bool
	}{
		// Anthropic: opus/sonnet → haiku
		{"claude-opus-4-6", "claude-haiku-4-5-20251001", true},
		{"claude-sonnet-4-6", "claude-haiku-4-5-20251001", true},

		// OpenAI: gpt-4o → gpt-4o-mini
		{"gpt-4o-2024-08-06", "gpt-4o-mini-2024-07-18", true},

		// Google: pro → flash
		{"gemini-2.0-pro", "gemini-2.0-flash", true},

		// Same model → no divergence
		{"claude-opus-4-6", "claude-opus-4-6", false},
		{"gpt-4o-mini", "gpt-4o-mini", false},

		// Empty → no divergence
		{"claude-opus-4-6", "", false},
		{"", "claude-haiku-4-5-20251001", false},

		// Different models (generic)
		{"claude-opus-4-6", "claude-sonnet-4-6", true},
	}

	for _, tt := range tests {
		t.Run(tt.parent+"→"+tt.child, func(t *testing.T) {
			got := isModelDivergence(tt.parent, tt.child)
			if got != tt.want {
				t.Errorf("isModelDivergence(%q, %q) = %v, want %v", tt.parent, tt.child, got, tt.want)
			}
		})
	}
}

func TestTunnelTracker_TemporalGapStillWorks(t *testing.T) {
	// Verify existing temporal gap detection is preserved alongside concurrency detection
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code"

	// First CONNECT establishes parent
	id1, _, isNew := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if isNew {
		t.Fatal("first CONNECT should not be new")
	}
	if id1.AgentID != parentID.AgentID {
		t.Errorf("first CONNECT should use parent identity: got %q", id1.AgentName)
	}

	// Simulate temporal gap (> burst window, with active tunnels)
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	// CONNECT with gap + parent trace → child (temporal gap detection)
	id2, pid2, isNew2 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", true)
	if !isNew2 {
		t.Fatal("CONNECT after temporal gap should be detected as new")
	}
	if pid2 != parentID.AgentID {
		t.Errorf("child parent should be %q, got %q", parentID.AgentID, pid2)
	}
	if id2.AgentID == parentID.AgentID {
		t.Error("child should have a different identity than parent")
	}
}

func TestTunnelTracker_MixedTemporalAndConcurrency(t *testing.T) {
	// Sequential handoff (temporal gap) then concurrent spike → both detected
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code:anthropic"

	// Phase 1: Establish parent with temporal gap child
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)

	// Temporal gap → child
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	child1, pid1, isNew1 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", true)
	if !isNew1 {
		t.Fatal("temporal gap should create child")
	}
	if pid1 == "" {
		t.Error("temporal gap child should have parent")
	}

	// Phase 2: Force stabilization complete with baseline
	tracker.mu.Lock()
	state := tracker.ipState[trackerKey]
	state.firstConnect = time.Now().Add(-15 * time.Second)
	state.baselineSet = true
	state.baseline = 2 // baseline of 2 concurrent tunnels
	tracker.mu.Unlock()

	// Add more tunnels to reach spike threshold (baseline=2, need active >= 2+2=4)
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false) // active=3
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false) // active=4 → spike!

	// The 4th tunnel (active=4 >= baseline 2 + threshold 2) should be a sub-agent
	child2, pid2, isNew2 := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if !isNew2 {
		t.Fatal("concurrency spike should create sub-agent")
	}
	if pid2 == "" {
		t.Error("concurrency spike child should have parent")
	}

	// Both children should be different from each other and from parent
	if child1.AgentID == child2.AgentID {
		t.Error("temporal child and concurrency child should be different agents")
	}
	if child1.AgentID == parentID.AgentID || child2.AgentID == parentID.AgentID {
		t.Error("children should differ from parent")
	}
}

func TestCorrelationEngine_Integration(t *testing.T) {
	p := setupTestProxy(t)

	// Assign parent trace
	parentIdentity := &auth.Identity{AgentID: "parent-agent"}
	parentTC := p.assignTrace(parentIdentity)

	// Simulate child connecting and being resolved
	childAgentID := "child-agent"
	childDepth := parentTC.Depth + 1

	// Add context signal through correlation engine
	rel := p.correlationEngine.AddContextSignal("parent-agent", childAgentID, parentTC.TraceID, childDepth)

	if rel == nil {
		t.Fatal("expected non-nil relationship")
	}
	if rel.ParentAgent != "parent-agent" {
		t.Errorf("expected parent %q, got %q", "parent-agent", rel.ParentAgent)
	}
	if rel.ChildAgent != "child-agent" {
		t.Errorf("expected child %q, got %q", "child-agent", rel.ChildAgent)
	}
	if rel.Confidence < 0.95 {
		t.Errorf("expected confidence >= 0.95, got %f", rel.Confidence)
	}
	if rel.Depth != 1 {
		t.Errorf("expected depth 1, got %d", rel.Depth)
	}

	// Verify depth tracking
	depth := p.correlationEngine.GetDepth(childAgentID)
	if depth != 1 {
		t.Errorf("expected tracked depth 1, got %d", depth)
	}
}

// --- Model-divergence split tests (Layer 1) ---

func TestTunnelTracker_ModelSplit_DivergentModel(t *testing.T) {
	tracker := newTunnelTracker(2000)

	trackerKey := "10.0.0.1:claude-code:anthropic"
	parentIdentity := &auth.Identity{AgentID: "parent-1", AgentName: "claude-code"}

	tracker.mu.Lock()
	tracker.ipState[trackerKey] = &ipTunnelState{
		parentID:    parentIdentity,
		currentID:   parentIdentity,
		parentModel: "claude-opus-4-6",
	}
	tracker.mu.Unlock()

	// Haiku diverges from Opus → should split
	result := tracker.detectModelSplit(trackerKey, "tunnel-abc", "claude-haiku-4-5-20251001")
	if !result.ShouldSplit {
		t.Fatal("expected ShouldSplit=true for Opus→Haiku divergence")
	}
	if result.ParentIdentity != parentIdentity {
		t.Error("expected ParentIdentity to match parent")
	}
	if result.ParentModel != "claude-opus-4-6" {
		t.Errorf("expected ParentModel='claude-opus-4-6', got %q", result.ParentModel)
	}
}

func TestTunnelTracker_ModelSplit_OncePerTunnel(t *testing.T) {
	tracker := newTunnelTracker(2000)

	trackerKey := "10.0.0.1:claude-code:anthropic"
	parentIdentity := &auth.Identity{AgentID: "parent-1", AgentName: "claude-code"}

	tracker.mu.Lock()
	tracker.ipState[trackerKey] = &ipTunnelState{
		parentID:    parentIdentity,
		currentID:   parentIdentity,
		parentModel: "claude-opus-4-6",
	}
	tracker.mu.Unlock()

	// First split on tunnel-abc → should split
	r1 := tracker.detectModelSplit(trackerKey, "tunnel-abc", "claude-haiku-4-5-20251001")
	if !r1.ShouldSplit {
		t.Fatal("first split on tunnel-abc should succeed")
	}

	// Second call on same tunnel-abc → should NOT split again
	r2 := tracker.detectModelSplit(trackerKey, "tunnel-abc", "claude-sonnet-4-6")
	if r2.ShouldSplit {
		t.Error("same tunnelID should not split twice")
	}

	// Different tunnel-def → should split
	r3 := tracker.detectModelSplit(trackerKey, "tunnel-def", "claude-haiku-4-5-20251001")
	if !r3.ShouldSplit {
		t.Fatal("different tunnelID should be allowed to split")
	}
}

func TestTunnelTracker_ModelSplit_NoParentModel(t *testing.T) {
	tracker := newTunnelTracker(2000)

	trackerKey := "10.0.0.1:claude-code:anthropic"
	parentIdentity := &auth.Identity{AgentID: "parent-1", AgentName: "claude-code"}

	tracker.mu.Lock()
	tracker.ipState[trackerKey] = &ipTunnelState{
		parentID:  parentIdentity,
		currentID: parentIdentity,
		// parentModel is empty — not set yet
	}
	tracker.mu.Unlock()

	// First model sets parentModel, no split
	result := tracker.detectModelSplit(trackerKey, "tunnel-abc", "claude-opus-4-6")
	if result.ShouldSplit {
		t.Error("first model observation should set baseline, not split")
	}

	// Verify parentModel was set
	tracker.mu.Lock()
	pm := tracker.ipState[trackerKey].parentModel
	tracker.mu.Unlock()
	if pm != "claude-opus-4-6" {
		t.Errorf("parentModel should be 'claude-opus-4-6', got %q", pm)
	}
}

func TestTunnelTracker_ModelSplit_SameModel(t *testing.T) {
	tracker := newTunnelTracker(2000)

	trackerKey := "10.0.0.1:claude-code:anthropic"
	parentIdentity := &auth.Identity{AgentID: "parent-1", AgentName: "claude-code"}

	tracker.mu.Lock()
	tracker.ipState[trackerKey] = &ipTunnelState{
		parentID:    parentIdentity,
		currentID:   parentIdentity,
		parentModel: "claude-opus-4-6",
	}
	tracker.mu.Unlock()

	// Same model as parent → no split
	result := tracker.detectModelSplit(trackerKey, "tunnel-abc", "claude-opus-4-6")
	if result.ShouldSplit {
		t.Error("same model as parent should not trigger split")
	}
}

func TestTunnelTracker_InferredChild_ActiveTunnelsNoTrace(t *testing.T) {
	// Temporal gap + no trace + parent active → inferred child with derived name
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code"

	// Establish parent (activeTunnels=1)
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)

	// Simulate temporal gap
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	// No trace, but parent still active → inferred child
	child, childParent, isNew := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if !isNew {
		t.Fatal("CONNECT after gap should be detected as new")
	}
	if childParent != parentID.AgentID {
		t.Errorf("inferred child parent should be %q, got %q", parentID.AgentID, childParent)
	}
	if child.AgentID == parentID.AgentID {
		t.Error("inferred child should have a different identity")
	}
	if !strings.HasPrefix(child.AgentName, "derived_") {
		t.Errorf("inferred child should have derived naming, got %q", child.AgentName)
	}
	if child.Source != "inferred_child" {
		t.Errorf("Source should be 'inferred_child', got %q", child.Source)
	}
}

func TestTunnelTracker_InferredChild_HasParent(t *testing.T) {
	// Verify inferred child retains parent link (parentIDStr is not cleared)
	tracker := newTunnelTracker(1) // 1ms burst

	db := setupTestAuthDB(t)
	resolver := NewIdentityResolver(db)
	parentID := resolver.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.0", "")

	trackerKey := "10.0.0.1:claude-code"

	// Establish parent (activeTunnels=1)
	tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)

	// Simulate temporal gap
	tracker.mu.Lock()
	tracker.ipState[trackerKey].lastConnect = time.Now().Add(-5 * time.Second)
	tracker.mu.Unlock()

	// Inferred child — key difference from old behavior: parentIDStr is preserved
	_, childParent, isNew := tracker.resolve(trackerKey, parentID, resolver, "claude-code/1.0", false)
	if !isNew {
		t.Fatal("expected new agent")
	}
	if childParent == "" {
		t.Fatal("inferred child must have a parent link — this is the core behavioral change")
	}
	if childParent != parentID.AgentID {
		t.Errorf("parent should be %q, got %q", parentID.AgentID, childParent)
	}
}
