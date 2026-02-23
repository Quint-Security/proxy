package approval

import (
	"testing"
	"time"
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

func TestCreateAndGet(t *testing.T) {
	db := testDB(t)

	score := 70
	level := "high"
	req, err := db.Create("agent_1", "test-bot", "ExecuteCommand", `{"cmd":"ls"}`, "test-server", &score, &level, 300)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if req.ID == "" {
		t.Error("ID is empty")
	}
	if req.Status != StatusPending {
		t.Errorf("status = %q, want pending", req.Status)
	}
	if req.AgentName != "test-bot" {
		t.Errorf("AgentName = %q, want test-bot", req.AgentName)
	}
	if req.ToolName != "ExecuteCommand" {
		t.Errorf("ToolName = %q, want ExecuteCommand", req.ToolName)
	}

	// Get by ID
	got, err := db.Get(req.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != req.ID {
		t.Errorf("Get ID = %q, want %q", got.ID, req.ID)
	}
	if *got.RiskScore != 70 {
		t.Errorf("RiskScore = %d, want 70", *got.RiskScore)
	}
}

func TestGetNonexistent(t *testing.T) {
	db := testDB(t)

	got, err := db.Get("nonexistent-id")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent ID")
	}
}

func TestListPending(t *testing.T) {
	db := testDB(t)

	db.Create("a1", "bot1", "tool1", "{}", "srv", nil, nil, 300)
	db.Create("a2", "bot2", "tool2", "{}", "srv", nil, nil, 300)

	pending, err := db.ListPending()
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("got %d pending, want 2", len(pending))
	}
}

func TestDecideApprove(t *testing.T) {
	db := testDB(t)

	req, _ := db.Create("a1", "bot1", "tool1", "{}", "srv", nil, nil, 300)

	err := db.Decide(req.ID, true, "operator", "sig123")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}

	got, _ := db.Get(req.ID)
	if got.Status != StatusApproved {
		t.Errorf("status = %q, want approved", got.Status)
	}
	if *got.DecisionBy != "operator" {
		t.Errorf("DecisionBy = %q, want operator", *got.DecisionBy)
	}
	if *got.DecisionSig != "sig123" {
		t.Errorf("DecisionSig = %q, want sig123", *got.DecisionSig)
	}

	// Should not appear in pending list
	pending, _ := db.ListPending()
	if len(pending) != 0 {
		t.Errorf("got %d pending after approval, want 0", len(pending))
	}
}

func TestDecideDeny(t *testing.T) {
	db := testDB(t)

	req, _ := db.Create("a1", "bot1", "tool1", "{}", "srv", nil, nil, 300)

	err := db.Decide(req.ID, false, "operator", "sig456")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}

	got, _ := db.Get(req.ID)
	if got.Status != StatusDenied {
		t.Errorf("status = %q, want denied", got.Status)
	}
}

func TestDoubleDecideRejected(t *testing.T) {
	db := testDB(t)

	req, _ := db.Create("a1", "bot1", "tool1", "{}", "srv", nil, nil, 300)
	db.Decide(req.ID, true, "operator", "sig")

	err := db.Decide(req.ID, false, "operator", "sig2")
	if err == nil {
		t.Error("expected error on double decide")
	}
}

func TestIsApproved(t *testing.T) {
	db := testDB(t)

	req, _ := db.Create("a1", "bot1", "tool1", "{}", "srv", nil, nil, 300)

	// Not yet decided
	if db.IsApproved(req.ID) {
		t.Error("should not be approved before decision")
	}

	// Approve
	db.Decide(req.ID, true, "operator", "sig")
	if !db.IsApproved(req.ID) {
		t.Error("should be approved after approval")
	}

	// Denied request
	req2, _ := db.Create("a2", "bot2", "tool2", "{}", "srv", nil, nil, 300)
	db.Decide(req2.ID, false, "operator", "sig")
	if db.IsApproved(req2.ID) {
		t.Error("denied request should not be approved")
	}

	// Nonexistent
	if db.IsApproved("fake-id") {
		t.Error("nonexistent ID should not be approved")
	}
}

func TestExpiredRequestNotApproved(t *testing.T) {
	db := testDB(t)

	// Create with 1-second timeout
	req, _ := db.Create("a1", "bot1", "tool1", "{}", "srv", nil, nil, 1)

	// Approve it
	db.Decide(req.ID, true, "operator", "sig")

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	if db.IsApproved(req.ID) {
		t.Error("expired approval should not be valid")
	}
}

func TestExpiredRequestsRemovedFromPending(t *testing.T) {
	db := testDB(t)

	// Create with 1-second timeout, sleep 2s to ensure expiry
	db.Create("a1", "bot1", "tool1", "{}", "srv", nil, nil, 1)

	time.Sleep(2 * time.Second)

	pending, err := db.ListPending()
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("got %d pending after expiry, want 0", len(pending))
	}
}

func TestDecideNonexistent(t *testing.T) {
	db := testDB(t)

	err := db.Decide("fake-id", true, "operator", "sig")
	if err == nil {
		t.Error("expected error for nonexistent approval")
	}
}
