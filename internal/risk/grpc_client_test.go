package risk

import (
	"testing"
)

func TestProtoEncodeDecode(t *testing.T) {
	// Test the manual proto encoding/decoding roundtrip
	req := encodeScoreRequest("WriteFile", `{"path":"/tmp"}`, "agent-1", "test-server", 50, "medium")
	if len(req) == 0 {
		t.Fatal("encoded request is empty")
	}

	// Test response decoding with a manually-crafted response
	// Field 1 (score): varint 75
	// Field 2 (level): string "high"
	// Field 3 (reasons): string "ML model flagged"
	// Field 4 (enhanced): varint 1
	resp := []byte{}
	resp = appendVarint(resp, 1, 75)
	resp = appendString(resp, 2, "high")
	resp = appendString(resp, 3, "ML model flagged")
	resp = appendVarint(resp, 4, 1)

	score, level, reasons, enhanced := decodeScoreResponse(resp)
	if score != 75 {
		t.Errorf("score: got %d, want 75", score)
	}
	if level != "high" {
		t.Errorf("level: got %q, want high", level)
	}
	if len(reasons) != 1 || reasons[0] != "ML model flagged" {
		t.Errorf("reasons: got %v, want [ML model flagged]", reasons)
	}
	if !enhanced {
		t.Error("enhanced should be true")
	}
}

func TestNewGRPCClientReturnsNilWithoutEnv(t *testing.T) {
	t.Setenv("QUINT_RISK_SERVICE_URL", "")
	c := NewGRPCClient()
	if c != nil {
		t.Error("expected nil client when env is not set")
	}
}

func TestEnhanceScoreFallsBackOnNoConnection(t *testing.T) {
	c := &GRPCClient{addr: "localhost:99999"} // unreachable
	localScore := Score{
		Value:     42,
		BaseScore: 40,
		Level:     "medium",
		Reasons:   []string{"test"},
	}
	result := c.EnhanceScore(localScore, "ReadFile", "{}", "test", "srv")
	if result.Value != 42 {
		t.Errorf("fallback score: got %d, want 42", result.Value)
	}
}
