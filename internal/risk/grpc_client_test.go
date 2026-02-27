package risk

import (
	"math"
	"testing"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	// Encode an EvaluateRiskRequest
	req := encodeEvaluateRiskRequest("WriteFile", `{"path":"/tmp"}`, "test-server", "agent-1")
	if len(req) == 0 {
		t.Fatal("encoded request is empty")
	}

	// Verify it's a valid embedded message (field 1, wire type 2)
	if req[0] != 0x0a { // field 1, wire type 2 = (1 << 3) | 2 = 0x0a
		t.Errorf("expected outer tag 0x0a, got 0x%02x", req[0])
	}
}

func TestDecodeEvaluateRiskResponse(t *testing.T) {
	// Build a mock EvaluateRiskResponse:
	// Field 1 (RiskAssessment, embedded message):
	//   Field 1 (level): varint 4 (HIGH)
	//   Field 2 (confidence): float32 0.85
	//   Field 3 (reasoning): string "ML model flagged filesystem write"
	//   Field 4 (mitigations): string "require approval"

	var assessment []byte
	assessment = appendVarint(assessment, 1, 4) // RISK_LEVEL_HIGH
	// Encode float32 0.85 as wire type 5 (32-bit)
	bits := math.Float32bits(0.85)
	assessment = appendTag(assessment, 2, 5) // field 2, wire type 5
	assessment = append(assessment, byte(bits), byte(bits>>8), byte(bits>>16), byte(bits>>24))
	assessment = appendString(assessment, 3, "ML model flagged filesystem write")
	assessment = appendString(assessment, 4, "require approval")

	// Wrap in outer EvaluateRiskResponse
	var resp []byte
	resp = appendBytes(resp, 1, assessment)

	level, confidence, reasoning, mitigations := decodeEvaluateRiskResponse(resp)

	if level != 4 {
		t.Errorf("level: got %d, want 4 (HIGH)", level)
	}
	if confidence < 0.84 || confidence > 0.86 {
		t.Errorf("confidence: got %f, want ~0.85", confidence)
	}
	if reasoning != "ML model flagged filesystem write" {
		t.Errorf("reasoning: got %q", reasoning)
	}
	if len(mitigations) != 1 || mitigations[0] != "require approval" {
		t.Errorf("mitigations: got %v", mitigations)
	}
}

func TestRiskLevelToString(t *testing.T) {
	cases := []struct {
		level int32
		want  string
	}{
		{0, "unknown"},
		{1, "none"},
		{2, "low"},
		{3, "medium"},
		{4, "high"},
		{5, "critical"},
	}
	for _, tc := range cases {
		got := riskLevelToString(tc.level)
		if got != tc.want {
			t.Errorf("riskLevelToString(%d) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestRiskLevelToScore(t *testing.T) {
	cases := []struct {
		level int32
		want  int
	}{
		{1, 0},
		{2, 25},
		{3, 50},
		{4, 75},
		{5, 95},
	}
	for _, tc := range cases {
		got := riskLevelToScore(tc.level)
		if got != tc.want {
			t.Errorf("riskLevelToScore(%d) = %d, want %d", tc.level, got, tc.want)
		}
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

func TestDecodeUnspecifiedLevelFallsBack(t *testing.T) {
	// Response with RISK_LEVEL_UNSPECIFIED (0) — should return zero level
	var assessment []byte
	// level 0 won't be encoded (proto3 default), so empty assessment
	assessment = appendString(assessment, 3, "no opinion")

	var resp []byte
	resp = appendBytes(resp, 1, assessment)

	level, _, _, _ := decodeEvaluateRiskResponse(resp)
	if level != 0 {
		t.Errorf("expected level 0 (UNSPECIFIED), got %d", level)
	}
}
