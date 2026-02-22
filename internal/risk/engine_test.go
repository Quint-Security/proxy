package risk

import "testing"

func newTestEngine(opts *EngineOpts) *Engine {
	return NewEngine(opts)
}

func TestScoresReadOperationsAsLowRisk(t *testing.T) {
	e := newTestEngine(nil)
	s := e.ScoreToolCall("ReadFile", "", "test")
	if s.Value > 20 {
		t.Errorf("ReadFile score too high: %d", s.Value)
	}
	if s.Level != "low" {
		t.Errorf("ReadFile level: got %q, want low", s.Level)
	}
}

func TestScoresDeleteOperationsAsHighRisk(t *testing.T) {
	e := newTestEngine(nil)
	s := e.ScoreToolCall("DeleteFile", "", "test")
	if s.Value < 60 {
		t.Errorf("DeleteFile score too low: %d", s.Value)
	}
	if s.Level != "high" && s.Level != "critical" {
		t.Errorf("DeleteFile level: got %q, want high or critical", s.Level)
	}
}

func TestScoresShellToolsAsHighRisk(t *testing.T) {
	e := newTestEngine(nil)
	s := e.ScoreToolCall("ExecuteCommand", "", "test")
	if s.Value < 60 {
		t.Errorf("ExecuteCommand score too low: %d", s.Value)
	}
}

func TestBoostsScoreForDangerousArgs(t *testing.T) {
	e := newTestEngine(nil)
	safe := e.ScoreToolCall("WriteFile", `{"path":"/tmp/test.txt","content":"hello"}`, "test-safe")
	dangerous := e.ScoreToolCall("WriteFile", `{"query":"DROP TABLE users"}`, "test-danger")

	if dangerous.Value <= safe.Value {
		t.Errorf("dangerous score (%d) should be higher than safe (%d)", dangerous.Value, safe.Value)
	}
	if dangerous.ArgBoost <= 0 {
		t.Errorf("dangerous argBoost should be > 0, got %d", dangerous.ArgBoost)
	}
}

func TestEscalatesOnRepeatedHighRisk(t *testing.T) {
	e := newTestEngine(nil)
	e.ScoreToolCall("DeleteFile", "", "escalation-agent")
	e.ScoreToolCall("DeleteFile", "", "escalation-agent")
	s := e.ScoreToolCall("DeleteFile", "", "escalation-agent")

	if s.BehaviorBoost <= 0 {
		t.Errorf("behaviorBoost should be > 0 after repeated high-risk, got %d", s.BehaviorBoost)
	}
}

func TestTriggersRevocationAfterThreshold(t *testing.T) {
	e := newTestEngine(&EngineOpts{
		Thresholds: &Thresholds{
			Flag:        60,
			Deny:        85,
			RevokeAfter: 3,
			WindowMs:    5 * 60 * 1000,
		},
	})
	for i := 0; i < 3; i++ {
		e.ScoreToolCall("DeleteFile", "", "revoke-agent")
	}
	if !e.ShouldRevoke("revoke-agent") {
		t.Error("shouldRevoke should return true after threshold")
	}
}

func TestNoRevocationForLowRisk(t *testing.T) {
	e := newTestEngine(&EngineOpts{
		Thresholds: &Thresholds{
			Flag:        60,
			Deny:        85,
			RevokeAfter: 3,
			WindowMs:    5 * 60 * 1000,
		},
	})
	for i := 0; i < 4; i++ {
		e.ScoreToolCall("ReadFile", "", "safe-agent")
	}
	if e.ShouldRevoke("safe-agent") {
		t.Error("shouldRevoke should return false for low-risk actions")
	}
}

func TestEvaluateReturnsCorrectAction(t *testing.T) {
	e := newTestEngine(nil)
	readScore := e.ScoreToolCall("ReadFile", "", "eval-agent-1")
	if e.Evaluate(readScore.Value) != "allow" {
		t.Errorf("ReadFile should be allow, got %s", e.Evaluate(readScore.Value))
	}

	deleteScore := e.ScoreToolCall("DeleteFile", "", "eval-agent-2")
	if e.Evaluate(deleteScore.Value) != "flag" {
		t.Errorf("DeleteFile should be flag, got %s (score=%d)", e.Evaluate(deleteScore.Value), deleteScore.Value)
	}
}

func TestAutoDeniesAboveThreshold(t *testing.T) {
	e := newTestEngine(&EngineOpts{
		Thresholds: &Thresholds{
			Flag:        60,
			Deny:        70,
			RevokeAfter: 5,
			WindowMs:    5 * 60 * 1000,
		},
	})
	s := e.ScoreToolCall("DeleteFile", `{"command":"rm -rf /"}`, "deny-agent")
	if e.Evaluate(s.Value) != "deny" {
		t.Errorf("should auto-deny, score=%d, action=%s", s.Value, e.Evaluate(s.Value))
	}
}

func TestCustomPatterns(t *testing.T) {
	e := newTestEngine(&EngineOpts{
		CustomPatterns: []RiskPattern{
			{Tool: "DangerousTool", BaseScore: 95},
			{Tool: "SafeTool", BaseScore: 5},
		},
	})

	s := e.ScoreToolCall("DangerousTool", "", "custom-agent")
	if s.BaseScore != 95 {
		t.Errorf("DangerousTool baseScore: got %d, want 95", s.BaseScore)
	}
	if s.Value < 85 {
		t.Errorf("DangerousTool score should be ≥ 85, got %d", s.Value)
	}

	s = e.ScoreToolCall("SafeTool", "", "custom-agent-2")
	if s.BaseScore != 5 {
		t.Errorf("SafeTool baseScore: got %d, want 5", s.BaseScore)
	}
}

func TestUnknownToolsGetDefaultBaseScore(t *testing.T) {
	e := newTestEngine(nil)
	s := e.ScoreToolCall("CompletelyUnknownTool", "", "unknown-agent")
	if s.BaseScore != 20 {
		t.Errorf("unknown tool baseScore: got %d, want 20", s.BaseScore)
	}
}

func TestListToolsAreLowRisk(t *testing.T) {
	e := newTestEngine(nil)
	s := e.ScoreToolCall("ListFiles", "", "list-agent")
	if s.BaseScore != 5 {
		t.Errorf("ListFiles baseScore: got %d, want 5", s.BaseScore)
	}
	if s.Level != "low" {
		t.Errorf("ListFiles level: got %q, want low", s.Level)
	}
}

func TestWriteToolWithPasswordArg(t *testing.T) {
	e := newTestEngine(nil)
	s := e.ScoreToolCall("WriteFile", `{"content":"password=secret123"}`, "pw-agent")
	if s.ArgBoost < 15 {
		t.Errorf("password arg should boost by at least 15, got argBoost=%d", s.ArgBoost)
	}
}
