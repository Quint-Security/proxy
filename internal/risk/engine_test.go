package risk

import (
	"testing"

	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

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

func TestNewEngineFromPolicy(t *testing.T) {
	flag40 := 40
	deny70 := 70
	revokeAfter := 3
	window := 60

	cfg := &intercept.RiskConfig{
		Flag:        &flag40,
		Deny:        &deny70,
		RevokeAfter: &revokeAfter,
		WindowSeconds: &window,
		Patterns: []intercept.RiskPatternConfig{
			{Tool: "CustomDanger*", BaseScore: 95},
			{Tool: "SafeCustom*", BaseScore: 2},
		},
		Keywords: []intercept.RiskKeywordConfig{
			{Pattern: `\bexploit\b`, Boost: 40},
		},
	}

	e := NewEngineFromPolicy(cfg, nil)

	// Custom pattern should match
	s := e.ScoreToolCall("CustomDangerTool", "", "test")
	if s.BaseScore != 95 {
		t.Errorf("CustomDangerTool base: got %d, want 95", s.BaseScore)
	}

	// Custom thresholds: flag=40 means ReadFile (base=10) is still allow
	s = e.ScoreToolCall("ReadFile", "", "test-thresh")
	if e.Evaluate(s.Value) != "allow" {
		t.Errorf("ReadFile should be allow with flag=40, got %s (score=%d)", e.Evaluate(s.Value), s.Value)
	}

	// Custom thresholds: deny=70 means WriteFile+dangerous (base=50+boost) could deny
	s = e.ScoreToolCall("WriteFile", `{"cmd":"exploit this"}`, "test-deny")
	if s.ArgBoost < 40 {
		t.Errorf("exploit keyword should boost by 40, got %d", s.ArgBoost)
	}

	// Check thresholds were applied
	th := e.GetThresholds()
	if th.Flag != 40 || th.Deny != 70 || th.RevokeAfter != 3 {
		t.Errorf("thresholds not applied: flag=%d deny=%d revoke=%d", th.Flag, th.Deny, th.RevokeAfter)
	}
}

func TestDisableBuiltins(t *testing.T) {
	cfg := &intercept.RiskConfig{
		DisableBuiltins: true,
		Patterns: []intercept.RiskPatternConfig{
			{Tool: "OnlyThis", BaseScore: 99},
		},
	}

	e := NewEngineFromPolicy(cfg, nil)

	// OnlyThis matches custom pattern
	s := e.ScoreToolCall("OnlyThis", "", "test")
	if s.BaseScore != 99 {
		t.Errorf("OnlyThis: got %d, want 99", s.BaseScore)
	}

	// DeleteFile would normally match builtin Delete* (80), but builtins disabled → default 20
	s = e.ScoreToolCall("DeleteFile", "", "test")
	if s.BaseScore != 20 {
		t.Errorf("DeleteFile with builtins disabled: got %d, want 20", s.BaseScore)
	}

	// Keywords disabled too — "drop" should not boost
	s = e.ScoreToolCall("WriteFile", `{"sql":"drop table"}`, "test")
	if s.ArgBoost != 0 {
		t.Errorf("argBoost with builtins disabled: got %d, want 0", s.ArgBoost)
	}
}

func TestWriteToolWithPasswordArg(t *testing.T) {
	e := newTestEngine(nil)
	s := e.ScoreToolCall("WriteFile", `{"content":"password=secret123"}`, "pw-agent")
	if s.ArgBoost < 15 {
		t.Errorf("password arg should boost by at least 15, got argBoost=%d", s.ArgBoost)
	}
}
