package risk

import (
	"fmt"

	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// Thresholds control risk-based actions.
type Thresholds struct {
	Flag        int   // Score at which action is flagged (default 60)
	Deny        int   // Score at which action is auto-denied (default 85)
	RevokeAfter int   // High-risk actions in window before revocation (default 5)
	WindowMs    int64 // Time window in ms for behavior tracking (default 5 min)
}

// DefaultThresholds returns the standard thresholds matching TypeScript.
var DefaultThresholds = Thresholds{
	Flag:        60,
	Deny:        85,
	RevokeAfter: 5,
	WindowMs:    5 * 60 * 1000,
}

// Score is the result of risk evaluation.
type Score struct {
	Value         int      // Final score 0-100 (capped)
	BaseScore     int      // Base score from tool pattern
	ArgBoost      int      // Boost from argument analysis
	BehaviorBoost int      // Boost from repeated behavior
	Level         string   // "low", "medium", "high", "critical"
	Reasons       []string // Human-readable reasons
}

// Engine performs risk scoring for tool calls.
type Engine struct {
	thresholds     Thresholds
	tracker        *BehaviorTracker
	customPatterns []RiskPattern
}

// EngineOpts configures the risk engine.
type EngineOpts struct {
	Thresholds     *Thresholds
	CustomPatterns []RiskPattern
	BehaviorDB     *BehaviorDB
}

// NewEngine creates a new risk scoring engine.
func NewEngine(opts *EngineOpts) *Engine {
	t := DefaultThresholds
	if opts != nil && opts.Thresholds != nil {
		t = *opts.Thresholds
	}

	var db *BehaviorDB
	var cp []RiskPattern
	if opts != nil {
		db = opts.BehaviorDB
		cp = opts.CustomPatterns
	}

	return &Engine{
		thresholds:     t,
		tracker:        NewBehaviorTracker(t.WindowMs, db),
		customPatterns: cp,
	}
}

// ScoreToolCall evaluates the risk of a tool call.
func (e *Engine) ScoreToolCall(toolName, argsJSON, subjectID string) Score {
	reasons := make([]string, 0, 4)
	baseScore := 20 // default for unknown tools

	// Check custom patterns first, then defaults
	allPatterns := append(e.customPatterns, DefaultToolRisks...)
	matched := false
	for _, p := range allPatterns {
		if intercept.GlobMatch(p.Tool, toolName) {
			baseScore = p.BaseScore
			reasons = append(reasons, fmt.Sprintf(`tool "%s" matches pattern "%s" (base=%d)`, toolName, p.Tool, p.BaseScore))
			matched = true
			break
		}
	}
	if !matched {
		reasons = append(reasons, fmt.Sprintf(`tool "%s" — no pattern match, using default base score`, toolName))
	}

	// Argument analysis
	argBoost := 0
	if argsJSON != "" {
		for _, kw := range DangerousArgKeywords {
			if kw.Pattern.MatchString(argsJSON) {
				argBoost += kw.Boost
				reasons = append(reasons, fmt.Sprintf(`argument contains "%s" (+%d)`, kw.Label, kw.Boost))
			}
		}
	}

	// Behavior escalation
	behaviorBoost := 0
	recentCount := e.tracker.Count(subjectID)
	if recentCount > 0 {
		behaviorBoost = recentCount * 5
		reasons = append(reasons, fmt.Sprintf("%d high-risk action(s) in window (+%d)", recentCount, behaviorBoost))
	}

	raw := baseScore + argBoost + behaviorBoost
	score := raw
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	level := "low"
	if score >= e.thresholds.Deny {
		level = "critical"
	} else if score >= e.thresholds.Flag {
		level = "high"
	} else if score >= 30 {
		level = "medium"
	}

	// Record if high-risk
	if score >= e.thresholds.Flag {
		e.tracker.Record(subjectID)
	}

	return Score{
		Value:         score,
		BaseScore:     baseScore,
		ArgBoost:      argBoost,
		BehaviorBoost: behaviorBoost,
		Level:         level,
		Reasons:       reasons,
	}
}

// Evaluate determines the action based on a risk score.
func (e *Engine) Evaluate(score int) string {
	if score >= e.thresholds.Deny {
		return "deny"
	}
	if score >= e.thresholds.Flag {
		return "flag"
	}
	return "allow"
}

// ShouldRevoke checks if the subject has exceeded the revocation threshold.
func (e *Engine) ShouldRevoke(subjectID string) bool {
	return e.tracker.Count(subjectID) >= e.thresholds.RevokeAfter
}

// GetThresholds returns the current thresholds.
func (e *Engine) GetThresholds() Thresholds {
	return e.thresholds
}
