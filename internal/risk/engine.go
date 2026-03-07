package risk

import (
	"fmt"
	"regexp"
	"strconv"

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
	Value            int               // Final score 0-100 (capped)
	BaseScore        int               // Base score from tool pattern
	ArgBoost         int               // Boost from argument analysis
	BehaviorBoost    int               // Boost from repeated behavior
	Level            string            // "low", "medium", "high", "critical"
	Reasons          []string          // Human-readable reasons
	RemoteEnrichment *RemoteEnrichment // Enrichment from remote scoring API (nil if local-only)
}

// Engine performs risk scoring for tool calls.
type Engine struct {
	thresholds      Thresholds
	tracker         *BehaviorTracker
	customPatterns  []RiskPattern
	customKeywords  []ArgKeyword
	disableBuiltins bool
	remote          *RemoteScorer
	includeHTTP     bool

	// cachedPatterns is the pre-built merged pattern list, rebuilt when includeHTTP changes.
	cachedPatterns []RiskPattern
}

// EngineOpts configures the risk engine.
type EngineOpts struct {
	Thresholds      *Thresholds
	CustomPatterns  []RiskPattern
	CustomKeywords  []ArgKeyword
	DisableBuiltins bool
	BehaviorDB      *BehaviorDB
	Remote          *RemoteScorer
	IncludeHTTP     bool // include DefaultHTTPRisks patterns
}

// NewEngine creates a new risk scoring engine.
func NewEngine(opts *EngineOpts) *Engine {
	t := DefaultThresholds
	if opts != nil && opts.Thresholds != nil {
		t = *opts.Thresholds
	}

	var db *BehaviorDB
	var cp []RiskPattern
	var ck []ArgKeyword
	var disableBuiltins bool
	var remote *RemoteScorer
	var includeHTTP bool
	if opts != nil {
		db = opts.BehaviorDB
		cp = opts.CustomPatterns
		ck = opts.CustomKeywords
		disableBuiltins = opts.DisableBuiltins
		remote = opts.Remote
		includeHTTP = opts.IncludeHTTP
	}

	e := &Engine{
		thresholds:      t,
		tracker:         NewBehaviorTracker(t.WindowMs, db),
		customPatterns:  cp,
		customKeywords:  ck,
		disableBuiltins: disableBuiltins,
		remote:          remote,
		includeHTTP:     includeHTTP,
	}
	e.rebuildPatternCache()
	return e
}

// NewEngineFromPolicy creates an engine configured from policy risk settings.
func NewEngineFromPolicy(riskCfg *intercept.RiskConfig, behaviorDB *BehaviorDB) *Engine {
	opts := &EngineOpts{BehaviorDB: behaviorDB}

	if riskCfg != nil {
		t := DefaultThresholds
		if riskCfg.Flag != nil {
			t.Flag = *riskCfg.Flag
		}
		if riskCfg.Deny != nil {
			t.Deny = *riskCfg.Deny
		}
		if riskCfg.RevokeAfter != nil {
			t.RevokeAfter = *riskCfg.RevokeAfter
		}
		if riskCfg.WindowSeconds != nil {
			t.WindowMs = int64(*riskCfg.WindowSeconds) * 1000
		}
		opts.Thresholds = &t

		for _, p := range riskCfg.Patterns {
			opts.CustomPatterns = append(opts.CustomPatterns, RiskPattern{
				Tool:      p.Tool,
				BaseScore: p.BaseScore,
			})
		}

		for _, k := range riskCfg.Keywords {
			re, err := regexp.Compile("(?i)" + k.Pattern)
			if err != nil {
				continue
			}
			opts.CustomKeywords = append(opts.CustomKeywords, ArgKeyword{
				Pattern: re,
				Boost:   k.Boost,
				Label:   k.Pattern,
			})
		}

		opts.DisableBuiltins = riskCfg.DisableBuiltins

		if riskCfg.RemoteAPI != nil {
			opts.Remote = NewRemoteScorer(&RemoteConfig{
				URL:        riskCfg.RemoteAPI.URL,
				APIKey:     riskCfg.RemoteAPI.APIKey,
				CustomerID: riskCfg.RemoteAPI.CustomerID,
				Enabled:    riskCfg.RemoteAPI.Enabled,
				TimeoutMs:  riskCfg.RemoteAPI.TimeoutMs,
			})
		}
	}

	return NewEngine(opts)
}

// rebuildPatternCache merges custom + builtin + HTTP patterns into a single cached slice.
func (e *Engine) rebuildPatternCache() {
	n := len(e.customPatterns)
	if !e.disableBuiltins {
		n += len(DefaultToolRisks)
	}
	if e.includeHTTP {
		n += len(DefaultHTTPRisks)
	}
	patterns := make([]RiskPattern, 0, n)
	patterns = append(patterns, e.customPatterns...)
	if !e.disableBuiltins {
		patterns = append(patterns, DefaultToolRisks...)
	}
	if e.includeHTTP {
		patterns = append(patterns, DefaultHTTPRisks...)
	}
	e.cachedPatterns = patterns
}

// SetIncludeHTTP enables or disables HTTP risk patterns.
func (e *Engine) SetIncludeHTTP(v bool) {
	e.includeHTTP = v
	e.rebuildPatternCache()
}

// DepthPenalty computes additional risk score based on agent tree depth.
// Deeper agents are inherently riskier: each level adds 5 points (capped at 25).
func DepthPenalty(depth int) int {
	penalty := depth * 5
	if penalty > 25 {
		penalty = 25
	}
	return penalty
}

// DelegationBurstPenalty adds risk score when delegation bursts are detected.
// A burst of rapid actions suggests automated child agents operating without human oversight.
func DelegationBurstPenalty(burstCount int) int {
	if burstCount < BurstThreshold {
		return 0
	}
	// 10 base + 2 per action above threshold
	return 10 + (burstCount-BurstThreshold)*2
}

// ScoreToolCall evaluates the risk of a tool call.
func (e *Engine) ScoreToolCall(toolName, argsJSON, subjectID string) Score {
	reasons := make([]string, 0, 4)
	baseScore := 20 // default for unknown tools

	// Use pre-built pattern cache (custom + builtin + HTTP)
	matched := false
	for _, p := range e.cachedPatterns {
		if intercept.GlobMatch(p.Tool, toolName) {
			baseScore = p.BaseScore
			reasons = append(reasons, `tool "`+toolName+`" matches pattern "`+p.Tool+`" (base=`+strconv.Itoa(p.BaseScore)+`)`)
			matched = true
			break
		}
	}
	if !matched {
		reasons = append(reasons, `tool "`+toolName+`" — no pattern match, using default base score`)
	}

	// Argument analysis — custom keywords first, then builtins
	argBoost := 0
	if argsJSON != "" {
		for _, kw := range e.customKeywords {
			if kw.Pattern.MatchString(argsJSON) {
				argBoost += kw.Boost
				reasons = append(reasons, `argument contains "`+kw.Label+`" (+`+strconv.Itoa(kw.Boost)+`)`)

			}
		}
		if !e.disableBuiltins {
			for _, kw := range DangerousArgKeywords {
				if kw.Pattern.MatchString(argsJSON) {
					argBoost += kw.Boost
					reasons = append(reasons, `argument contains "`+kw.Label+`" (+`+strconv.Itoa(kw.Boost)+`)`)

				}
			}
		}
	}

	// Behavior escalation
	behaviorBoost := 0
	recentCount := e.tracker.Count(subjectID)
	if recentCount > 0 {
		behaviorBoost = recentCount * 5
		reasons = append(reasons, strconv.Itoa(recentCount)+" high-risk action(s) in window (+"+strconv.Itoa(behaviorBoost)+")")
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

// ScoreWithContext evaluates risk with agent tree context (depth, burst, parent inheritance).
// This is the enriched version of ScoreToolCall that factors in agent relationship data.
// The sessionTracker parameter is used for delegation burst detection; it may be nil.
func (e *Engine) ScoreWithContext(toolName, argsJSON, subjectID string, ctx *EventContext, sessionTracker *SessionTracker) Score {
	score := e.ScoreToolCall(toolName, argsJSON, subjectID)

	if ctx == nil {
		return score
	}

	// Depth penalty: deeper agents get higher base risk
	if ctx.Depth > 0 {
		penalty := DepthPenalty(ctx.Depth)
		score.Value += penalty
		score.Reasons = append(score.Reasons, fmt.Sprintf("agent depth %d (+%d)", ctx.Depth, penalty))
	}

	// Delegation burst detection
	if sessionTracker != nil {
		burstCount, isBurst := sessionTracker.DetectDelegationBurst(subjectID)
		if isBurst {
			penalty := DelegationBurstPenalty(burstCount)
			score.Value += penalty
			score.Reasons = append(score.Reasons, fmt.Sprintf("delegation burst: %d actions in %.0fs (+%d)", burstCount, BurstWindow.Seconds(), penalty))
		}
	}

	// Cap at 100
	if score.Value > 100 {
		score.Value = 100
	}

	// Re-evaluate level after adjustments
	if score.Value >= e.thresholds.Deny {
		score.Level = "critical"
	} else if score.Value >= e.thresholds.Flag {
		score.Level = "high"
	} else if score.Value >= 30 {
		score.Level = "medium"
	} else {
		score.Level = "low"
	}

	return score
}

// EnhanceWithRemote sends the local score to the remote API for enrichment.
// Returns the local score unchanged if no remote scorer is configured or on failure.
// ctx may be nil for backward compatibility.
func (e *Engine) EnhanceWithRemote(localScore Score, toolName, argsJSON, subjectID, serverName string, ctx *EventContext) Score {
	if e.remote == nil {
		return localScore
	}
	return e.remote.EnhanceScore(localScore, toolName, argsJSON, subjectID, serverName, ctx)
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
