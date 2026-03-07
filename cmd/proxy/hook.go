package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

// hookInput matches the Claude Code PreToolUse JSON schema.
type hookInput struct {
	SessionID     string         `json:"session_id"`
	Cwd           string         `json:"cwd"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
}

// hookOutput is the Claude Code hook response for deny decisions.
type hookOutput struct {
	HookSpecificOutput hookDecision `json:"hookSpecificOutput"`
}

type hookDecision struct {
	HookEventName           string `json:"hookEventName"`
	PermissionDecision      string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

const (
	maxStdinBytes   = 2 * 1024 * 1024 // 2MB
	maxArgStringLen = 4096             // truncate individual string args
	auditDrainTime  = 50 * time.Millisecond
)

func runHook(_ []string) {
	// Fail-open on any panic — never break Claude Code
	defer func() {
		if r := recover(); r != nil {
			os.Exit(0)
		}
	}()

	// Read stdin (capped)
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdinBytes))
	if err != nil || len(raw) == 0 {
		os.Exit(0)
	}

	var input hookInput
	if err := json.Unmarshal(raw, &input); err != nil {
		os.Exit(0)
	}

	// Skip tools already scored by the quint gateway
	if strings.HasPrefix(input.ToolName, "mcp__quint__") {
		os.Exit(0)
	}

	// Load policy (fail-open if missing)
	policy, err := intercept.LoadPolicy("")
	if err != nil {
		os.Exit(0)
	}

	dataDir := intercept.ResolveDataDir(policy.DataDir)
	serverName := classifyToolServer(input.ToolName)
	argsJSON := marshalToolInput(input.ToolInput)

	// Evaluate policy for all tools
	verdict := intercept.EvaluatePolicy(policy, serverName, input.ToolName)

	// Score risk. For native Claude Code tools, replace the MCP tool name
	// base score (which gives false positives like *Bash* → 75) with sane
	// native baselines, then add arg + behavior boosts from the engine.
	engine := buildLocalEngine(policy)
	score := engine.ScoreToolCall(input.ToolName, argsJSON, input.SessionID)

	if serverName == "claude-code" {
		nativeBase := nativeToolBase(input.ToolName)
		score.Value = nativeBase + score.ArgBoost + score.BehaviorBoost
		score.BaseScore = nativeBase
		if score.Value > 100 {
			score.Value = 100
		}
	}
	score.Level = scoreLevel(score.Value)

	evalResult := engine.Evaluate(score.Value)

	verdictStr := "allow"
	denied := false
	if verdict == intercept.VerdictDeny || evalResult == "deny" {
		verdictStr = "deny"
		denied = true
	} else if evalResult == "flag" {
		verdictStr = "flag"
	}

	// Async audit log + cloud forward (fire-and-forget)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logHookAudit(dataDir, policy, serverName, input, argsJSON, verdictStr, score)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		forwardToCloud(policy.Cloud, serverName, input, verdictStr, score)
	}()

	if denied {
		reason := fmt.Sprintf("quint: %s on %s denied (risk_score=%d, level=%s)",
			input.ToolName, serverName, score.Value, score.Level)
		emitDeny(input.HookEventName, reason)
	}

	// Give audit goroutine time to drain
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(auditDrainTime):
	}

	os.Exit(0)
}

// classifyToolServer extracts the logical server name from a tool name.
// Native Claude Code tools → "claude-code"
// MCP tools (mcp__<server>__<tool>) → extracted server name
func classifyToolServer(toolName string) string {
	if !strings.HasPrefix(toolName, "mcp__") {
		return "claude-code"
	}

	// mcp__<server>__<tool> → server
	rest := toolName[5:] // strip "mcp__"
	idx := strings.Index(rest, "__")
	if idx < 0 {
		return "claude-code"
	}
	return rest[:idx]
}

// marshalToolInput converts tool_input to JSON string, truncating large string values.
func marshalToolInput(input map[string]any) string {
	if input == nil {
		return "{}"
	}
	truncated := truncateStrings(input)
	b, err := json.Marshal(truncated)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// truncateStrings recursively truncates string values exceeding maxArgStringLen.
func truncateStrings(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, v := range val {
			out[k] = truncateStrings(v)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, v := range val {
			out[i] = truncateStrings(v)
		}
		return out
	case string:
		if len(val) > maxArgStringLen {
			return val[:maxArgStringLen] + "...<truncated>"
		}
		return val
	default:
		return val
	}
}

// nativeToolBase returns the inherent risk baseline for Claude Code native tools.
// These replace the MCP glob patterns (which give inflated scores like *Bash* → 75)
// with calibrated values that reflect what each tool can actually do.
func nativeToolBase(toolName string) int {
	switch toolName {
	case "Bash":
		return 15 // shell access — can run arbitrary commands
	case "Write":
		return 10 // creates or overwrites entire files
	case "Edit":
		return 5 // targeted modification of existing files
	case "NotebookEdit":
		return 5 // notebook cell modification
	case "WebFetch":
		return 5 // outbound network request
	case "Read":
		return 0 // read-only
	case "Grep":
		return 0 // content search
	case "Glob":
		return 0 // file search
	case "Task":
		return 0 // spawns subagent
	default:
		return 5 // unknown native tool — small baseline
	}
}

// scoreLevel maps a risk score to a human-readable level, matching the engine's logic.
func scoreLevel(score int) string {
	if score >= 85 {
		return "critical"
	}
	if score >= 60 {
		return "high"
	}
	if score >= 30 {
		return "medium"
	}
	return "low"
}

// buildLocalEngine creates a local-only risk engine from policy (no remote scorer).
func buildLocalEngine(policy intercept.PolicyConfig) *risk.Engine {
	return risk.NewEngineFromPolicy(policy.Risk, nil)
}

// logHookAudit writes a signed audit entry for the hook invocation.
func logHookAudit(
	dataDir string,
	policy intercept.PolicyConfig,
	serverName string,
	input hookInput,
	argsJSON string,
	verdict string,
	score risk.Score,
) {
	defer func() { recover() }()

	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		return
	}

	db, err := audit.OpenDB(dataDir)
	if err != nil {
		return
	}
	defer db.Close()

	policyBytes, _ := json.Marshal(policy)
	var policyMap map[string]any
	json.Unmarshal(policyBytes, &policyMap)

	logger := audit.NewLogger(db, kp.PrivateKey, kp.PublicKey, policyMap)

	riskScore := score.Value
	riskLevel := score.Level
	scoringSource := "local"

	logger.Log(audit.LogOpts{
		ServerName:    serverName,
		Direction:     "request",
		Method:        "tools/call",
		ToolName:      input.ToolName,
		ArgumentsJSON: argsJSON,
		Verdict:       verdict,
		RiskScore:     &riskScore,
		RiskLevel:     &riskLevel,
		ScoringSource: scoringSource,
		LocalScore:    &riskScore,
	})
}

// emitDeny writes a Claude Code deny response to stdout.
func emitDeny(hookEventName, reason string) {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName:           hookEventName,
			PermissionDecision:      "deny",
			PermissionDecisionReason: reason,
		},
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
