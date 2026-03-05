package intercept

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SpawnPattern defines a pattern for detecting agent spawn events.
type SpawnPattern struct {
	ID          string   `json:"id" yaml:"id"`
	Description string   `json:"description" yaml:"description"`
	ToolPattern string   `json:"tool_pattern" yaml:"tool_pattern"`
	ArgPatterns []string `json:"arg_patterns" yaml:"arg_patterns"`
	Confidence  float64  `json:"confidence" yaml:"confidence"`
	SpawnType   string   `json:"spawn_type" yaml:"spawn_type"` // "direct", "delegation", "fork"
}

// SpawnEvent is emitted when a tool call matches a spawn pattern.
type SpawnEvent struct {
	PatternID    string    `json:"pattern_id"`
	ParentAgent  string    `json:"parent_agent"`
	ChildHint    string    `json:"child_hint"`    // extracted child agent identifier if available
	SpawnType    string    `json:"spawn_type"`     // "direct", "delegation", "fork"
	Confidence   float64   `json:"confidence"`     // 0.0-1.0
	ToolName     string    `json:"tool_name"`
	ServerName   string    `json:"server_name"`
	DetectedAt   time.Time `json:"detected_at"`
	ArgumentsRef string    `json:"arguments_ref"`  // hash or truncated args for correlation
}

// SpawnDetector detects agent spawn events from tool calls.
type SpawnDetector struct {
	mu       sync.RWMutex
	patterns []compiledSpawnPattern
}

type compiledSpawnPattern struct {
	SpawnPattern
	toolRegex *regexp.Regexp
	argRegexs []*regexp.Regexp
}

// DefaultSpawnPatterns returns the built-in spawn patterns.
func DefaultSpawnPatterns() []SpawnPattern {
	return []SpawnPattern{
		{
			ID:          "openai-handoff",
			Description: "OpenAI Agents SDK transfer/handoff to another agent",
			ToolPattern: "*transfer_to_*",
			ArgPatterns: []string{},
			Confidence:  0.90,
			SpawnType:   "delegation",
		},
		{
			ID:          "generic-create-agent",
			Description: "Generic agent creation tool calls",
			ToolPattern: "*create*agent*",
			ArgPatterns: []string{`"agent"`, `"assistant"`, `"model"`},
			Confidence:  0.85,
			SpawnType:   "direct",
		},
		{
			ID:          "delegation-flag",
			Description: "Tool arguments containing delegation-related keywords",
			ToolPattern: "*",
			ArgPatterns: []string{`"delegate"`, `"handoff"`, `"transfer"`, `"spawn_agent"`},
			Confidence:  0.75,
			SpawnType:   "delegation",
		},
		{
			ID:          "shell-agent-spawn",
			Description: "Shell/exec tools launching agent processes",
			ToolPattern: "*exec*",
			ArgPatterns: []string{`agent`, `assistant`, `claude`, `gpt`, `llm`},
			Confidence:  0.70,
			SpawnType:   "fork",
		},
		{
			ID:          "subtask-spawn",
			Description: "Task decomposition and subtask delegation",
			ToolPattern: "*task*",
			ArgPatterns: []string{`"subtask"`, `"sub_task"`, `"child_task"`, `"delegate_task"`},
			Confidence:  0.65,
			SpawnType:   "delegation",
		},
		{
			ID:          "a2a-delegation",
			Description: "Agent-to-Agent protocol delegation",
			ToolPattern: "*send_task*",
			ArgPatterns: []string{`"agent"`, `"task"`},
			Confidence:  0.85,
			SpawnType:   "delegation",
		},
		{
			ID:          "run-agent",
			Description: "Explicitly running or invoking another agent",
			ToolPattern: "*run*agent*",
			ArgPatterns: []string{},
			Confidence:  0.85,
			SpawnType:   "direct",
		},
		{
			ID:          "invoke-assistant",
			Description: "Invoking or calling an assistant",
			ToolPattern: "*invoke*assistant*",
			ArgPatterns: []string{},
			Confidence:  0.80,
			SpawnType:   "direct",
		},
	}
}

// NewSpawnDetector creates a detector with the given patterns.
// If patterns is nil, uses the default built-in patterns.
func NewSpawnDetector(patterns []SpawnPattern) *SpawnDetector {
	if patterns == nil {
		patterns = DefaultSpawnPatterns()
	}

	compiled := make([]compiledSpawnPattern, 0, len(patterns))
	for _, p := range patterns {
		cp := compiledSpawnPattern{SpawnPattern: p}

		// Compile tool pattern to regex (glob → regex)
		escaped := regexp.QuoteMeta(p.ToolPattern)
		escaped = strings.ReplaceAll(escaped, `\*`, ".*")
		escaped = strings.ReplaceAll(escaped, `\?`, ".")
		if re, err := regexp.Compile("(?i)^" + escaped + "$"); err == nil {
			cp.toolRegex = re
		}

		// Compile argument patterns
		for _, ap := range p.ArgPatterns {
			if re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(ap)); err == nil {
				cp.argRegexs = append(cp.argRegexs, re)
			}
		}

		compiled = append(compiled, cp)
	}

	return &SpawnDetector{patterns: compiled}
}

// DetectSpawn checks if a tool call looks like an agent spawn.
// Returns nil if no spawn pattern matches.
func (d *SpawnDetector) DetectSpawn(serverName, toolName, argsJSON, parentAgent string) *SpawnEvent {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, p := range d.patterns {
		if !d.matchPattern(p, toolName, argsJSON) {
			continue
		}

		childHint := extractChildHint(toolName, argsJSON)

		return &SpawnEvent{
			PatternID:    p.ID,
			ParentAgent:  parentAgent,
			ChildHint:    childHint,
			SpawnType:    p.SpawnType,
			Confidence:   p.Confidence,
			ToolName:     toolName,
			ServerName:   serverName,
			DetectedAt:   time.Now(),
			ArgumentsRef: truncateArgs(argsJSON, 256),
		}
	}

	return nil
}

func (d *SpawnDetector) matchPattern(p compiledSpawnPattern, toolName, argsJSON string) bool {
	// Tool name must match
	if p.toolRegex != nil && !p.toolRegex.MatchString(toolName) {
		return false
	}

	// If there are arg patterns, at least one must match
	if len(p.argRegexs) > 0 {
		matched := false
		for _, re := range p.argRegexs {
			if re.MatchString(argsJSON) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// LoadSpawnPatterns loads patterns from a JSON file.
// Falls back to default patterns on any error.
func LoadSpawnPatterns(path string) []SpawnPattern {
	if path == "" {
		return DefaultSpawnPatterns()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultSpawnPatterns()
	}

	var patterns []SpawnPattern
	if err := json.Unmarshal(data, &patterns); err != nil {
		return DefaultSpawnPatterns()
	}

	if len(patterns) == 0 {
		return DefaultSpawnPatterns()
	}

	return patterns
}

// extractChildHint tries to identify the child agent from tool name or arguments.
func extractChildHint(toolName, argsJSON string) string {
	// Pattern: transfer_to_<agent_name>
	if strings.HasPrefix(strings.ToLower(toolName), "transfer_to_") {
		return strings.TrimPrefix(strings.ToLower(toolName), "transfer_to_")
	}

	// Try to extract from common argument fields
	if argsJSON == "" {
		return ""
	}

	var args map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return ""
	}

	// Check common field names for child agent identifiers
	for _, key := range []string{"agent", "agent_name", "agent_id", "assistant", "assistant_id", "target_agent", "delegate_to"} {
		if v, ok := args[key]; ok {
			return fmt.Sprintf("%v", v)
		}
	}

	return ""
}

func truncateArgs(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
