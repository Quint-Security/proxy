package intercept

import (
	"crypto/sha256"
	"encoding/hex"
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
	ChildHint    string    `json:"child_hint"`    // extracted child agent identifier (always non-empty)
	SpawnType    string    `json:"spawn_type"`     // "direct", "delegation", "fork"
	Confidence   float64   `json:"confidence"`     // 0.0-1.0
	ToolName     string    `json:"tool_name"`
	ServerName   string    `json:"server_name"`
	DetectedAt   time.Time `json:"detected_at"`
	ArgumentsRef string    `json:"arguments_ref"`  // hash or truncated args for correlation
	Framework    string    `json:"framework,omitempty"` // detected agent framework (e.g., "openai", "claude", "langchain")
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

// DefaultSpawnPatterns returns the built-in spawn patterns covering the top
// agent frameworks: OpenAI Agents SDK, Claude/Anthropic, Codex, Gemini,
// LangChain/LangGraph, CrewAI, AutoGen, Semantic Kernel, AWS Bedrock,
// Vertex AI, GitHub Copilot, and generic A2A patterns.
func DefaultSpawnPatterns() []SpawnPattern {
	return []SpawnPattern{
		// --- OpenAI Agents SDK ---
		{
			ID:          "openai-handoff",
			Description: "OpenAI Agents SDK transfer/handoff to another agent",
			ToolPattern: "*transfer_to_*",
			ArgPatterns: []string{},
			Confidence:  0.90,
			SpawnType:   "delegation",
		},

		// --- Claude / Anthropic ---
		{
			ID:          "claude-agent-tool",
			Description: "Claude computer_use or Agent tool delegation",
			ToolPattern: "*Agent*",
			ArgPatterns: []string{`"prompt"`, `"subagent"`, `"task"`},
			Confidence:  0.85,
			SpawnType:   "delegation",
		},
		{
			ID:          "claude-subagent",
			Description: "Claude Code sub-agent invocation",
			ToolPattern: "*subagent*",
			ArgPatterns: []string{},
			Confidence:  0.85,
			SpawnType:   "direct",
		},

		// --- OpenAI Codex ---
		{
			ID:          "codex-spawn",
			Description: "Codex CLI agent spawn via exec or subprocess",
			ToolPattern: "*codex*",
			ArgPatterns: []string{`"agent"`, `"run"`, `"execute"`},
			Confidence:  0.80,
			SpawnType:   "fork",
		},

		// --- Google Gemini / Vertex AI ---
		{
			ID:          "gemini-function-call",
			Description: "Gemini agent delegation via function calling",
			ToolPattern: "*gemini*",
			ArgPatterns: []string{`"agent"`, `"delegate"`, `"function_call"`},
			Confidence:  0.80,
			SpawnType:   "delegation",
		},
		{
			ID:          "vertex-agent-builder",
			Description: "Vertex AI Agent Builder task dispatch",
			ToolPattern: "*dispatch*agent*",
			ArgPatterns: []string{},
			Confidence:  0.85,
			SpawnType:   "direct",
		},

		// --- LangChain / LangGraph ---
		{
			ID:          "langchain-agent-executor",
			Description: "LangChain AgentExecutor or chain delegation",
			ToolPattern: "*agent_executor*",
			ArgPatterns: []string{},
			Confidence:  0.85,
			SpawnType:   "direct",
		},
		{
			ID:          "langgraph-handoff",
			Description: "LangGraph node-to-node agent handoff",
			ToolPattern: "*handoff*",
			ArgPatterns: []string{`"agent"`, `"node"`, `"target"`},
			Confidence:  0.80,
			SpawnType:   "delegation",
		},

		// --- CrewAI ---
		{
			ID:          "crewai-delegate",
			Description: "CrewAI delegate_work or ask_question to crew member",
			ToolPattern: "*delegate_work*",
			ArgPatterns: []string{},
			Confidence:  0.90,
			SpawnType:   "delegation",
		},
		{
			ID:          "crewai-coworker",
			Description: "CrewAI coworker/crew member invocation",
			ToolPattern: "*ask_question*",
			ArgPatterns: []string{`"coworker"`, `"crew"`},
			Confidence:  0.80,
			SpawnType:   "delegation",
		},

		// --- Microsoft AutoGen ---
		{
			ID:          "autogen-initiate-chat",
			Description: "AutoGen agent initiate_chat or generate_reply",
			ToolPattern: "*initiate_chat*",
			ArgPatterns: []string{},
			Confidence:  0.85,
			SpawnType:   "delegation",
		},
		{
			ID:          "autogen-groupchat",
			Description: "AutoGen GroupChat agent spawn",
			ToolPattern: "*group_chat*",
			ArgPatterns: []string{`"agent"`, `"agents"`},
			Confidence:  0.80,
			SpawnType:   "direct",
		},

		// --- Microsoft Semantic Kernel ---
		{
			ID:          "semantic-kernel-invoke",
			Description: "Semantic Kernel agent/plugin invocation",
			ToolPattern: "*invoke*plugin*",
			ArgPatterns: []string{},
			Confidence:  0.80,
			SpawnType:   "direct",
		},

		// --- AWS Bedrock Agents ---
		{
			ID:          "bedrock-invoke-agent",
			Description: "AWS Bedrock InvokeAgent API",
			ToolPattern: "*invoke*agent*",
			ArgPatterns: []string{},
			Confidence:  0.85,
			SpawnType:   "direct",
		},
		{
			ID:          "bedrock-action-group",
			Description: "AWS Bedrock action group execution with agent delegation",
			ToolPattern: "*action_group*",
			ArgPatterns: []string{`"agent"`, `"invoke"`},
			Confidence:  0.75,
			SpawnType:   "delegation",
		},

		// --- GitHub Copilot ---
		{
			ID:          "copilot-agent",
			Description: "GitHub Copilot agent/extension invocation",
			ToolPattern: "*copilot*",
			ArgPatterns: []string{`"agent"`, `"extension"`, `"skill"`},
			Confidence:  0.75,
			SpawnType:   "delegation",
		},

		// --- Generic patterns (lower confidence, catch-all) ---
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

		// --- Real-world shell/subprocess patterns ---
		// Agents use generic tool names (Bash, shell, run, cmd, terminal)
		// with framework-specific commands in the arguments.
		{
			ID:          "bash-agent-spawn",
			Description: "Bash tool launching agent processes (Claude Code, etc.)",
			ToolPattern: "*bash*",
			ArgPatterns: []string{`claude`, `codex`, `gemini`, `gpt`, `anthropic`, `openai`, `agent`, `llm`, `copilot`},
			Confidence:  0.75,
			SpawnType:   "fork",
		},
		{
			ID:          "shell-tool-spawn",
			Description: "Shell tool launching agent processes",
			ToolPattern: "*shell*",
			ArgPatterns: []string{`claude`, `codex`, `gemini`, `gpt`, `anthropic`, `openai`, `agent`, `llm`, `copilot`},
			Confidence:  0.75,
			SpawnType:   "fork",
		},
		{
			ID:          "shell-agent-spawn",
			Description: "Shell/exec tools launching agent processes",
			ToolPattern: "*exec*",
			ArgPatterns: []string{`agent`, `assistant`, `claude`, `gpt`, `llm`, `codex`, `gemini`, `copilot`},
			Confidence:  0.70,
			SpawnType:   "fork",
		},
		{
			ID:          "terminal-agent-spawn",
			Description: "Terminal/console tool launching agent processes",
			ToolPattern: "*terminal*",
			ArgPatterns: []string{`claude`, `codex`, `gemini`, `gpt`, `anthropic`, `openai`, `agent`, `llm`, `copilot`},
			Confidence:  0.70,
			SpawnType:   "fork",
		},
		{
			ID:          "cmd-agent-spawn",
			Description: "Command tool launching agent processes",
			ToolPattern: "*command*",
			ArgPatterns: []string{`claude`, `codex`, `gemini`, `gpt`, `anthropic`, `openai`, `agent`, `llm`, `copilot`},
			Confidence:  0.70,
			SpawnType:   "fork",
		},
		{
			ID:          "subprocess-agent",
			Description: "Subprocess/spawn launching agent processes",
			ToolPattern: "*spawn*",
			ArgPatterns: []string{`agent`, `assistant`, `claude`, `gpt`, `llm`, `codex`, `gemini`, `copilot`},
			Confidence:  0.70,
			SpawnType:   "fork",
		},

		// --- Framework-specific CLI spawning via any tool ---
		// Detects when any tool (including wildcards) runs a specific
		// framework's CLI command as a subprocess.
		{
			ID:          "claude-cli-spawn",
			Description: "Any tool spawning Claude CLI as subprocess",
			ToolPattern: "*",
			ArgPatterns: []string{`"claude "`, `"claude\n`, `claude code`, `claude agent`, `npx @anthropic`},
			Confidence:  0.80,
			SpawnType:   "fork",
		},
		{
			ID:          "codex-cli-spawn",
			Description: "Any tool spawning Codex CLI as subprocess",
			ToolPattern: "*",
			ArgPatterns: []string{`"codex "`, `"codex\n`, `codex agent`, `codex run`, `npx codex`},
			Confidence:  0.80,
			SpawnType:   "fork",
		},
		{
			ID:          "gemini-cli-spawn",
			Description: "Any tool spawning Gemini CLI as subprocess",
			ToolPattern: "*",
			ArgPatterns: []string{`"gemini "`, `"gemini\n`, `gemini agent`, `gemini run`, `npx @google`},
			Confidence:  0.80,
			SpawnType:   "fork",
		},
		{
			ID:          "interpreter-agent-spawn",
			Description: "Python/Node interpreter launching agent scripts",
			ToolPattern: "*",
			ArgPatterns: []string{`python agent`, `python -m agent`, `node agent`, `npx agent`, `python claude`, `python codex`, `python gemini`},
			Confidence:  0.65,
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
// When a spawn is detected but no explicit child identity is found,
// a deterministic child ID is generated from the call content to prevent
// conflation of distinct children.
func (d *SpawnDetector) DetectSpawn(serverName, toolName, argsJSON, parentAgent string) *SpawnEvent {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, p := range d.patterns {
		if !d.matchPattern(p, toolName, argsJSON) {
			continue
		}

		childHint := extractChildHint(toolName, argsJSON)

		// Generate deterministic child ID when no explicit hint is available.
		// This prevents multiple distinct children from being conflated into
		// a single "unknown:server:tool" relationship.
		if childHint == "" {
			childHint = fmt.Sprintf("child:%s:%s:%s",
				serverName, toolName, deterministicChildID(serverName, toolName, argsJSON))
		}

		// Detect framework from pattern and args
		framework := inferFramework(p.ID, toolName, argsJSON)

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
			Framework:    framework,
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
// Returns a non-empty string in all cases to prevent child conflation.
// When no explicit child identity is found, generates a deterministic ID from
// the tool call content so distinct calls produce distinct children.
func extractChildHint(toolName, argsJSON string) string {
	// Pattern: transfer_to_<agent_name>
	lower := strings.ToLower(toolName)
	if strings.HasPrefix(lower, "transfer_to_") {
		return strings.TrimPrefix(lower, "transfer_to_")
	}

	// Pattern: delegate_work_to_<agent>
	if strings.HasPrefix(lower, "delegate_work_to_") {
		return strings.TrimPrefix(lower, "delegate_work_to_")
	}

	// Try to extract from common argument fields (expanded for framework coverage)
	if argsJSON != "" {
		var args map[string]any
		if err := json.Unmarshal([]byte(argsJSON), &args); err == nil {
			// Check nested objects first: args.agent.name, args.agent.id
			// (must come before top-level "agent" check to avoid stringifying a map)
			if agentObj, ok := args["agent"].(map[string]any); ok {
				for _, sub := range []string{"name", "id", "agent_id"} {
					if v, ok := agentObj[sub]; ok {
						s := fmt.Sprintf("%v", v)
						if s != "" && s != "<nil>" {
							return s
						}
					}
				}
			}

			// Priority-ordered list of keys that identify the child agent
			for _, key := range []string{
				"agent", "agent_name", "agent_id",
				"assistant", "assistant_id", "assistant_name",
				"target_agent", "delegate_to", "recipient",
				"coworker",                 // CrewAI
				"node", "target_node",      // LangGraph
				"agentId", "agentName",     // Bedrock
				"model", "model_id",        // generic model-based agents
				"skill", "extension",       // Copilot
				"subagent_type",            // Claude Code
			} {
				if v, ok := args[key]; ok {
					// Skip map/slice values — they need nested extraction
					switch v.(type) {
					case map[string]any, []any:
						continue
					}
					s := fmt.Sprintf("%v", v)
					if s != "" && s != "<nil>" {
						return s
					}
				}
			}
		}
	}

	return ""
}

// deterministicChildID generates a short deterministic ID from the tool call
// content. Two calls with identical tool+args produce the same ID; different
// args produce different IDs. This prevents conflation of distinct children
// that lack an explicit child hint.
func deterministicChildID(serverName, toolName, argsJSON string) string {
	h := sha256.New()
	h.Write([]byte(serverName))
	h.Write([]byte{0})
	h.Write([]byte(toolName))
	h.Write([]byte{0})
	h.Write([]byte(argsJSON))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// inferFramework identifies the agent framework from the spawn pattern ID,
// tool name, and argument signatures. Returns empty string if unknown.
func inferFramework(patternID, toolName, argsJSON string) string {
	// Direct mapping from pattern IDs to frameworks
	patternFrameworks := map[string]string{
		"openai-handoff":           "openai",
		"claude-agent-tool":        "claude",
		"claude-subagent":          "claude",
		"claude-cli-spawn":         "claude",
		"codex-spawn":              "codex",
		"codex-cli-spawn":          "codex",
		"gemini-function-call":     "gemini",
		"gemini-cli-spawn":         "gemini",
		"vertex-agent-builder":     "vertex-ai",
		"langchain-agent-executor": "langchain",
		"langgraph-handoff":        "langgraph",
		"crewai-delegate":          "crewai",
		"crewai-coworker":          "crewai",
		"autogen-initiate-chat":    "autogen",
		"autogen-groupchat":        "autogen",
		"semantic-kernel-invoke":   "semantic-kernel",
		"bedrock-invoke-agent":     "bedrock",
		"bedrock-action-group":     "bedrock",
		"copilot-agent":            "copilot",
		"a2a-delegation":           "a2a",
	}
	if fw, ok := patternFrameworks[patternID]; ok {
		return fw
	}

	// Fallback: detect from tool name or args for generic patterns
	lower := strings.ToLower(toolName)
	argLower := strings.ToLower(argsJSON)

	frameworkSignals := []struct {
		keywords  []string
		framework string
	}{
		{[]string{"claude", "anthropic"}, "claude"},
		{[]string{"openai", "gpt", "chatgpt"}, "openai"},
		{[]string{"codex"}, "codex"},
		{[]string{"gemini", "google_ai"}, "gemini"},
		{[]string{"langchain", "langgraph"}, "langchain"},
		{[]string{"crewai", "crew_ai", "coworker"}, "crewai"},
		{[]string{"autogen", "auto_gen"}, "autogen"},
		{[]string{"semantic_kernel"}, "semantic-kernel"},
		{[]string{"bedrock"}, "bedrock"},
		{[]string{"vertex"}, "vertex-ai"},
		{[]string{"copilot"}, "copilot"},
	}

	combined := lower + " " + argLower
	for _, fs := range frameworkSignals {
		for _, kw := range fs.keywords {
			if strings.Contains(combined, kw) {
				return fs.framework
			}
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
