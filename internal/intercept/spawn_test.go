package intercept

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// DefaultSpawnPatterns coverage
// ---------------------------------------------------------------------------

func TestDefaultSpawnPatterns_CoversMajorFrameworks(t *testing.T) {
	patterns := DefaultSpawnPatterns()

	requiredIDs := []string{
		"openai-handoff",
		"claude-agent-tool",
		"claude-subagent",
		"codex-spawn",
		"gemini-function-call",
		"vertex-agent-builder",
		"langchain-agent-executor",
		"langgraph-handoff",
		"crewai-delegate",
		"crewai-coworker",
		"autogen-initiate-chat",
		"autogen-groupchat",
		"semantic-kernel-invoke",
		"bedrock-invoke-agent",
		"bedrock-action-group",
		"copilot-agent",
		"a2a-delegation",
		"generic-create-agent",
		"bash-agent-spawn",
		"shell-tool-spawn",
		"shell-agent-spawn",
		"terminal-agent-spawn",
		"cmd-agent-spawn",
		"subprocess-agent",
		"claude-cli-spawn",
		"codex-cli-spawn",
		"gemini-cli-spawn",
		"interpreter-agent-spawn",
		"run-agent",
		"invoke-assistant",
	}

	idSet := make(map[string]bool)
	for _, p := range patterns {
		idSet[p.ID] = true
	}

	for _, id := range requiredIDs {
		if !idSet[id] {
			t.Errorf("missing required pattern: %s", id)
		}
	}
}

// ---------------------------------------------------------------------------
// DetectSpawn — framework-specific detection
// ---------------------------------------------------------------------------

func TestDetectSpawn_OpenAIHandoff(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("openai", "transfer_to_triage_agent", `{}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for transfer_to_triage_agent")
	}
	if ev.PatternID != "openai-handoff" {
		t.Errorf("pattern=%s, want openai-handoff", ev.PatternID)
	}
	if ev.ChildHint != "triage_agent" {
		t.Errorf("child_hint=%s, want triage_agent", ev.ChildHint)
	}
	if ev.Framework != "openai" {
		t.Errorf("framework=%s, want openai", ev.Framework)
	}
}

func TestDetectSpawn_ClaudeAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"prompt":"research this topic","subagent":"researcher"}`
	ev := d.DetectSpawn("claude", "Agent", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for Claude Agent tool")
	}
	if ev.PatternID != "claude-agent-tool" {
		t.Errorf("pattern=%s, want claude-agent-tool", ev.PatternID)
	}
	if ev.Framework != "claude" {
		t.Errorf("framework=%s, want claude", ev.Framework)
	}
}

func TestDetectSpawn_ClaudeSubagent(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("claude-code", "launch_subagent", `{}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for claude subagent")
	}
	if ev.PatternID != "claude-subagent" {
		t.Errorf("pattern=%s, want claude-subagent", ev.PatternID)
	}
}

func TestDetectSpawn_Codex(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"code-reviewer","run":"analyze"}`
	ev := d.DetectSpawn("openai", "codex_run", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for codex")
	}
	if ev.PatternID != "codex-spawn" {
		t.Errorf("pattern=%s, want codex-spawn", ev.PatternID)
	}
	if ev.Framework != "codex" {
		t.Errorf("framework=%s, want codex", ev.Framework)
	}
}

func TestDetectSpawn_Gemini(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"researcher","delegate":true}`
	ev := d.DetectSpawn("google", "gemini_call", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for gemini")
	}
	if ev.Framework != "gemini" {
		t.Errorf("framework=%s, want gemini", ev.Framework)
	}
}

func TestDetectSpawn_LangChainAgentExecutor(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("langchain", "run_agent_executor", `{}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for langchain agent_executor")
	}
	if ev.PatternID != "langchain-agent-executor" {
		t.Errorf("pattern=%s, want langchain-agent-executor", ev.PatternID)
	}
	if ev.Framework != "langchain" {
		t.Errorf("framework=%s, want langchain", ev.Framework)
	}
}

func TestDetectSpawn_LangGraphHandoff(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"writer","node":"summarize"}`
	ev := d.DetectSpawn("langgraph", "handoff_to_node", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for langgraph handoff")
	}
	if ev.Framework != "langgraph" {
		t.Errorf("framework=%s, want langgraph", ev.Framework)
	}
}

func TestDetectSpawn_CrewAIDelegate(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("crewai", "delegate_work", `{"coworker":"analyst"}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for crewai delegate_work")
	}
	if ev.PatternID != "crewai-delegate" {
		t.Errorf("pattern=%s, want crewai-delegate", ev.PatternID)
	}
	if ev.ChildHint != "analyst" {
		t.Errorf("child_hint=%s, want analyst", ev.ChildHint)
	}
	if ev.Framework != "crewai" {
		t.Errorf("framework=%s, want crewai", ev.Framework)
	}
}

func TestDetectSpawn_CrewAIAskQuestion(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("crewai", "ask_question", `{"coworker":"researcher","question":"what is X?"}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for crewai ask_question")
	}
	if ev.PatternID != "crewai-coworker" {
		t.Errorf("pattern=%s, want crewai-coworker", ev.PatternID)
	}
}

func TestDetectSpawn_AutoGenInitiateChat(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("autogen", "initiate_chat", `{}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for autogen initiate_chat")
	}
	if ev.PatternID != "autogen-initiate-chat" {
		t.Errorf("pattern=%s, want autogen-initiate-chat", ev.PatternID)
	}
	if ev.Framework != "autogen" {
		t.Errorf("framework=%s, want autogen", ev.Framework)
	}
}

func TestDetectSpawn_AutoGenGroupChat(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agents":["coder","reviewer"]}`
	ev := d.DetectSpawn("autogen", "start_group_chat", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for autogen group_chat")
	}
	if ev.PatternID != "autogen-groupchat" {
		t.Errorf("pattern=%s, want autogen-groupchat", ev.PatternID)
	}
}

func TestDetectSpawn_SemanticKernel(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("semantic-kernel", "invoke_plugin_agent", `{}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for semantic kernel")
	}
	if ev.PatternID != "semantic-kernel-invoke" {
		t.Errorf("pattern=%s, want semantic-kernel-invoke", ev.PatternID)
	}
	if ev.Framework != "semantic-kernel" {
		t.Errorf("framework=%s, want semantic-kernel", ev.Framework)
	}
}

func TestDetectSpawn_BedrockInvokeAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("bedrock", "invoke_agent", `{}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for bedrock invoke_agent")
	}
	if ev.PatternID != "bedrock-invoke-agent" {
		t.Errorf("pattern=%s, want bedrock-invoke-agent", ev.PatternID)
	}
	if ev.Framework != "bedrock" {
		t.Errorf("framework=%s, want bedrock", ev.Framework)
	}
}

func TestDetectSpawn_BedrockActionGroup(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"data-processor","invoke":true}`
	ev := d.DetectSpawn("bedrock", "run_action_group", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for bedrock action_group")
	}
	if ev.PatternID != "bedrock-action-group" {
		t.Errorf("pattern=%s, want bedrock-action-group", ev.PatternID)
	}
}

func TestDetectSpawn_CopilotAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"code-reviewer","skill":"review"}`
	ev := d.DetectSpawn("github", "copilot_invoke", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for copilot")
	}
	if ev.PatternID != "copilot-agent" {
		t.Errorf("pattern=%s, want copilot-agent", ev.PatternID)
	}
	if ev.Framework != "copilot" {
		t.Errorf("framework=%s, want copilot", ev.Framework)
	}
}

func TestDetectSpawn_VertexAgentBuilder(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("vertex", "dispatch_agent_task", `{}`, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for vertex dispatch_agent")
	}
	if ev.PatternID != "vertex-agent-builder" {
		t.Errorf("pattern=%s, want vertex-agent-builder", ev.PatternID)
	}
	if ev.Framework != "vertex-ai" {
		t.Errorf("framework=%s, want vertex-ai", ev.Framework)
	}
}

func TestDetectSpawn_A2ADelegation(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"worker","task":"process_data"}`
	ev := d.DetectSpawn("a2a", "send_task", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for a2a send_task")
	}
	if ev.PatternID != "a2a-delegation" {
		t.Errorf("pattern=%s, want a2a-delegation", ev.PatternID)
	}
	if ev.Framework != "a2a" {
		t.Errorf("framework=%s, want a2a", ev.Framework)
	}
}

func TestDetectSpawn_SubprocessAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"command":"claude agent run"}`
	ev := d.DetectSpawn("shell", "spawn_process", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for subprocess agent")
	}
	if ev.PatternID != "subprocess-agent" {
		t.Errorf("pattern=%s, want subprocess-agent", ev.PatternID)
	}
}

func TestDetectSpawn_NoMatch(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("filesystem", "read_file", `{"path":"/tmp/test.txt"}`, "parent-1")
	if ev != nil {
		t.Errorf("expected nil for non-spawn tool, got pattern=%s", ev.PatternID)
	}
}

// ---------------------------------------------------------------------------
// extractChildHint — deterministic child ID generation
// ---------------------------------------------------------------------------

func TestExtractChildHint_TransferTo(t *testing.T) {
	hint := extractChildHint("transfer_to_researcher", "")
	if hint != "researcher" {
		t.Errorf("hint=%s, want researcher", hint)
	}
}

func TestExtractChildHint_DelegateWorkTo(t *testing.T) {
	hint := extractChildHint("delegate_work_to_analyst", "")
	if hint != "analyst" {
		t.Errorf("hint=%s, want analyst", hint)
	}
}

func TestExtractChildHint_FromArgs_Agent(t *testing.T) {
	hint := extractChildHint("some_tool", `{"agent":"code-reviewer"}`)
	if hint != "code-reviewer" {
		t.Errorf("hint=%s, want code-reviewer", hint)
	}
}

func TestExtractChildHint_FromArgs_Coworker(t *testing.T) {
	hint := extractChildHint("ask_question", `{"coworker":"analyst","question":"what?"}`)
	if hint != "analyst" {
		t.Errorf("hint=%s, want analyst", hint)
	}
}

func TestExtractChildHint_FromArgs_NestedAgent(t *testing.T) {
	hint := extractChildHint("invoke", `{"agent":{"name":"deep-agent","id":"123"}}`)
	if hint != "deep-agent" {
		t.Errorf("hint=%s, want deep-agent", hint)
	}
}

func TestExtractChildHint_FromArgs_NestedAgentID(t *testing.T) {
	hint := extractChildHint("invoke", `{"agent":{"id":"agent-42"}}`)
	if hint != "agent-42" {
		t.Errorf("hint=%s, want agent-42", hint)
	}
}

func TestExtractChildHint_FromArgs_SubagentType(t *testing.T) {
	hint := extractChildHint("Agent", `{"subagent_type":"Explore","prompt":"find files"}`)
	if hint != "Explore" {
		t.Errorf("hint=%s, want Explore", hint)
	}
}

func TestExtractChildHint_FromArgs_AssistantName(t *testing.T) {
	hint := extractChildHint("invoke_assistant", `{"assistant_name":"helper-bot"}`)
	if hint != "helper-bot" {
		t.Errorf("hint=%s, want helper-bot", hint)
	}
}

func TestExtractChildHint_FromArgs_TargetAgent(t *testing.T) {
	hint := extractChildHint("delegate", `{"target_agent":"worker-1"}`)
	if hint != "worker-1" {
		t.Errorf("hint=%s, want worker-1", hint)
	}
}

func TestExtractChildHint_EmptyReturnsEmpty(t *testing.T) {
	hint := extractChildHint("exec", `{"command":"ls -la"}`)
	if hint != "" {
		t.Errorf("expected empty hint for non-agent args, got %s", hint)
	}
}

func TestExtractChildHint_InvalidJSON(t *testing.T) {
	hint := extractChildHint("exec", "not-json")
	if hint != "" {
		t.Errorf("expected empty hint for invalid JSON, got %s", hint)
	}
}

func TestExtractChildHint_EmptyArgs(t *testing.T) {
	hint := extractChildHint("transfer_agent", "")
	if hint != "" {
		t.Errorf("expected empty hint for empty args, got %s", hint)
	}
}

// ---------------------------------------------------------------------------
// deterministicChildID
// ---------------------------------------------------------------------------

func TestDeterministicChildID_Deterministic(t *testing.T) {
	id1 := deterministicChildID("server", "tool", `{"arg":"value"}`)
	id2 := deterministicChildID("server", "tool", `{"arg":"value"}`)
	if id1 != id2 {
		t.Errorf("expected deterministic ID, got %s != %s", id1, id2)
	}
}

func TestDeterministicChildID_DifferentArgs(t *testing.T) {
	id1 := deterministicChildID("server", "exec", `{"cmd":"agent1"}`)
	id2 := deterministicChildID("server", "exec", `{"cmd":"agent2"}`)
	if id1 == id2 {
		t.Error("expected different IDs for different args")
	}
}

func TestDeterministicChildID_DifferentServers(t *testing.T) {
	id1 := deterministicChildID("server-a", "tool", `{}`)
	id2 := deterministicChildID("server-b", "tool", `{}`)
	if id1 == id2 {
		t.Error("expected different IDs for different servers")
	}
}

func TestDeterministicChildID_Length(t *testing.T) {
	id := deterministicChildID("server", "tool", `{}`)
	if len(id) != 12 {
		t.Errorf("expected 12-char ID, got %d chars: %s", len(id), id)
	}
}

// ---------------------------------------------------------------------------
// DetectSpawn — child hint always non-empty
// ---------------------------------------------------------------------------

func TestDetectSpawn_ChildHintNeverEmpty(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Generic delegation pattern with no child identity in args
	args := `{"delegate":true,"data":"some data"}`
	ev := d.DetectSpawn("shell", "run_tool", args, "parent-1")
	if ev == nil {
		t.Fatal("expected spawn event for delegation keyword")
	}
	if ev.ChildHint == "" {
		t.Error("child_hint must never be empty after fix")
	}
	if !strings.HasPrefix(ev.ChildHint, "child:") {
		t.Errorf("expected deterministic child ID prefix 'child:', got %s", ev.ChildHint)
	}
}

func TestDetectSpawn_DifferentArgsProduceDifferentChildren(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Same tool, different args — should produce different child IDs
	ev1 := d.DetectSpawn("shell", "exec_command", `{"command":"claude agent run task1"}`, "parent-1")
	ev2 := d.DetectSpawn("shell", "exec_command", `{"command":"claude agent run task2"}`, "parent-1")

	if ev1 == nil || ev2 == nil {
		t.Fatal("expected spawn events for both exec calls")
	}
	if ev1.ChildHint == ev2.ChildHint {
		t.Errorf("different args should produce different children: both got %s", ev1.ChildHint)
	}
}

func TestDetectSpawn_SameArgsProduceSameChild(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Same tool, same args — should produce same child ID (idempotent)
	args := `{"command":"claude agent run"}`
	ev1 := d.DetectSpawn("shell", "exec_command", args, "parent-1")
	ev2 := d.DetectSpawn("shell", "exec_command", args, "parent-1")

	if ev1 == nil || ev2 == nil {
		t.Fatal("expected spawn events for both exec calls")
	}
	if ev1.ChildHint != ev2.ChildHint {
		t.Errorf("same args should produce same child: %s != %s", ev1.ChildHint, ev2.ChildHint)
	}
}

// ---------------------------------------------------------------------------
// inferFramework
// ---------------------------------------------------------------------------

func TestInferFramework_PatternMapping(t *testing.T) {
	tests := []struct {
		patternID string
		want      string
	}{
		{"openai-handoff", "openai"},
		{"claude-agent-tool", "claude"},
		{"claude-subagent", "claude"},
		{"codex-spawn", "codex"},
		{"gemini-function-call", "gemini"},
		{"vertex-agent-builder", "vertex-ai"},
		{"langchain-agent-executor", "langchain"},
		{"langgraph-handoff", "langgraph"},
		{"crewai-delegate", "crewai"},
		{"crewai-coworker", "crewai"},
		{"autogen-initiate-chat", "autogen"},
		{"autogen-groupchat", "autogen"},
		{"semantic-kernel-invoke", "semantic-kernel"},
		{"bedrock-invoke-agent", "bedrock"},
		{"bedrock-action-group", "bedrock"},
		{"copilot-agent", "copilot"},
		{"a2a-delegation", "a2a"},
	}

	for _, tt := range tests {
		got := inferFramework(tt.patternID, "", "")
		if got != tt.want {
			t.Errorf("inferFramework(%q) = %q, want %q", tt.patternID, got, tt.want)
		}
	}
}

func TestInferFramework_FallbackFromToolName(t *testing.T) {
	tests := []struct {
		tool string
		want string
	}{
		{"claude_code_run", "claude"},
		{"openai_dispatch", "openai"},
		{"run_gemini_agent", "gemini"},
		{"langchain_chain", "langchain"},
		{"crewai_delegate", "crewai"},
		{"autogen_chat", "autogen"},
		{"bedrock_invoke", "bedrock"},
		{"copilot_suggest", "copilot"},
	}

	for _, tt := range tests {
		got := inferFramework("generic-create-agent", tt.tool, "")
		if got != tt.want {
			t.Errorf("inferFramework(generic, %q) = %q, want %q", tt.tool, got, tt.want)
		}
	}
}

func TestInferFramework_FallbackFromArgs(t *testing.T) {
	got := inferFramework("delegation-flag", "delegate_task", `{"model":"anthropic.claude","delegate":true}`)
	if got != "claude" {
		t.Errorf("expected claude from args, got %q", got)
	}
}

func TestInferFramework_UnknownReturnsEmpty(t *testing.T) {
	got := inferFramework("unknown-pattern", "random_tool", `{"key":"value"}`)
	if got != "" {
		t.Errorf("expected empty for unknown, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// LoadSpawnPatterns
// ---------------------------------------------------------------------------

func TestLoadSpawnPatterns_EmptyPath(t *testing.T) {
	patterns := LoadSpawnPatterns("")
	if len(patterns) == 0 {
		t.Error("expected default patterns for empty path")
	}
	if len(patterns) < 50 {
		t.Errorf("expected at least 50 patterns, got %d", len(patterns))
	}
}

func TestLoadSpawnPatterns_NonexistentFile(t *testing.T) {
	patterns := LoadSpawnPatterns("/nonexistent/file.json")
	if len(patterns) == 0 {
		t.Error("expected default patterns for nonexistent file")
	}
}

// ---------------------------------------------------------------------------
// SpawnEvent JSON serialization (Framework field)
// ---------------------------------------------------------------------------

func TestSpawnEvent_FrameworkInJSON(t *testing.T) {
	ev := SpawnEvent{
		PatternID: "openai-handoff",
		ChildHint: "triage",
		Framework: "openai",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"framework":"openai"`) {
		t.Errorf("expected framework in JSON, got %s", s)
	}
}

func TestSpawnEvent_EmptyFrameworkOmitted(t *testing.T) {
	ev := SpawnEvent{
		PatternID: "generic",
		ChildHint: "child",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "framework") {
		t.Errorf("expected framework omitted when empty, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// truncateArgs
// ---------------------------------------------------------------------------

func TestTruncateArgs(t *testing.T) {
	short := "hello"
	if truncateArgs(short, 256) != short {
		t.Error("short string should not be truncated")
	}

	long := strings.Repeat("x", 300)
	result := truncateArgs(long, 256)
	if len(result) != 256 {
		t.Errorf("expected 256 chars, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// matchPattern
// ---------------------------------------------------------------------------

func TestMatchPattern_ToolOnly(t *testing.T) {
	d := NewSpawnDetector([]SpawnPattern{
		{ID: "test", ToolPattern: "*agent*", Confidence: 0.9, SpawnType: "direct"},
	})
	ev := d.DetectSpawn("s", "run_agent_task", `{}`, "p")
	if ev == nil {
		t.Error("expected match for *agent* pattern")
	}
}

func TestMatchPattern_ToolAndArgs(t *testing.T) {
	d := NewSpawnDetector([]SpawnPattern{
		{ID: "test", ToolPattern: "*exec*", ArgPatterns: []string{`claude`}, Confidence: 0.7, SpawnType: "fork"},
	})

	// Matches tool + args
	ev := d.DetectSpawn("s", "exec_command", `{"cmd":"claude run"}`, "p")
	if ev == nil {
		t.Error("expected match when tool and args match")
	}

	// Matches tool but not args — should NOT match
	ev = d.DetectSpawn("s", "exec_command", `{"cmd":"ls -la"}`, "p")
	if ev != nil {
		t.Error("expected no match when args don't match")
	}
}

func TestMatchPattern_CaseInsensitive(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("s", "Transfer_To_Alice", `{}`, "p")
	if ev == nil {
		t.Error("expected case-insensitive match for Transfer_To_Alice")
	}
	if ev.ChildHint != "alice" {
		t.Errorf("child_hint=%s, want alice", ev.ChildHint)
	}
}

// ---------------------------------------------------------------------------
// Real-world subprocess detection — Claude, Codex, Gemini
// These tests simulate the actual tool names and arguments used by each
// framework when spawning subprocesses through the proxy.
// ---------------------------------------------------------------------------

func TestDetectSpawn_RealWorld_ClaudeBashSubprocess(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Claude Code uses "Bash" tool to spawn claude CLI
	args := `{"command":"claude code --help"}`
	ev := d.DetectSpawn("claude-code-server", "Bash", args, "claude-agent-1")
	if ev == nil {
		t.Fatal("expected spawn detection for Bash tool running 'claude code'")
	}
	if ev.Framework != "claude" {
		t.Errorf("framework=%s, want claude", ev.Framework)
	}
	if ev.SpawnType != "fork" {
		t.Errorf("spawn_type=%s, want fork", ev.SpawnType)
	}
}

func TestDetectSpawn_RealWorld_ClaudeBashAgent(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Claude spawning another agent via bash
	args := `{"command":"claude agent run --task 'analyze code'"}`
	ev := d.DetectSpawn("mcp-server", "Bash", args, "claude-parent")
	if ev == nil {
		t.Fatal("expected spawn detection for Bash tool running 'claude agent'")
	}
	if ev.Framework != "claude" {
		t.Errorf("framework=%s, want claude", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_CodexShellSubprocess(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Codex uses "shell" tool
	args := `{"command":"codex run --task review"}`
	ev := d.DetectSpawn("codex-server", "shell", args, "codex-agent-1")
	if ev == nil {
		t.Fatal("expected spawn detection for shell tool running 'codex run'")
	}
	if ev.Framework != "codex" {
		t.Errorf("framework=%s, want codex", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_CodexExecSubprocess(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Codex via exec_command
	args := `{"cmd":"npx codex agent --file test.py"}`
	ev := d.DetectSpawn("code-server", "exec_command", args, "codex-parent")
	if ev == nil {
		t.Fatal("expected spawn detection for exec_command running 'npx codex'")
	}
	if ev.Framework != "codex" {
		t.Errorf("framework=%s, want codex", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_GeminiShellSubprocess(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Gemini using shell to spawn another agent
	args := `{"command":"gemini agent run --model pro"}`
	ev := d.DetectSpawn("gemini-server", "shell", args, "gemini-agent-1")
	if ev == nil {
		t.Fatal("expected spawn detection for shell tool running 'gemini agent'")
	}
	if ev.Framework != "gemini" {
		t.Errorf("framework=%s, want gemini", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_GeminiBashSubprocess(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Gemini via Bash tool
	args := `{"command":"gemini run task --input data.json"}`
	ev := d.DetectSpawn("google-ai", "Bash", args, "gemini-parent")
	if ev == nil {
		t.Fatal("expected spawn detection for Bash tool running 'gemini run'")
	}
	if ev.Framework != "gemini" {
		t.Errorf("framework=%s, want gemini", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_TerminalAgentSpawn(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Agent spawned via terminal tool
	args := `{"input":"claude code review src/"}`
	ev := d.DetectSpawn("ide-server", "terminal_exec", args, "ide-agent")
	if ev == nil {
		t.Fatal("expected spawn detection for terminal_exec running claude")
	}
	if ev.Framework != "claude" {
		t.Errorf("framework=%s, want claude", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_RunCommandAgentSpawn(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Agent spawned via run_command tool
	args := `{"command":"codex agent analyze"}`
	ev := d.DetectSpawn("server", "run_command", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn detection for run_command running codex")
	}
	if ev.Framework != "codex" {
		t.Errorf("framework=%s, want codex", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_NoFalsePositive_BashLs(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Regular bash command should NOT trigger spawn detection
	args := `{"command":"ls -la /tmp"}`
	ev := d.DetectSpawn("server", "Bash", args, "agent")
	if ev != nil {
		t.Errorf("expected no spawn for 'ls -la', got pattern=%s", ev.PatternID)
	}
}

func TestDetectSpawn_RealWorld_NoFalsePositive_ShellGrep(t *testing.T) {
	d := NewSpawnDetector(nil)

	// Regular shell command should NOT trigger
	args := `{"command":"grep -r 'TODO' src/"}`
	ev := d.DetectSpawn("server", "shell", args, "agent")
	if ev != nil {
		t.Errorf("expected no spawn for 'grep', got pattern=%s", ev.PatternID)
	}
}

func TestDetectSpawn_RealWorld_ClaudeCliSpawn_WildcardTool(t *testing.T) {
	d := NewSpawnDetector(nil)

	// The claude-cli-spawn pattern uses "*" tool pattern, catching ANY tool
	// that runs claude CLI commands in arguments
	args := `{"script":"claude code --task 'fix bug'"}`
	ev := d.DetectSpawn("custom-server", "run_script", args, "orchestrator")
	if ev == nil {
		t.Fatal("expected claude-cli-spawn to catch 'claude code' in any tool")
	}
	if ev.Framework != "claude" {
		t.Errorf("framework=%s, want claude", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_NpxAnthropicSpawn(t *testing.T) {
	d := NewSpawnDetector(nil)

	// npx @anthropic packages
	args := `{"command":"npx @anthropic/claude-agent run"}`
	ev := d.DetectSpawn("server", "Bash", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn detection for npx @anthropic")
	}
	if ev.Framework != "claude" {
		t.Errorf("framework=%s, want claude", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_DefaultPatterns_NewIDs(t *testing.T) {
	patterns := DefaultSpawnPatterns()
	idSet := make(map[string]bool)
	for _, p := range patterns {
		idSet[p.ID] = true
	}

	newIDs := []string{
		"bash-agent-spawn",
		"shell-tool-spawn",
		"terminal-agent-spawn",
		"cmd-agent-spawn",
		"claude-cli-spawn",
		"codex-cli-spawn",
		"gemini-cli-spawn",
		"interpreter-agent-spawn",
	}
	for _, id := range newIDs {
		if !idSet[id] {
			t.Errorf("missing new pattern: %s", id)
		}
	}
}

func TestInferFramework_NewCLIPatterns(t *testing.T) {
	tests := []struct {
		patternID string
		want      string
	}{
		{"claude-cli-spawn", "claude"},
		{"codex-cli-spawn", "codex"},
		{"gemini-cli-spawn", "gemini"},
		{"aider-cli-spawn", "aider"},
		{"cursor-cli-spawn", "cursor"},
		{"devin-cli-spawn", "devin"},
		{"swe-agent-cli-spawn", "swe-agent"},
		{"amazon-q-cli-spawn", "amazon-q"},
	}
	for _, tt := range tests {
		got := inferFramework(tt.patternID, "", "")
		if got != tt.want {
			t.Errorf("inferFramework(%q) = %q, want %q", tt.patternID, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Coding IDE spawn detection
// ---------------------------------------------------------------------------

func TestDetectSpawn_CursorAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"code-reviewer","task":"review PR"}`
	ev := d.DetectSpawn("cursor-server", "cursor_agent_run", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for cursor agent")
	}
	if ev.Framework != "cursor" {
		t.Errorf("framework=%s, want cursor", ev.Framework)
	}
}

func TestDetectSpawn_CursorTerminal(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"command":"claude code --task 'fix tests'"}`
	ev := d.DetectSpawn("cursor", "run_terminal_command", args, "cursor-agent")
	if ev == nil {
		t.Fatal("expected spawn event for cursor run_terminal_command")
	}
	if ev.SpawnType != "fork" {
		t.Errorf("spawn_type=%s, want fork", ev.SpawnType)
	}
}

func TestDetectSpawn_CursorComposer(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"multi-file","task":"refactor","apply":true}`
	ev := d.DetectSpawn("cursor", "composer_run", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for cursor composer")
	}
	if ev.Framework != "cursor" {
		t.Errorf("framework=%s, want cursor", ev.Framework)
	}
}

func TestDetectSpawn_WindsurfCascade(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"analyzer","step":"plan"}`
	ev := d.DetectSpawn("windsurf", "cascade_step", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for windsurf cascade")
	}
	if ev.Framework != "windsurf" {
		t.Errorf("framework=%s, want windsurf", ev.Framework)
	}
}

func TestDetectSpawn_AiderSpawn(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("shell", "aider_run", `{}`, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for aider")
	}
	if ev.Framework != "aider" {
		t.Errorf("framework=%s, want aider", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_AiderCliViaBash(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"command":"aider --model deepseek --yes src/main.py"}`
	ev := d.DetectSpawn("server", "Bash", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn for aider CLI via Bash")
	}
	if ev.Framework != "aider" {
		t.Errorf("framework=%s, want aider", ev.Framework)
	}
}

func TestDetectSpawn_ClineExecuteCommand(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"execute":"run tests","agent":"code-fixer"}`
	ev := d.DetectSpawn("vscode", "cline_run", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for cline")
	}
	if ev.Framework != "cline" {
		t.Errorf("framework=%s, want cline", ev.Framework)
	}
}

func TestDetectSpawn_RooCodeAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"architect","mode":"plan"}`
	ev := d.DetectSpawn("vscode", "roo_task", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for roo-code")
	}
	if ev.Framework != "roo-code" {
		t.Errorf("framework=%s, want roo-code", ev.Framework)
	}
}

func TestDetectSpawn_ContinueAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"helper","model":"claude"}`
	ev := d.DetectSpawn("vscode", "continue_agent", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for continue")
	}
	if ev.Framework != "continue" {
		t.Errorf("framework=%s, want continue", ev.Framework)
	}
}

// ---------------------------------------------------------------------------
// AI dev tools spawn detection
// ---------------------------------------------------------------------------

func TestDetectSpawn_DevinTask(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"task":"implement feature","agent":"devin-worker"}`
	ev := d.DetectSpawn("cognition", "devin_task", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for devin")
	}
	if ev.Framework != "devin" {
		t.Errorf("framework=%s, want devin", ev.Framework)
	}
}

func TestDetectSpawn_SWEAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("princeton", "swe_agent_run", `{}`, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for swe-agent")
	}
	if ev.Framework != "swe-agent" {
		t.Errorf("framework=%s, want swe-agent", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_SWEAgentViaBash(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"command":"python -m swe_agent run --issue 123"}`
	ev := d.DetectSpawn("server", "Bash", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn for swe-agent via Bash")
	}
}

func TestDetectSpawn_AmazonQAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"task":"transform code","agent":"q-worker"}`
	ev := d.DetectSpawn("aws", "amazon_q_dev", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for amazon-q")
	}
	if ev.Framework != "amazon-q" {
		t.Errorf("framework=%s, want amazon-q", ev.Framework)
	}
}

func TestDetectSpawn_JunieAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	ev := d.DetectSpawn("jetbrains", "junie_task", `{}`, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for junie")
	}
	if ev.Framework != "junie" {
		t.Errorf("framework=%s, want junie", ev.Framework)
	}
}

func TestDetectSpawn_JetBrainsAI(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"code-assist","task":"refactor"}`
	ev := d.DetectSpawn("ide", "jetbrains_ai_run", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for jetbrains")
	}
	if ev.Framework != "jetbrains" {
		t.Errorf("framework=%s, want jetbrains", ev.Framework)
	}
}

func TestDetectSpawn_TabnineAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"tabnine-assistant","task":"complete"}`
	ev := d.DetectSpawn("ide", "tabnine_agent", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for tabnine")
	}
	if ev.Framework != "tabnine" {
		t.Errorf("framework=%s, want tabnine", ev.Framework)
	}
}

func TestDetectSpawn_AugmentAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"augment-worker","task":"implement"}`
	ev := d.DetectSpawn("ide", "augment_code", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for augment")
	}
	if ev.Framework != "augment" {
		t.Errorf("framework=%s, want augment", ev.Framework)
	}
}

func TestDetectSpawn_CodyAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"cody-assistant","command":"explain"}`
	ev := d.DetectSpawn("sourcegraph", "cody_agent", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for cody")
	}
	if ev.Framework != "cody" {
		t.Errorf("framework=%s, want cody", ev.Framework)
	}
}

func TestDetectSpawn_BoltAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"bolt-builder","task":"scaffold"}`
	ev := d.DetectSpawn("web", "bolt_generate", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for bolt")
	}
	if ev.Framework != "bolt" {
		t.Errorf("framework=%s, want bolt", ev.Framework)
	}
}

func TestDetectSpawn_LovableAgent(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"agent":"lovable-builder","build":"app"}`
	ev := d.DetectSpawn("web", "lovable_build", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn event for lovable")
	}
	if ev.Framework != "lovable" {
		t.Errorf("framework=%s, want lovable", ev.Framework)
	}
}

// ---------------------------------------------------------------------------
// IDE subprocess detection via real-world Bash/shell
// ---------------------------------------------------------------------------

func TestDetectSpawn_RealWorld_CursorAgentViaBash(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"command":"cursor agent --task 'fix linting'"}`
	ev := d.DetectSpawn("server", "Bash", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn for cursor agent via Bash")
	}
	if ev.Framework != "cursor" {
		t.Errorf("framework=%s, want cursor", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_DevinViaBash(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"command":"devin run --issue 456"}`
	ev := d.DetectSpawn("server", "Bash", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn for devin via Bash")
	}
	if ev.Framework != "devin" {
		t.Errorf("framework=%s, want devin", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_WindsurfViaShell(t *testing.T) {
	d := NewSpawnDetector(nil)
	args := `{"command":"windsurf cascade --task refactor"}`
	ev := d.DetectSpawn("server", "shell", args, "parent")
	if ev == nil {
		t.Fatal("expected spawn for windsurf via shell")
	}
	if ev.Framework != "windsurf" {
		t.Errorf("framework=%s, want windsurf", ev.Framework)
	}
}

func TestDetectSpawn_RealWorld_DefaultPatterns_AllIDs(t *testing.T) {
	patterns := DefaultSpawnPatterns()
	idSet := make(map[string]bool)
	for _, p := range patterns {
		idSet[p.ID] = true
	}

	allExpectedIDs := []string{
		// Core AI providers
		"openai-handoff", "claude-agent-tool", "claude-subagent",
		"codex-spawn", "gemini-function-call", "vertex-agent-builder",
		// Agent frameworks
		"langchain-agent-executor", "langgraph-handoff",
		"crewai-delegate", "crewai-coworker",
		"autogen-initiate-chat", "autogen-groupchat",
		"semantic-kernel-invoke",
		"bedrock-invoke-agent", "bedrock-action-group",
		"copilot-agent",
		// Coding IDEs
		"cursor-agent", "cursor-terminal", "cursor-composer",
		"windsurf-cascade", "windsurf-command", "codeium-agent",
		"aider-spawn", "continue-agent",
		"cline-command", "roo-code-agent",
		// AI dev tools
		"devin-task", "swe-agent-spawn",
		"amazon-q-agent", "q-developer-cli",
		"junie-agent", "jetbrains-ai-agent",
		"bolt-agent", "lovable-agent",
		"tabnine-agent", "augment-agent", "cody-agent",
		// Generic + shell patterns
		"generic-create-agent", "delegation-flag",
		"bash-agent-spawn", "shell-tool-spawn", "shell-agent-spawn",
		"terminal-agent-spawn", "cmd-agent-spawn", "subprocess-agent",
		// CLI spawn patterns
		"claude-cli-spawn", "codex-cli-spawn", "gemini-cli-spawn",
		"aider-cli-spawn", "cursor-cli-spawn", "devin-cli-spawn",
		"swe-agent-cli-spawn", "amazon-q-cli-spawn",
		"interpreter-agent-spawn",
		// Other generic
		"subtask-spawn", "a2a-delegation", "run-agent", "invoke-assistant",
	}

	for _, id := range allExpectedIDs {
		if !idSet[id] {
			t.Errorf("missing pattern: %s", id)
		}
	}
}

func TestInferFramework_AllIDEPatterns(t *testing.T) {
	tests := []struct {
		patternID string
		want      string
	}{
		{"cursor-agent", "cursor"},
		{"cursor-terminal", "cursor"},
		{"cursor-composer", "cursor"},
		{"windsurf-cascade", "windsurf"},
		{"windsurf-command", "windsurf"},
		{"codeium-agent", "codeium"},
		{"aider-spawn", "aider"},
		{"continue-agent", "continue"},
		{"cline-command", "cline"},
		{"roo-code-agent", "roo-code"},
		{"devin-task", "devin"},
		{"swe-agent-spawn", "swe-agent"},
		{"amazon-q-agent", "amazon-q"},
		{"q-developer-cli", "amazon-q"},
		{"junie-agent", "junie"},
		{"jetbrains-ai-agent", "jetbrains"},
		{"bolt-agent", "bolt"},
		{"lovable-agent", "lovable"},
		{"tabnine-agent", "tabnine"},
		{"augment-agent", "augment"},
		{"cody-agent", "cody"},
	}
	for _, tt := range tests {
		got := inferFramework(tt.patternID, "", "")
		if got != tt.want {
			t.Errorf("inferFramework(%q) = %q, want %q", tt.patternID, got, tt.want)
		}
	}
}

func TestInferFramework_FallbackIDEKeywords(t *testing.T) {
	tests := []struct {
		tool string
		want string
	}{
		{"cursor_dispatch", "cursor"},
		{"windsurf_run", "windsurf"},
		{"aider_edit", "aider"},
		{"cline_execute", "cline"},
		{"devin_plan", "devin"},
		{"junie_task", "junie"},
		{"tabnine_complete", "tabnine"},
		{"augment_assist", "augment"},
		{"cody_explain", "cody"},
	}
	for _, tt := range tests {
		got := inferFramework("generic-create-agent", tt.tool, "")
		if got != tt.want {
			t.Errorf("inferFramework(generic, %q) = %q, want %q", tt.tool, got, tt.want)
		}
	}
}
