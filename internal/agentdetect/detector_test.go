package agentdetect

import (
	"net/http"
	"testing"
)

func TestExtractSystemPrompt_Anthropic(t *testing.T) {
	// Anthropic format: top-level "system" string
	body := `{"model":"claude-sonnet-4-20250514","system":"You are Claude Code, Anthropic's official CLI for Claude.","messages":[{"role":"user","content":"hello"}]}`
	got := ExtractSystemPrompt(body)
	if got != "You are Claude Code, Anthropic's official CLI for Claude." {
		t.Errorf("Anthropic string format: got %q", got)
	}
}

func TestExtractSystemPrompt_AnthropicBlocks(t *testing.T) {
	// Anthropic format: system as array of content blocks
	body := `{"model":"claude-sonnet-4-20250514","system":[{"type":"text","text":"You are Claude Code."},{"type":"text","text":"Follow instructions."}],"messages":[]}`
	got := ExtractSystemPrompt(body)
	if got != "You are Claude Code.\nFollow instructions." {
		t.Errorf("Anthropic blocks format: got %q", got)
	}
}

func TestExtractSystemPrompt_OpenAI(t *testing.T) {
	// OpenAI format: messages array with role "system"
	body := `{"model":"gpt-4o","messages":[{"role":"system","content":"You are a powerful agentic AI coding assistant, designed by Cursor."},{"role":"user","content":"hi"}]}`
	got := ExtractSystemPrompt(body)
	if got != "You are a powerful agentic AI coding assistant, designed by Cursor." {
		t.Errorf("OpenAI system format: got %q", got)
	}
}

func TestExtractSystemPrompt_OpenAIDeveloper(t *testing.T) {
	// OpenAI format: "developer" role instead of "system"
	body := `{"model":"gpt-4o","messages":[{"role":"developer","content":"GitHub Copilot instructions."},{"role":"user","content":"hi"}]}`
	got := ExtractSystemPrompt(body)
	if got != "GitHub Copilot instructions." {
		t.Errorf("OpenAI developer format: got %q", got)
	}
}

func TestExtractSystemPrompt_Google(t *testing.T) {
	body := `{"system_instruction":{"parts":[{"text":"Gemini CLI system prompt"}]},"contents":[]}`
	got := ExtractSystemPrompt(body)
	if got != "Gemini CLI system prompt" {
		t.Errorf("Google format: got %q", got)
	}
}

func TestExtractSystemPrompt_Empty(t *testing.T) {
	if got := ExtractSystemPrompt(""); got != "" {
		t.Errorf("empty body: got %q", got)
	}
	if got := ExtractSystemPrompt(`{"messages":[]}`); got != "" {
		t.Errorf("no system message: got %q", got)
	}
}

func TestIdentifyFromSystemPrompt_ClaudeCode(t *testing.T) {
	tests := []struct {
		name   string
		prompt string
	}{
		{"direct mention", "You are Claude Code, Anthropic's official CLI for Claude."},
		{"hyphenated", "This is claude-code running in your terminal."},
		{"engineering tasks", "The user will primarily request you to perform software engineering tasks. These may include solving bugs. You have a working directory at /home/user."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform, conf := identifyFromSystemPrompt(tt.prompt)
			if platform != "claude-code" {
				t.Errorf("got platform=%q, want claude-code", platform)
			}
			if conf < 0.9 {
				t.Errorf("got confidence=%.2f, want >= 0.9", conf)
			}
		})
	}
}

func TestIdentifyFromSystemPrompt_Cursor(t *testing.T) {
	prompt := "You are a powerful agentic AI coding assistant, designed by Cursor - an AI company based in San Francisco, California. You operate exclusively in Cursor, the world's best IDE."
	platform, conf := identifyFromSystemPrompt(prompt)
	if platform != "cursor" {
		t.Errorf("got platform=%q, want cursor", platform)
	}
	if conf < 0.9 {
		t.Errorf("got confidence=%.2f, want >= 0.9", conf)
	}
}

func TestIdentifyFromSystemPrompt_Copilot(t *testing.T) {
	prompt := "You are GitHub Copilot, an AI coding assistant."
	platform, conf := identifyFromSystemPrompt(prompt)
	if platform != "copilot" {
		t.Errorf("got platform=%q, want copilot", platform)
	}
	if conf < 0.9 {
		t.Errorf("got confidence=%.2f, want >= 0.9", conf)
	}
}

func TestIdentifyFromSystemPrompt_Generic(t *testing.T) {
	// Generic prompts should NOT match any platform
	prompts := []string{
		"You are a helpful AI assistant.",
		"Answer the user's question concisely.",
		"",
	}
	for _, prompt := range prompts {
		platform, _ := identifyFromSystemPrompt(prompt)
		if platform != "" {
			t.Errorf("generic prompt %q matched platform %q", prompt, platform)
		}
	}
}

func TestIdentifyFromHeaders_Cursor(t *testing.T) {
	h := http.Header{}
	h.Set("x-cursor-checksum", "abc123")
	platform, conf := identifyFromHeaders(h)
	if platform != "cursor" {
		t.Errorf("got platform=%q, want cursor", platform)
	}
	if conf < 0.85 {
		t.Errorf("got confidence=%.2f, want >= 0.85", conf)
	}
}

func TestIdentifyFromHeaders_Copilot(t *testing.T) {
	h := http.Header{}
	h.Set("copilot-integration-id", "vscode")
	platform, conf := identifyFromHeaders(h)
	if platform != "copilot" {
		t.Errorf("got platform=%q, want copilot", platform)
	}
	if conf < 0.85 {
		t.Errorf("got confidence=%.2f, want >= 0.85", conf)
	}
}

func TestIdentifyFromHeaders_Windsurf(t *testing.T) {
	h := http.Header{}
	h.Set("x-codeium-session-id", "sess-123")
	platform, conf := identifyFromHeaders(h)
	if platform != "windsurf" {
		t.Errorf("got platform=%q, want windsurf", platform)
	}
	if conf < 0.85 {
		t.Errorf("got confidence=%.2f, want >= 0.85", conf)
	}
}

func TestIdentifyFromHeaders_NoMatch(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	platform, _ := identifyFromHeaders(h)
	if platform != "" {
		t.Errorf("got platform=%q, want empty", platform)
	}
}

func TestIdentifyFromUA(t *testing.T) {
	tests := []struct {
		ua       string
		platform string
	}{
		{"claude-code/1.2.3", "claude-code"},
		{"claude-ai/2024.1", "claude-code"},
		{"Cursor/0.45.1", "cursor"},
		{"aider/v0.72", "aider"},
		{"codex-cli/1.0", "codex"},
		{"gose/0.1.0", "goose"},
	}
	for _, tt := range tests {
		t.Run(tt.ua, func(t *testing.T) {
			platform, conf := identifyFromUA(tt.ua)
			if platform != tt.platform {
				t.Errorf("UA %q: got platform=%q, want %q", tt.ua, platform, tt.platform)
			}
			if conf < 0.5 {
				t.Errorf("UA %q: got confidence=%.2f, want > 0.5", tt.ua, conf)
			}
		})
	}
}

func TestIdentifyFromProcess(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		platform string
	}{
		{"claude-code", "", "claude-code"},
		{"cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor", "cursor"},
		{"node", "/Applications/Cursor.app/Contents/MacOS/node", "cursor"},
		{"unknown", "/usr/bin/python3", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform := identifyFromProcess(tt.name, tt.path)
			if platform != tt.platform {
				t.Errorf("process %q (path=%q): got %q, want %q", tt.name, tt.path, platform, tt.platform)
			}
		})
	}
}

func TestDetect_SystemPromptOverridesGenericUA(t *testing.T) {
	// When UA is generic but system prompt identifies the platform,
	// the system prompt should win.
	d := NewDetector()
	result := d.Detect(DetectParams{
		UserAgent: "python-httpx/0.27.0",
		BodyPreview: `{
			"model": "claude-sonnet-4-20250514",
			"system": "You are Claude Code, Anthropic's official CLI.",
			"messages": [{"role": "user", "content": "hi"}]
		}`,
	})
	if result.Platform != "claude-code" {
		t.Errorf("got platform=%q, want claude-code", result.Platform)
	}
	if result.Confidence < 0.9 {
		t.Errorf("got confidence=%.2f, want >= 0.9", result.Confidence)
	}
}

func TestDetect_HeadersWin(t *testing.T) {
	d := NewDetector()
	h := http.Header{}
	h.Set("x-cursor-checksum", "abc")
	result := d.Detect(DetectParams{
		UserAgent: "node-fetch/3.0",
		Headers:   h,
	})
	if result.Platform != "cursor" {
		t.Errorf("got platform=%q, want cursor", result.Platform)
	}
}

func TestDetect_MultiLayerBoost(t *testing.T) {
	// Both UA and system prompt agree → confidence should be boosted
	d := NewDetector()
	result := d.Detect(DetectParams{
		UserAgent: "cursor/0.45.1",
		BodyPreview: `{
			"model": "gpt-4o",
			"messages": [{"role": "system", "content": "You are designed by Cursor."}]
		}`,
	})
	if result.Platform != "cursor" {
		t.Errorf("got platform=%q, want cursor", result.Platform)
	}
	if len(result.Sources) < 2 {
		t.Errorf("expected multiple sources, got %v", result.Sources)
	}
}

func TestDetect_ProcessTreeIsHardStop(t *testing.T) {
	// Process tree match should return immediately with confidence 1.0
	d := NewDetector()
	result := d.Detect(DetectParams{
		ProcessName: "cursor",
		ProcessPath: "/Applications/Cursor.app/Contents/MacOS/Cursor",
		PID:         12345,
	})
	if result.Platform != "cursor" {
		t.Errorf("got platform=%q, want cursor", result.Platform)
	}
	if result.Confidence != 1.0 {
		t.Errorf("got confidence=%.2f, want 1.0", result.Confidence)
	}
	if result.PID != 12345 {
		t.Errorf("got PID=%d, want 12345", result.PID)
	}
}

func TestDetect_Unknown(t *testing.T) {
	d := NewDetector()
	result := d.Detect(DetectParams{
		UserAgent: "Mozilla/5.0",
	})
	if result.Platform != "unknown" {
		t.Errorf("got platform=%q, want unknown", result.Platform)
	}
}

func TestDetectCached(t *testing.T) {
	d := NewDetector()
	params := DetectParams{
		ProcessName: "claude-code",
		ProcessPath: "/usr/local/bin/claude",
		PID:         999,
	}

	// First call — runs detection
	r1 := d.DetectCached("agent-123", params)
	if r1.Platform != "claude-code" {
		t.Fatalf("first call: got %q", r1.Platform)
	}

	// Second call with empty params — should return cached result
	r2 := d.DetectCached("agent-123", DetectParams{})
	if r2.Platform != "claude-code" {
		t.Errorf("cached call: got %q, want claude-code", r2.Platform)
	}
}

func TestIsSpecificPlatform(t *testing.T) {
	if !IsSpecificPlatform("claude-code") {
		t.Error("claude-code should be specific")
	}
	if !IsSpecificPlatform("cursor") {
		t.Error("cursor should be specific")
	}
	if IsSpecificPlatform("python-httpx") {
		t.Error("python-httpx should not be specific")
	}
	if IsSpecificPlatform("") {
		t.Error("empty should not be specific")
	}
}
