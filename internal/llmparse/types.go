package llmparse

import "time"

// AgentEvent represents a single parsed tool call or message from an LLM conversation.
type AgentEvent struct {
	EventID       string
	Timestamp     time.Time
	Provider      string // "anthropic", "openai", "google"
	Model         string
	AgentIdentity string // from User-Agent header
	EventType     string // "tool_use", "tool_result", "message"
	ToolName      string // "Bash", "Read", "Write", "Edit", etc.
	ToolArgs      string // JSON string of tool arguments
	ToolResult    string // tool result content (truncated)
	RiskScore     int
}

// ParseResult contains all events extracted from a single API request/response pair.
type ParseResult struct {
	Events []AgentEvent
	Model  string
	Agent  string // best-guess agent identity from User-Agent
}
