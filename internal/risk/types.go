package risk

// EventContext carries enriched context from the proxy to the remote scorer.
type EventContext struct {
	AgentID          string
	AgentName        string
	AgentType        string // "claude", "chatgpt", "cursor", "generic", etc.
	ServerName       string
	Transport        string // "stdio" or "http"
	IsVerified       bool
	ToolName         string
	PrecedingActions []string
	SessionID        string
	CanonicalAction  string // e.g. "mcp:github:list_repos.list" — set by ClassifyAction
	TraceID          string // X-Quint-Trace: {trace_id}.{depth}
	Depth            int    // agent tree depth (0 = root)
	ParentAgentID    string // parent agent identifier if known
	SpawnDetected    bool   // true if this call was detected as spawning a child

	// Cloud auth enrichment
	TokenType    string // "agent", "subagent", "session", etc.
	MaxRiskScore int    // from RBAC policy; 0 = no limit
	CustomerID   string // from JWT sub claim
}
