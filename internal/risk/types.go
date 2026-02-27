package risk

// EventContext carries enriched context from the proxy to the remote scorer.
type EventContext struct {
	AgentID          string
	AgentName        string
	ServerName       string
	Transport        string // "stdio" or "http"
	IsVerified       bool
	ToolName         string
	PrecedingActions []string
	SessionID        string
	CanonicalAction  string // e.g. "mcp:github:list_repos.list" — set by ClassifyAction
}
