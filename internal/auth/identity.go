package auth

// Identity represents a resolved caller identity.
// For agents, IsAgent is true and AgentID/AgentName/Scopes are populated.
// For raw API keys, only SubjectID and KeyScopes are populated.
// For anonymous callers, SubjectID is "anonymous".
type Identity struct {
	SubjectID string
	AgentID   string
	AgentName string
	Scopes    []string
	IsAgent   bool
}
