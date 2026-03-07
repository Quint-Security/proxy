package auth

// Identity represents a resolved caller identity.
// For agents, IsAgent is true and AgentID/AgentName/Scopes are populated.
// For raw API keys, only SubjectID and KeyScopes are populated.
// For anonymous callers, SubjectID is "anonymous".
// For cloud JWT tokens, IsCloudToken is true and RBAC/TokenType/etc are populated.
type Identity struct {
	SubjectID string
	AgentID   string
	AgentName string
	AgentType string // "chatgpt", "claude", "generic", etc.
	Scopes    []string
	IsAgent   bool

	// Cloud auth fields (zero-value defaults preserve backward compatibility)
	TokenType    string      // "app", "bearer", "agent", "subagent", "session", "override"
	CustomerID   string      // JWT sub claim
	RBAC         *RBACPolicy // from JWT claims (nil for local tokens)
	Depth        int         // subagent depth from JWT
	ParentJTI    string      // parent token JTI for chain validation
	JTI          string      // this token's JTI
	IsCloudToken bool        // true if resolved via cloud JWT
	MaxRiskScore int         // from RBAC policy, 0 = no limit

	// Source tracks how the identity was resolved.
	// Values: "cli_flag", "env_var", "cloud_token", "quint_auth", "client_info", "auto_register"
	Source string

	// Provider detection (forward proxy mode)
	Provider string // "anthropic", "openai", "google", etc.
	Model    string // Last observed model: "claude-sonnet-4-20250514", "gpt-4o", etc.
	Tool     string // Client tool: "claude-code", "cursor", "aider", etc.
}
