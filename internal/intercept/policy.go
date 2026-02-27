package intercept

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Quint-Security/quint-proxy/internal/crypto"
)

// Action is "allow" or "deny".
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Verdict is the result of policy evaluation.
type Verdict string

const (
	VerdictAllow       Verdict = "allow"
	VerdictDeny        Verdict = "deny"
	VerdictPassthrough Verdict = "passthrough"
)

// ToolRule is a per-tool policy override.
type ToolRule struct {
	Tool   string `json:"tool"`
	Action Action `json:"action"`
}

// ServerPolicy defines policy for a named server.
type ServerPolicy struct {
	Server        string     `json:"server"`
	DefaultAction Action     `json:"default_action"`
	Tools         []ToolRule `json:"tools"`
}

// RiskPatternConfig is a user-configurable risk pattern.
type RiskPatternConfig struct {
	Tool      string `json:"tool"`
	BaseScore int    `json:"base_score"`
}

// RiskKeywordConfig is a user-configurable dangerous argument keyword.
type RiskKeywordConfig struct {
	Pattern string `json:"pattern"`
	Boost   int    `json:"boost"`
}

// RiskConfig holds user-configurable risk scoring settings.
type RiskConfig struct {
	// Flag is the score at which actions are flagged for review (default 60).
	Flag *int `json:"flag,omitempty"`
	// Deny is the score at which actions are auto-denied (default 85).
	Deny *int `json:"deny,omitempty"`
	// RevokeAfter is the number of high-risk actions in window before revocation (default 5).
	RevokeAfter *int `json:"revoke_after,omitempty"`
	// WindowSeconds is the behavior tracking window in seconds (default 300).
	WindowSeconds *int `json:"window_seconds,omitempty"`
	// Patterns are custom tool risk patterns (checked before built-in defaults).
	Patterns []RiskPatternConfig `json:"patterns,omitempty"`
	// Keywords are custom dangerous argument keywords (added to built-in defaults).
	Keywords []RiskKeywordConfig `json:"keywords,omitempty"`
	// DisableBuiltins disables the built-in risk patterns and keywords when true.
	DisableBuiltins bool `json:"disable_builtins,omitempty"`
	// RemoteAPI configures an optional remote risk scoring API (paid tier).
	RemoteAPI *RemoteAPIConfig `json:"risk_api,omitempty"`
}

// RemoteAPIConfig configures the remote risk scoring API.
type RemoteAPIConfig struct {
	URL        string `json:"url"`
	APIKey     string `json:"api_key"`
	CustomerID string `json:"customer_id"`
	Enabled    bool   `json:"enabled"`
	TimeoutMs  int    `json:"timeout_ms,omitempty"`
}

// PolicyConfig is the top-level policy file structure.
type PolicyConfig struct {
	Version                int            `json:"version"`
	DataDir                string         `json:"data_dir"`
	LogLevel               string         `json:"log_level"`
	FailMode               string         `json:"fail_mode,omitempty"`  // "open" or "closed" (default "closed")
	Servers                []ServerPolicy `json:"servers"`
	Risk                   *RiskConfig    `json:"risk,omitempty"`
	ApprovalRequired       bool           `json:"approval_required,omitempty"`
	ApprovalTimeoutSeconds int            `json:"approval_timeout_seconds,omitempty"`
	RateLimitRpm           int            `json:"rate_limit_rpm,omitempty"`
	RateLimitBurst         int            `json:"rate_limit_burst,omitempty"`
	Signature              string         `json:"_signature,omitempty"` // Ed25519 signature of the canonical policy JSON
}

// GetApprovalTimeout returns the effective approval timeout in seconds, defaulting to 300.
func (p PolicyConfig) GetApprovalTimeout() int {
	if p.ApprovalTimeoutSeconds > 0 {
		return p.ApprovalTimeoutSeconds
	}
	return 300
}

// GetRateLimitRpm returns the effective rate limit in requests per minute, defaulting to 60.
func (p PolicyConfig) GetRateLimitRpm() int {
	if p.RateLimitRpm > 0 {
		return p.RateLimitRpm
	}
	return 60
}

// GetRateLimitBurst returns the effective rate limit burst, defaulting to 10.
func (p PolicyConfig) GetRateLimitBurst() int {
	if p.RateLimitBurst > 0 {
		return p.RateLimitBurst
	}
	return 10
}

// GetFailMode returns the effective fail mode, defaulting to "closed".
func (p PolicyConfig) GetFailMode() string {
	if p.FailMode == "open" {
		return "open"
	}
	return "closed"
}

// DefaultPolicy returns a sensible default when no policy file exists.
func DefaultPolicy() PolicyConfig {
	return PolicyConfig{
		Version:  1,
		DataDir:  "~/.quint",
		LogLevel: "info",
		Servers: []ServerPolicy{
			{Server: "*", DefaultAction: ActionAllow, Tools: []ToolRule{}},
		},
	}
}

// LoadPolicy loads policy from a file path or directory.
// If pathOrDir ends in .json, it's treated as a direct file path.
// Otherwise, it looks for policy.json inside that directory.
// Falls back to QUINT_DATA_DIR env var, then ~/.quint.
func LoadPolicy(pathOrDir string) (PolicyConfig, error) {
	envDir := os.Getenv("QUINT_DATA_DIR")

	var policyPath string
	if pathOrDir != "" && strings.HasSuffix(pathOrDir, ".json") {
		policyPath = pathOrDir
	} else {
		dir := pathOrDir
		if dir == "" {
			dir = envDir
		}
		if dir == "" {
			home, _ := os.UserHomeDir()
			dir = filepath.Join(home, ".quint")
		}
		policyPath = filepath.Join(dir, "policy.json")
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			p := DefaultPolicy()
			if pathOrDir != "" {
				p.DataDir = pathOrDir
			}
			return p, nil
		}
		return PolicyConfig{}, err
	}

	var cfg PolicyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return PolicyConfig{}, err
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Dir(policyPath)
	}
	cfg.DataDir = ResolveDataDir(cfg.DataDir)
	return cfg, nil
}

// ResolveDataDir expands ~ to the user's home directory.
func ResolveDataDir(raw string) string {
	if strings.HasPrefix(raw, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, raw[2:])
	}
	return raw
}

// GlobMatch matches a string against a pattern with * (any chars) and ? (single char).
// This matches the TypeScript implementation exactly.
func GlobMatch(pattern, value string) bool {
	if pattern == value || pattern == "*" {
		return true
	}

	// Escape regex special chars, then convert glob wildcards
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(escaped, `\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\?`, ".")

	re, err := regexp.Compile("^" + escaped + "$")
	if err != nil {
		return pattern == value
	}
	return re.MatchString(value)
}

// EvaluatePolicy determines the verdict for a tool call on a server.
// Matches the TypeScript evaluatePolicy logic: first-match-wins for servers and tools.
func EvaluatePolicy(cfg PolicyConfig, serverName string, toolName string) Verdict {
	// Find matching server (first match wins)
	var sp *ServerPolicy
	for i := range cfg.Servers {
		if GlobMatch(cfg.Servers[i].Server, serverName) {
			sp = &cfg.Servers[i]
			break
		}
	}

	// No server match = fail closed
	if sp == nil {
		return VerdictDeny
	}

	// If no tool name (not a tools/call), passthrough
	if toolName == "" {
		return VerdictPassthrough
	}

	// Check tool-specific rules (first match wins)
	for _, rule := range sp.Tools {
		if GlobMatch(rule.Tool, toolName) {
			return Verdict(rule.Action)
		}
	}

	// Fall back to server default
	return Verdict(sp.DefaultAction)
}

// SignPolicy signs a policy config and returns the signed JSON bytes.
// The signature is computed over the canonical JSON representation (without the _signature field).
func SignPolicy(policy PolicyConfig, privateKey string) ([]byte, error) {
	// Remove signature field before signing
	policy.Signature = ""

	// Marshal to JSON
	policyJSON, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}

	// Sign the canonical JSON
	signature, err := crypto.SignData(string(policyJSON), privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign policy: %w", err)
	}

	// Add signature back to policy
	policy.Signature = signature

	// Marshal again with signature
	signedJSON, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal signed policy: %w", err)
	}

	return signedJSON, nil
}

// VerifyPolicy checks if a policy file has a valid signature.
// Returns the policy if valid, or a lockdown policy if tampered.
// The second return value indicates whether the signature was valid.
func VerifyPolicy(data []byte, publicKey string) (PolicyConfig, bool, error) {
	var policy PolicyConfig
	if err := json.Unmarshal(data, &policy); err != nil {
		return LockdownPolicy(), false, fmt.Errorf("unmarshal policy: %w", err)
	}

	// If there's no signature, return lockdown policy (fail-closed)
	if policy.Signature == "" {
		return LockdownPolicy(), false, fmt.Errorf("policy has no signature")
	}

	// Store signature and remove it from policy for verification
	signature := policy.Signature
	policy.Signature = ""

	// Marshal to JSON (without signature)
	policyJSON, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return LockdownPolicy(), false, fmt.Errorf("marshal policy for verification: %w", err)
	}

	// Verify signature
	valid, err := crypto.VerifySignature(string(policyJSON), signature, publicKey)
	if err != nil {
		return LockdownPolicy(), false, fmt.Errorf("verify signature: %w", err)
	}

	if !valid {
		return LockdownPolicy(), false, fmt.Errorf("invalid signature")
	}

	// Restore signature
	policy.Signature = signature
	return policy, true, nil
}

// LockdownPolicy returns an ultra-restrictive policy used when tamper detection fails.
// Denies all access to all servers.
func LockdownPolicy() PolicyConfig {
	return PolicyConfig{
		Version:  1,
		DataDir:  "~/.quint",
		LogLevel: "info",
		FailMode: "closed",
		Servers: []ServerPolicy{
			{Server: "*", DefaultAction: ActionDeny, Tools: []ToolRule{}},
		},
	}
}
