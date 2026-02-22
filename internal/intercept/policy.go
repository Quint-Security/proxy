package intercept

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// PolicyConfig is the top-level policy file structure.
type PolicyConfig struct {
	Version  int            `json:"version"`
	DataDir  string         `json:"data_dir"`
	LogLevel string         `json:"log_level"`
	Servers  []ServerPolicy `json:"servers"`
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
