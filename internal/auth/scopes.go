package auth

import "strings"

// Scope constants.
const (
	ScopeToolsAdmin   = "tools:admin"
	ScopeToolsExecute = "tools:execute"
	ScopeToolsWrite   = "tools:write"
	ScopeToolsRead    = "tools:read"
)

// scopeHierarchy maps each scope to the set of scopes it implicitly grants.
var scopeHierarchy = map[string][]string{
	ScopeToolsAdmin:   {ScopeToolsWrite, ScopeToolsRead},
	ScopeToolsExecute: {ScopeToolsRead},
	ScopeToolsWrite:   {ScopeToolsRead},
	ScopeToolsRead:    {},
}

// ExpandScopes returns all effective scopes given a list of granted scopes.
func ExpandScopes(scopes []string) map[string]bool {
	expanded := make(map[string]bool)
	for _, s := range scopes {
		expanded[s] = true
		if children, ok := scopeHierarchy[s]; ok {
			for _, c := range children {
				expanded[c] = true
			}
		}
	}
	return expanded
}

// HasScope returns true if the effective scope set includes the required scope.
func HasScope(granted []string, required string) bool {
	return ExpandScopes(granted)[required]
}

// RequiredScopeForTool returns the scope required to call the given tool.
// Uses glob-style prefix matching on the tool name.
func RequiredScopeForTool(toolName string) string {
	upper := strings.ToUpper(toolName)

	// Admin: destructive operations
	for _, prefix := range []string{"DELETE", "REMOVE", "DROP"} {
		if strings.HasPrefix(upper, prefix) {
			return ScopeToolsAdmin
		}
	}

	// Execute: shell/code execution
	for _, keyword := range []string{"EXECUTE", "SHELL", "BASH", "RUN"} {
		if strings.Contains(upper, keyword) {
			return ScopeToolsExecute
		}
	}

	// Write: creation/modification
	for _, prefix := range []string{"WRITE", "CREATE", "UPDATE", "EDIT"} {
		if strings.HasPrefix(upper, prefix) {
			return ScopeToolsWrite
		}
	}

	// Read: read-only operations
	for _, prefix := range []string{"READ", "GET", "LIST", "SEARCH"} {
		if strings.HasPrefix(upper, prefix) {
			return ScopeToolsRead
		}
	}

	// Unknown tool — fail closed
	return ScopeToolsWrite
}

// EnforceScope checks whether the identity has the required scope for the tool.
// Returns ("", true) if allowed, or (required_scope, false) if denied.
// Non-agent identities always pass (backwards compatible).
func EnforceScope(identity *Identity, toolName string) (string, bool) {
	if identity == nil || !identity.IsAgent {
		return "", true
	}
	required := RequiredScopeForTool(toolName)
	if HasScope(identity.Scopes, required) {
		return "", true
	}
	return required, false
}

// NormalizeScopes ensures scope strings use the "tools:" prefix format.
// Bare scopes like "read" are mapped to "tools:read", etc.
// Already-prefixed scopes are left unchanged.
func NormalizeScopes(scopes []string) []string {
	bareToFull := map[string]string{
		"read":    ScopeToolsRead,
		"write":   ScopeToolsWrite,
		"admin":   ScopeToolsAdmin,
		"execute": ScopeToolsExecute,
	}
	out := make([]string, len(scopes))
	for i, s := range scopes {
		if full, ok := bareToFull[s]; ok {
			out[i] = full
		} else {
			out[i] = s
		}
	}
	return out
}

// NormalizeScopeString normalizes a comma-separated scope string.
func NormalizeScopeString(s string) string {
	parsed := ParseScopes(s)
	normalized := NormalizeScopes(parsed)
	return strings.Join(normalized, ",")
}

// ParseScopes splits a comma-separated scope string into a slice.
func ParseScopes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
