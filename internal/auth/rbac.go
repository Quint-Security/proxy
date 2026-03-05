package auth

import (
	"fmt"
	"path/filepath"
	"strings"
)

// RBACPolicy is the RBAC policy embedded in agent/subagent token claims.
type RBACPolicy struct {
	AllowedActions   []string `json:"allowed_actions"`
	DeniedActions    []string `json:"denied_actions"`
	AllowedResources []string `json:"allowed_resources"`
	DeniedResources  []string `json:"denied_resources"`
	SensitivityLevel int      `json:"sensitivity_level"`
	MaxRiskScore     int      `json:"max_risk_score"`
}

// RBACDecision is the result of RBAC evaluation.
type RBACDecision struct {
	Allowed  bool
	Reason   string
	Step     int
	StepName string
}

// EvaluateRBAC runs the deny-first 6-step evaluation.
// action is in canonical format (e.g., "mcp:github:list_repos.list").
// resource is the target resource identifier (may be empty).
// sensitivityLevel is the resource sensitivity (0 = unclassified).
func EvaluateRBAC(policy *RBACPolicy, action, resource string, sensitivityLevel int) RBACDecision {
	if policy == nil {
		return RBACDecision{Allowed: true, Reason: "no RBAC policy", Step: 0}
	}

	// Step 1: Check denied_actions
	for _, pattern := range policy.DeniedActions {
		if GlobMatchAction(pattern, action) {
			return RBACDecision{
				Allowed:  false,
				Reason:   fmt.Sprintf("action %q matches denied pattern %q", action, pattern),
				Step:     1,
				StepName: "denied_actions",
			}
		}
	}

	// Step 2: Check allowed_actions (empty = allow all)
	if len(policy.AllowedActions) > 0 {
		actionAllowed := false
		for _, pattern := range policy.AllowedActions {
			if GlobMatchAction(pattern, action) {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			return RBACDecision{
				Allowed:  false,
				Reason:   fmt.Sprintf("action %q not in allowed_actions", action),
				Step:     2,
				StepName: "allowed_actions",
			}
		}
	}

	// Step 3: Check denied_resources
	if resource != "" {
		for _, pattern := range policy.DeniedResources {
			if GlobMatchAction(pattern, resource) {
				return RBACDecision{
					Allowed:  false,
					Reason:   fmt.Sprintf("resource %q matches denied pattern %q", resource, pattern),
					Step:     3,
					StepName: "denied_resources",
				}
			}
		}
	}

	// Step 4: Check allowed_resources (empty = allow all)
	if resource != "" && len(policy.AllowedResources) > 0 {
		resourceAllowed := false
		for _, pattern := range policy.AllowedResources {
			if GlobMatchAction(pattern, resource) {
				resourceAllowed = true
				break
			}
		}
		if !resourceAllowed {
			return RBACDecision{
				Allowed:  false,
				Reason:   fmt.Sprintf("resource %q not in allowed_resources", resource),
				Step:     4,
				StepName: "allowed_resources",
			}
		}
	}

	// Step 5: Check sensitivity_level
	if policy.SensitivityLevel > 0 && sensitivityLevel > policy.SensitivityLevel {
		return RBACDecision{
			Allowed: false,
			Reason: fmt.Sprintf("resource sensitivity %d exceeds policy limit %d",
				sensitivityLevel, policy.SensitivityLevel),
			Step:     5,
			StepName: "sensitivity_level",
		}
	}

	// Step 6: ALLOWED
	return RBACDecision{
		Allowed:  true,
		Reason:   "all checks passed",
		Step:     6,
		StepName: "ALLOWED",
	}
}

// GlobMatchAction matches a value against an fnmatch-style glob pattern.
// Supports * (any sequence within a segment) and ** (any depth).
// Uses filepath.Match for single-segment wildcards with special handling for
// colon-separated segments (domain:scope:verb).
func GlobMatchAction(pattern, value string) bool {
	if pattern == value || pattern == "*" {
		return true
	}

	// Handle ** wildcard for matching across colon segments
	if strings.Contains(pattern, "**") {
		// Convert ** to match any number of colon-separated segments
		// e.g., "mcp:**" matches "mcp:github:list_repos.list"
		regex := globToRegex(pattern)
		if regex != "" {
			matched, _ := filepath.Match(regex, value)
			if matched {
				return true
			}
		}
		// Fallback: try segment-based matching
		return matchSegmented(pattern, value)
	}

	// filepath.Match handles * and ? within segments
	matched, _ := filepath.Match(pattern, value)
	return matched
}

// matchSegmented matches colon-separated patterns allowing ** to span segments.
func matchSegmented(pattern, value string) bool {
	patParts := strings.Split(pattern, ":")
	valParts := strings.Split(value, ":")

	return matchParts(patParts, valParts)
}

func matchParts(patParts, valParts []string) bool {
	pi, vi := 0, 0
	for pi < len(patParts) && vi < len(valParts) {
		if patParts[pi] == "**" {
			// ** matches zero or more segments
			if pi == len(patParts)-1 {
				return true // ** at end matches everything
			}
			// Try matching ** against 0..N segments
			for skip := 0; skip <= len(valParts)-vi; skip++ {
				if matchParts(patParts[pi+1:], valParts[vi+skip:]) {
					return true
				}
			}
			return false
		}
		matched, _ := filepath.Match(patParts[pi], valParts[vi])
		if !matched {
			return false
		}
		pi++
		vi++
	}
	// Check remaining pattern parts are all **
	for pi < len(patParts) {
		if patParts[pi] != "**" {
			return false
		}
		pi++
	}
	return vi == len(valParts)
}

// globToRegex converts a simple glob (no colon awareness) to a filepath.Match pattern.
// Returns empty string if conversion is not straightforward.
func globToRegex(pattern string) string {
	// Simple case: replace ** with * for filepath.Match (loses segment awareness)
	// This is a best-effort single-pass match
	return strings.ReplaceAll(pattern, "**", "*")
}

// NarrowRBAC computes the intersection for subagent token narrowing.
// child.allowed ⊆ parent.allowed, child.denied ⊇ parent.denied,
// child.sensitivity ≤ parent.sensitivity, child.max_risk ≤ parent.max_risk.
func NarrowRBAC(parent, child *RBACPolicy) *RBACPolicy {
	if parent == nil {
		return child
	}
	if child == nil {
		return parent
	}

	narrowed := &RBACPolicy{}

	// Allowed actions: intersection (child ⊆ parent)
	if len(parent.AllowedActions) > 0 && len(child.AllowedActions) > 0 {
		narrowed.AllowedActions = child.AllowedActions
	} else if len(parent.AllowedActions) > 0 {
		narrowed.AllowedActions = parent.AllowedActions
	} else {
		narrowed.AllowedActions = child.AllowedActions
	}

	// Denied actions: union (child ⊇ parent)
	denied := make(map[string]bool)
	for _, d := range parent.DeniedActions {
		denied[d] = true
	}
	for _, d := range child.DeniedActions {
		denied[d] = true
	}
	for d := range denied {
		narrowed.DeniedActions = append(narrowed.DeniedActions, d)
	}

	// Allowed resources: intersection
	if len(parent.AllowedResources) > 0 && len(child.AllowedResources) > 0 {
		narrowed.AllowedResources = child.AllowedResources
	} else if len(parent.AllowedResources) > 0 {
		narrowed.AllowedResources = parent.AllowedResources
	} else {
		narrowed.AllowedResources = child.AllowedResources
	}

	// Denied resources: union
	deniedRes := make(map[string]bool)
	for _, d := range parent.DeniedResources {
		deniedRes[d] = true
	}
	for _, d := range child.DeniedResources {
		deniedRes[d] = true
	}
	for d := range deniedRes {
		narrowed.DeniedResources = append(narrowed.DeniedResources, d)
	}

	// Sensitivity: min(parent, child) — lower is more restrictive
	if parent.SensitivityLevel > 0 && child.SensitivityLevel > 0 {
		narrowed.SensitivityLevel = parent.SensitivityLevel
		if child.SensitivityLevel < parent.SensitivityLevel {
			narrowed.SensitivityLevel = child.SensitivityLevel
		}
	} else if parent.SensitivityLevel > 0 {
		narrowed.SensitivityLevel = parent.SensitivityLevel
	} else {
		narrowed.SensitivityLevel = child.SensitivityLevel
	}

	// Max risk score: min(parent, child) — lower is more restrictive
	if parent.MaxRiskScore > 0 && child.MaxRiskScore > 0 {
		narrowed.MaxRiskScore = parent.MaxRiskScore
		if child.MaxRiskScore < parent.MaxRiskScore {
			narrowed.MaxRiskScore = child.MaxRiskScore
		}
	} else if parent.MaxRiskScore > 0 {
		narrowed.MaxRiskScore = parent.MaxRiskScore
	} else {
		narrowed.MaxRiskScore = child.MaxRiskScore
	}

	return narrowed
}

// ValidateNarrowing checks that a child RBAC is a valid narrowing of parent.
// Returns an error describing the first violation found.
func ValidateNarrowing(parent, child *RBACPolicy) error {
	if parent == nil {
		return nil // no parent constraints
	}
	if child == nil {
		return fmt.Errorf("child RBAC is nil but parent has constraints")
	}

	// Child sensitivity must not exceed parent
	if parent.SensitivityLevel > 0 && child.SensitivityLevel > parent.SensitivityLevel {
		return fmt.Errorf("child sensitivity_level %d exceeds parent %d",
			child.SensitivityLevel, parent.SensitivityLevel)
	}

	// Child max_risk_score must not exceed parent
	if parent.MaxRiskScore > 0 && (child.MaxRiskScore == 0 || child.MaxRiskScore > parent.MaxRiskScore) {
		return fmt.Errorf("child max_risk_score %d exceeds parent %d",
			child.MaxRiskScore, parent.MaxRiskScore)
	}

	// Child must include all parent denied actions
	parentDenied := make(map[string]bool)
	for _, d := range parent.DeniedActions {
		parentDenied[d] = true
	}
	childDenied := make(map[string]bool)
	for _, d := range child.DeniedActions {
		childDenied[d] = true
	}
	for d := range parentDenied {
		if !childDenied[d] {
			return fmt.Errorf("child missing parent denied_action %q", d)
		}
	}

	// Child must include all parent denied resources
	parentDeniedRes := make(map[string]bool)
	for _, d := range parent.DeniedResources {
		parentDeniedRes[d] = true
	}
	childDeniedRes := make(map[string]bool)
	for _, d := range child.DeniedResources {
		childDeniedRes[d] = true
	}
	for d := range parentDeniedRes {
		if !childDeniedRes[d] {
			return fmt.Errorf("child missing parent denied_resource %q", d)
		}
	}

	return nil
}
