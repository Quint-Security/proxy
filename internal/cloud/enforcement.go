package cloud

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// EnforcementResult is the output of policy evaluation.
type EnforcementResult struct {
	Action     string // "allow", "block", "flag", "require_approval"
	PolicyID   string // ID of the matching policy (empty if no match)
	PolicyName string // Name of the matching policy
	RuleIndex  int    // Index of the matching rule within the policy (-1 if no match)
}

// Enforcer evaluates cloud enforcement policies against tool calls.
type Enforcer struct {
	mu         sync.RWMutex
	policies   []CloudPolicy
	policyHash string
	cacheDir   string
}

// policyCache is the on-disk format for cached policies.
type policyCache struct {
	Policies []CloudPolicy `json:"policies"`
	Hash     string        `json:"hash"`
}

// NewEnforcer creates a new policy enforcer. Loads cached policies from disk on startup.
func NewEnforcer(cacheDir string) *Enforcer {
	e := &Enforcer{cacheDir: cacheDir}
	e.loadFromDisk()
	return e
}

// Update replaces the current policies and persists to disk.
func (e *Enforcer) Update(policies []CloudPolicy, hash string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Sort by priority descending (highest priority first)
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Priority > policies[j].Priority
	})
	e.policies = policies
	e.policyHash = hash
	e.saveToDisk()
}

// Hash returns the current policy version hash.
func (e *Enforcer) Hash() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policyHash
}

// PolicyCount returns the number of loaded policies.
func (e *Enforcer) PolicyCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.policies)
}

// Evaluate checks a tool call against all policies.
// Input: toolName (e.g. "Bash" or "api.github.com:POST./repos"),
// agentName (e.g. "anthropic:swift-blue-falcon"), argsJSON (tool arguments as string).
// Policies are checked in priority order (highest first). First matching rule wins.
// Returns "allow" if no rule matches.
func (e *Enforcer) Evaluate(toolName, agentName, argsJSON string) EnforcementResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}
		for i, rule := range policy.Rules {
			if !globMatch(rule.Tool, toolName) {
				continue
			}
			if !globMatch(rule.Agent, agentName) {
				continue
			}
			// Check conditions (if any) against arguments
			if len(rule.Conditions) > 0 {
				if !matchesAnyCondition(rule.Conditions, argsJSON) {
					continue
				}
			}
			return EnforcementResult{
				Action:     rule.Action,
				PolicyID:   policy.ID,
				PolicyName: policy.Name,
				RuleIndex:  i,
			}
		}
	}
	return EnforcementResult{Action: "allow", RuleIndex: -1}
}

// globMatch performs simple glob matching: "*" matches everything,
// "Foo*" matches prefix, "*Bar" matches suffix, "*mid*" matches contains,
// exact match otherwise. Case-insensitive. Empty pattern matches everything.
func globMatch(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	pLower := strings.ToLower(pattern)
	vLower := strings.ToLower(value)

	// Check for contains pattern: *something*
	if strings.HasPrefix(pLower, "*") && strings.HasSuffix(pLower, "*") && len(pLower) > 2 {
		middle := pLower[1 : len(pLower)-1]
		return strings.Contains(vLower, middle)
	}
	// Prefix match: Foo*
	if strings.HasSuffix(pLower, "*") {
		prefix := pLower[:len(pLower)-1]
		return strings.HasPrefix(vLower, prefix)
	}
	// Suffix match: *Bar
	if strings.HasPrefix(pLower, "*") {
		suffix := pLower[1:]
		return strings.HasSuffix(vLower, suffix)
	}
	// Exact match (case-insensitive)
	return pLower == vLower
}

// matchesAnyCondition checks if any condition pattern appears in the args.
// Conditions are treated as case-insensitive substring matches with glob support
// for patterns like "/etc/*".
func matchesAnyCondition(conditions []string, argsJSON string) bool {
	if argsJSON == "" {
		return false
	}
	argsLower := strings.ToLower(argsJSON)
	for _, cond := range conditions {
		condLower := strings.ToLower(cond)
		// If condition contains a glob wildcard, use glob matching on the args
		if strings.Contains(condLower, "*") {
			// For conditions like "/etc/*", check if any part of args matches
			// Strip leading/trailing * for a contains-style match on the fixed part
			fixed := strings.ReplaceAll(condLower, "*", "")
			if fixed != "" && strings.Contains(argsLower, fixed) {
				return true
			}
		} else {
			// Simple substring match
			if strings.Contains(argsLower, condLower) {
				return true
			}
		}
	}
	return false
}

// saveToDisk writes policies + hash to {cacheDir}/cloud_policies.json.
func (e *Enforcer) saveToDisk() {
	if e.cacheDir == "" {
		return
	}
	cache := policyCache{
		Policies: e.policies,
		Hash:     e.policyHash,
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		qlog.Warn("failed to marshal cloud policies for caching: %v", err)
		return
	}
	path := filepath.Join(e.cacheDir, "cloud_policies.json")
	if err := os.MkdirAll(e.cacheDir, 0755); err != nil {
		qlog.Warn("failed to create cache dir %s: %v", e.cacheDir, err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		qlog.Warn("failed to write cloud policies cache: %v", err)
		return
	}
	qlog.Debug("cached %d cloud policies to %s", len(e.policies), path)
}

// loadFromDisk reads cached policies from {cacheDir}/cloud_policies.json.
func (e *Enforcer) loadFromDisk() {
	if e.cacheDir == "" {
		return
	}
	path := filepath.Join(e.cacheDir, "cloud_policies.json")
	data, err := os.ReadFile(path)
	if err != nil {
		// File doesn't exist yet — not an error on first run
		return
	}
	var cache policyCache
	if err := json.Unmarshal(data, &cache); err != nil {
		qlog.Warn("failed to parse cached cloud policies: %v", err)
		return
	}
	// Sort by priority descending
	sort.Slice(cache.Policies, func(i, j int) bool {
		return cache.Policies[i].Priority > cache.Policies[j].Priority
	})
	e.policies = cache.Policies
	e.policyHash = cache.Hash
	qlog.Info("loaded %d cached cloud policies (hash=%s)", len(e.policies), e.policyHash)
}
