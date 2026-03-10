package main

import (
	"github.com/Quint-Security/quint-proxy/internal/cloud"
	"github.com/Quint-Security/quint-proxy/internal/forwardproxy"
)

// enforcerAdapter wraps cloud.Enforcer to satisfy forwardproxy.CloudEnforcer.
// This adapter bridges the type gap between cloud.EnforcementResult and
// forwardproxy.EnforcementResult without introducing a circular import.
type enforcerAdapter struct {
	inner *cloud.Enforcer
}

// newEnforcerAdapter creates an adapter. Returns nil (typed as the interface)
// when the enforcer is nil so that interface nil checks work correctly.
func newEnforcerAdapter(e *cloud.Enforcer) forwardproxy.CloudEnforcer {
	if e == nil {
		return nil
	}
	return &enforcerAdapter{inner: e}
}

func (a *enforcerAdapter) Evaluate(toolName, agentName, argsJSON string) forwardproxy.EnforcementResult {
	r := a.inner.Evaluate(toolName, agentName, argsJSON)
	return forwardproxy.EnforcementResult{
		Action:     r.Action,
		PolicyID:   r.PolicyID,
		PolicyName: r.PolicyName,
		RuleIndex:  r.RuleIndex,
	}
}
