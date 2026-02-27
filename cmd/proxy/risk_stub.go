package main

import (
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

// sessionTracker is the global session tracker for relay mode.
var sessionTracker *risk.SessionTracker

func initRisk(dataDir string, policy intercept.PolicyConfig, scoreTool *scoreFunc, evalRisk *evalFunc, revoke *revokeFunc) {
	behaviorDB, err := risk.OpenBehaviorDB(dataDir)
	if err != nil {
		qlog.Error("failed to open behavior database: %v", err)
	}

	if behaviorDB != nil {
		cleanupFuncs = append(cleanupFuncs, func() { behaviorDB.Close() })
	}

	engine := risk.NewEngineFromPolicy(policy.Risk, behaviorDB)

	if policy.Risk != nil {
		t := engine.GetThresholds()
		qlog.Info("risk config: flag=%d deny=%d revoke_after=%d window=%dms builtins=%v",
			t.Flag, t.Deny, t.RevokeAfter, t.WindowMs, !policy.Risk.DisableBuiltins)
	}

	// Optional gRPC risk service
	grpcClient := risk.NewGRPCClient()
	if grpcClient != nil {
		cleanupFuncs = append(cleanupFuncs, func() { grpcClient.Close() })
	}

	// Initialize session tracker for preceding action context
	sessionTracker = risk.NewSessionTracker(20, 0)

	*scoreTool = func(toolName, argsJSON, subjectID, serverName string) *riskResult {
		s := engine.ScoreToolCall(toolName, argsJSON, subjectID)

		if grpcClient != nil {
			s = grpcClient.EnhanceScore(s, toolName, argsJSON, subjectID, serverName)
		}

		// Classify the action and build event context for remote enrichment
		action := intercept.ClassifyAction(serverName, toolName, "tools/call")
		var preceding []string
		if sessionTracker != nil {
			preceding = sessionTracker.Recent(subjectID)
		}
		eventCtx := &risk.EventContext{
			AgentID:          subjectID,
			ServerName:       serverName,
			Transport:        "stdio",
			IsVerified:       true,
			ToolName:         toolName,
			PrecedingActions: preceding,
			SessionID:        subjectID,
			CanonicalAction:  action,
		}

		s = engine.EnhanceWithRemote(s, toolName, argsJSON, subjectID, serverName, eventCtx)

		return &riskResult{score: s.Value, level: s.Level}
	}

	*evalRisk = func(score int) string {
		return engine.Evaluate(score)
	}

	*revoke = func(subjectID string) bool {
		return engine.ShouldRevoke(subjectID)
	}
}
