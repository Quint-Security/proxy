package main

import (
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

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

	*scoreTool = func(toolName, argsJSON, subjectID string) *riskResult {
		s := engine.ScoreToolCall(toolName, argsJSON, subjectID)

		if grpcClient != nil {
			s = grpcClient.EnhanceScore(s, toolName, argsJSON, subjectID, "")
		}

		return &riskResult{score: s.Value, level: s.Level}
	}

	*evalRisk = func(score int) string {
		return engine.Evaluate(score)
	}

	*revoke = func(subjectID string) bool {
		return engine.ShouldRevoke(subjectID)
	}
}
