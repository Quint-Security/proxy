package main

import (
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

func initRisk(dataDir string, scoreTool *scoreFunc, evalRisk *evalFunc, revoke *revokeFunc) {
	behaviorDB, err := risk.OpenBehaviorDB(dataDir)
	if err != nil {
		qlog.Error("failed to open behavior database: %v", err)
		// Continue with in-memory fallback
	}

	if behaviorDB != nil {
		cleanupFuncs = append(cleanupFuncs, func() { behaviorDB.Close() })
	}

	engine := risk.NewEngine(&risk.EngineOpts{
		BehaviorDB: behaviorDB,
	})

	// Optional gRPC risk service
	grpcClient := risk.NewGRPCClient()
	if grpcClient != nil {
		cleanupFuncs = append(cleanupFuncs, func() { grpcClient.Close() })
	}

	*scoreTool = func(toolName, argsJSON, subjectID string) *riskResult {
		s := engine.ScoreToolCall(toolName, argsJSON, subjectID)

		// Optionally enhance with remote ML scoring
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
