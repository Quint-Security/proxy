package main

import (
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
	"github.com/Quint-Security/quint-proxy/internal/stream"
)

// sessionTracker is the global session tracker for relay mode.
var sessionTracker *risk.SessionTracker

// spawnDetector is the global spawn detector for relay mode.
var spawnDetector *intercept.SpawnDetector

// correlationEngine is the global correlation engine for relay mode.
var correlationEngine *intercept.CorrelationEngine

// kafkaProducer is the global Kafka producer for relay mode.
var kafkaProducer *stream.Producer

// ticketSigner is the global spawn ticket signer for relay mode.
var ticketSigner *intercept.SpawnTicketSigner

func initRisk(dataDir string, policy intercept.PolicyConfig, scoreTool *scoreFunc, evalRisk *evalFunc, revoke *revokeFunc, agentIdentity ...*auth.Identity) {
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

	// Initialize spawn detection and correlation
	spawnDetector = intercept.NewSpawnDetector(nil)
	correlationEngine = intercept.NewCorrelationEngine()

	// Initialize spawn ticket signer
	if signer, signerErr := intercept.NewSpawnTicketSigner(0); signerErr != nil {
		qlog.Warn("failed to initialize spawn ticket signer: %v", signerErr)
	} else {
		ticketSigner = signer
	}

	// Initialize Kafka producer if configured
	if policy.Kafka != nil && policy.Kafka.Enabled {
		kafkaProducer = stream.NewProducer(&stream.ProducerConfig{
			Brokers:     policy.Kafka.Brokers,
			Enabled:     policy.Kafka.Enabled,
			Async:       policy.Kafka.Async,
			BatchSize:   policy.Kafka.BatchSize,
			BatchTimeMs: policy.Kafka.BatchTimeMs,
		})
		if kafkaProducer != nil {
			cleanupFuncs = append(cleanupFuncs, func() { kafkaProducer.Close() })
		}
	}

	*scoreTool = func(toolName, argsJSON, subjectID, serverName string) *riskResult {
		// Classify the action and build event context
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
		// Populate agent type from identity if available
		if len(agentIdentity) > 0 && agentIdentity[0] != nil {
			eventCtx.AgentType = agentIdentity[0].AgentType
			if eventCtx.AgentID == "" || eventCtx.AgentID == subjectID {
				eventCtx.AgentID = agentIdentity[0].AgentID
				eventCtx.AgentName = agentIdentity[0].AgentName
			}
		}

		// Agent depth from correlation engine
		if correlationEngine != nil {
			eventCtx.Depth = correlationEngine.GetDepth(subjectID)
			if parent := correlationEngine.GetParent(subjectID); parent != nil {
				eventCtx.ParentAgentID = parent.ParentAgent
			}
		}

		// Use context-aware scoring (includes depth penalty and burst detection)
		s := engine.ScoreWithContext(toolName, argsJSON, subjectID, eventCtx, sessionTracker)

		if grpcClient != nil {
			s = grpcClient.EnhanceScore(s, toolName, argsJSON, subjectID, serverName)
		}

		s = engine.EnhanceWithRemote(s, toolName, argsJSON, subjectID, serverName, eventCtx)

		result := &riskResult{
			score:      s.Value,
			level:      s.Level,
			localScore: s.BaseScore,
		}

		// Populate enrichment data if available
		if s.RemoteEnrichment != nil {
			result.scoringSource = "remote"
			result.complianceRefs = s.RemoteEnrichment.ComplianceRefs
			result.behavioralFlags = s.RemoteEnrichment.BehavioralFlags
			result.scoreDecomposition = s.RemoteEnrichment.ScoreDecomposition
			result.gnnScore = s.RemoteEnrichment.GNNScore
			result.confidence = s.RemoteEnrichment.Confidence
			result.mitigations = s.RemoteEnrichment.Mitigations
			result.cloudEventID = s.RemoteEnrichment.EventID
		} else {
			result.scoringSource = "local"
		}

		return result
	}

	*evalRisk = func(score int) string {
		return engine.Evaluate(score)
	}

	*revoke = func(subjectID string) bool {
		return engine.ShouldRevoke(subjectID)
	}
}
