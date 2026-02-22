package main

import (
	"encoding/json"
	"os"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

func initAudit(dataDir string, policy intercept.PolicyConfig, logEntry *logEntryFunc) {
	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		qlog.Error("failed to load/generate keys: %v", err)
		return
	}

	db, err := audit.OpenDB(dataDir)
	if err != nil {
		qlog.Error("failed to open audit database: %v", err)
		return
	}
	cleanupFuncs = append(cleanupFuncs, func() { db.Close() })

	// Convert policy to map[string]any for hashing
	policyBytes, _ := json.Marshal(policy)
	var policyMap map[string]any
	json.Unmarshal(policyBytes, &policyMap)

	logger := audit.NewLogger(db, kp.PrivateKey, kp.PublicKey, policyMap)

	*logEntry = func(serverName, direction, method, messageID, toolName, argsJSON, respJSON string, verdict intercept.Verdict, riskScore *int, riskLevel *string) {
		logger.Log(audit.LogOpts{
			ServerName:    serverName,
			Direction:     direction,
			Method:        method,
			MessageID:     messageID,
			ToolName:      toolName,
			ArgumentsJSON: argsJSON,
			ResponseJSON:  respJSON,
			Verdict:       string(verdict),
			RiskScore:     riskScore,
			RiskLevel:     riskLevel,
		})
	}
}
