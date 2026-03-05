package audit

import (
	"encoding/json"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/crypto"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/google/uuid"
)

// Logger produces signed, chain-linked audit entries.
type Logger struct {
	db         *DB
	privateKey string
	publicKey  string
	policyHash string
}

// NewLogger creates an audit logger. It computes the policy hash from the canonical policy JSON.
func NewLogger(db *DB, privateKey, publicKey string, policyJSON map[string]any) *Logger {
	canonical, err := crypto.Canonicalize(policyJSON)
	if err != nil {
		qlog.Error("failed to canonicalize policy for hash: %v", err)
		canonical = "{}"
	}
	return &Logger{
		db:         db,
		privateKey: privateKey,
		publicKey:  publicKey,
		policyHash: crypto.SHA256Hex(canonical),
	}
}

// LogOpts are the fields for a single audit entry.
type LogOpts struct {
	ServerName         string
	Direction          string // "request" or "response"
	Method             string
	MessageID          string
	ToolName           string
	ArgumentsJSON      string
	ResponseJSON       string
	Verdict            string
	RiskScore          *int
	RiskLevel          *string
	AgentID            string
	AgentName          string
	ScoringSource      string
	LocalScore         *int
	RemoteScore        *int
	GNNScore           *float64
	Confidence         *float64
	ComplianceRefs     []string
	BehavioralFlags    []string
	ScoreDecomposition map[string]any
	Mitigations        []string
	CloudEventID       string
	TraceID            string
	AgentDepth         *int
	ParentAgentID      string
	SpawnDetected      string // JSON of spawn event if detected

	// Cloud auth fields
	TokenType    string // "agent", "subagent", "session", etc.
	TokenJTI     string // JWT token ID
	RBACDecision string // "allowed" or denial reason
	CustomerID   string // customer ID from JWT
}

// Log creates a signed audit entry and inserts it atomically.
func (l *Logger) Log(opts LogOpts) {
	_, err := l.db.InsertAtomic(func(prevSignature string) Entry {
		timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		nonce := uuid.New().String()

		var prevHash string
		if prevSignature != "" {
			prevHash = crypto.SHA256Hex(prevSignature)
		}

		// Build the signable object — always include risk_score/risk_level (even when nil)
		msgID := strPtr(opts.MessageID)
		toolName := strPtr(opts.ToolName)
		argsJSON := strPtr(opts.ArgumentsJSON)
		respJSON := strPtr(opts.ResponseJSON)
		agentID := strPtr(opts.AgentID)
		agentName := strPtr(opts.AgentName)

		obj := crypto.BuildSignableObject(
			timestamp, opts.ServerName, opts.Direction, opts.Method,
			msgID, toolName, argsJSON, respJSON,
			opts.Verdict, l.policyHash, prevHash, nonce, l.publicKey,
			opts.RiskScore, opts.RiskLevel,
			agentID, agentName,
		)

		canonical, err := crypto.Canonicalize(obj)
		if err != nil {
			qlog.Error("failed to canonicalize entry: %v", err)
			canonical = "{}"
		}

		sig, err := crypto.SignData(canonical, l.privateKey)
		if err != nil {
			qlog.Error("failed to sign entry: %v", err)
			sig = ""
		}

		// Serialize enrichment fields to JSON
		var complianceRefsJSON, behavioralFlagsJSON, scoreDecompJSON, mitigationsJSON *string

		if len(opts.ComplianceRefs) > 0 {
			if b, err := json.Marshal(opts.ComplianceRefs); err == nil {
				complianceRefsJSON = strPtr(string(b))
			}
		}

		if len(opts.BehavioralFlags) > 0 {
			if b, err := json.Marshal(opts.BehavioralFlags); err == nil {
				behavioralFlagsJSON = strPtr(string(b))
			}
		}

		if opts.ScoreDecomposition != nil && len(opts.ScoreDecomposition) > 0 {
			if b, err := json.Marshal(opts.ScoreDecomposition); err == nil {
				scoreDecompJSON = strPtr(string(b))
			}
		}

		if len(opts.Mitigations) > 0 {
			if b, err := json.Marshal(opts.Mitigations); err == nil {
				mitigationsJSON = strPtr(string(b))
			}
		}

		scoringSource := strPtr(opts.ScoringSource)
		cloudEventID := strPtr(opts.CloudEventID)
		traceID := strPtr(opts.TraceID)
		parentAgentID := strPtr(opts.ParentAgentID)
		spawnDetected := strPtr(opts.SpawnDetected)

		return Entry{
			Timestamp:          timestamp,
			ServerName:         opts.ServerName,
			Direction:          opts.Direction,
			Method:             opts.Method,
			MessageID:          msgID,
			ToolName:           toolName,
			ArgumentsJSON:      argsJSON,
			ResponseJSON:       respJSON,
			Verdict:            opts.Verdict,
			RiskScore:          opts.RiskScore,
			RiskLevel:          opts.RiskLevel,
			PolicyHash:         l.policyHash,
			PrevHash:           prevHash,
			Nonce:              nonce,
			Signature:          sig,
			PublicKey:          l.publicKey,
			AgentID:            agentID,
			AgentName:          agentName,
			ScoringSource:      scoringSource,
			LocalScore:         opts.LocalScore,
			RemoteScore:        opts.RemoteScore,
			GNNScore:           opts.GNNScore,
			Confidence:         opts.Confidence,
			ComplianceRefs:     complianceRefsJSON,
			BehavioralFlags:    behavioralFlagsJSON,
			ScoreDecomposition: scoreDecompJSON,
			Mitigations:        mitigationsJSON,
			CloudEventID:       cloudEventID,
			TraceID:            traceID,
			AgentDepth:         opts.AgentDepth,
			ParentAgentID:      parentAgentID,
			SpawnDetected:      spawnDetected,
		}
	})
	if err != nil {
		qlog.Error("failed to insert audit entry: %v", err)
	}
}

// RecordRelationship persists an agent relationship to the database.
func (l *Logger) RecordRelationship(parentAgent, childAgent string, confidence float64, depth int, spawnType, signalType string) {
	if l.db == nil {
		return
	}
	if err := l.db.UpsertRelationship(parentAgent, childAgent, confidence, depth, spawnType, signalType, ""); err != nil {
		qlog.Error("failed to upsert relationship: %v", err)
	}
}

// RecordSpawnEvent persists a spawn event to the database.
func (l *Logger) RecordSpawnEvent(timestamp, patternID, parentAgent, childHint, spawnType, toolName, serverName, argsRef string, confidence float64) {
	if l.db == nil {
		return
	}
	if err := l.db.InsertSpawnEvent(timestamp, patternID, parentAgent, childHint, spawnType, toolName, serverName, argsRef, confidence); err != nil {
		qlog.Error("failed to insert spawn event: %v", err)
	}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
