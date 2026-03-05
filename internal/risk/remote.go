package risk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// sanitize replaces characters that break the action taxonomy format.
func sanitize(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

// RemoteConfig configures the remote risk scoring API.
type RemoteConfig struct {
	URL        string `json:"url"`
	APIKey     string `json:"api_key"`
	CustomerID string `json:"customer_id"`
	Enabled    bool   `json:"enabled"`
	TimeoutMs  int    `json:"timeout_ms,omitempty"` // default 3000
}

// GetTimeout returns the effective timeout duration.
func (c RemoteConfig) GetTimeout() time.Duration {
	if c.TimeoutMs > 0 {
		return time.Duration(c.TimeoutMs) * time.Millisecond
	}
	return 15 * time.Second
}

// RemoteScorer calls an external risk API to enhance local scoring.
// Falls back to local scoring on any failure.
type RemoteScorer struct {
	config RemoteConfig
	client *http.Client
}

// NewRemoteScorer creates a new remote risk scorer.
// Returns nil if config is nil or not enabled.
func NewRemoteScorer(cfg *RemoteConfig) *RemoteScorer {
	if cfg == nil || !cfg.Enabled || cfg.URL == "" {
		return nil
	}
	qlog.Info("remote risk API configured: %s", cfg.URL)
	return &RemoteScorer{
		config: *cfg,
		client: &http.Client{Timeout: cfg.GetTimeout()},
	}
}

// --- Request payload types matching AgentEventCreate schema ---

type eventRequest struct {
	EventID            string              `json:"event_id"`
	CustomerID         string              `json:"customer_id"`
	AgentID            string              `json:"agent_id,omitempty"`
	Action             string              `json:"action"`
	TargetResource     string              `json:"target_resource,omitempty"`
	DataFieldsAccessed []ClassifiedField   `json:"data_fields_accessed,omitempty"`
	UserContext        string              `json:"user_context,omitempty"`
	Metadata           map[string]any      `json:"metadata,omitempty"`
	Timestamp          string              `json:"timestamp"`
	Agent              *AgentInfoPayload   `json:"agent,omitempty"`
	Session            *SessionInfoPayload `json:"session,omitempty"`
	Target             *TargetInfoPayload  `json:"target,omitempty"`
	Parameters         json.RawMessage     `json:"parameters,omitempty"`
	MCPContext         *MCPContextPayload  `json:"mcp_context,omitempty"`
	PrecedingActions   []string            `json:"preceding_actions,omitempty"`
}

// AgentInfoPayload describes the agent making the action.
type AgentInfoPayload struct {
	AgentID   string `json:"agent_id"`
	AgentType string `json:"agent_type,omitempty"`
	Framework string `json:"framework,omitempty"`
	Model     string `json:"model,omitempty"`
}

// SessionInfoPayload describes the session context.
type SessionInfoPayload struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id,omitempty"`
}

// TargetInfoPayload describes the target resource.
type TargetInfoPayload struct {
	ResourceType     string `json:"resource_type,omitempty"`
	ResourceID       string `json:"resource_id,omitempty"`
	SensitivityLevel int    `json:"sensitivity_level,omitempty"`
}

// MCPContextPayload describes the MCP server context.
type MCPContextPayload struct {
	ServerName string `json:"server_name"`
	Transport  string `json:"transport,omitempty"`
	IsVerified bool   `json:"is_verified"`
	ToolName   string `json:"tool_name,omitempty"`
}

// --- Response types matching full scoring API response ---

type eventResponse struct {
	EventID            string         `json:"event_id"`
	Score              int            `json:"score"`
	RiskLevel          string         `json:"risk_level"`
	Violations         []string       `json:"violations"`
	Reasoning          string         `json:"reasoning"`
	ScoringSource      string         `json:"scoring_source"`
	ComplianceRefs     []string       `json:"compliance_refs"`
	Mitigations        []string       `json:"mitigations"`
	BehavioralFlags    []string       `json:"behavioral_flags"`
	ScoreDecomposition map[string]any `json:"score_decomposition"`
	GNNScore           *float64       `json:"gnn_score"`
	Confidence         *float64       `json:"confidence"`
}

// RemoteEnrichment holds the extra fields from the remote scoring response
// that should be persisted in the audit log.
type RemoteEnrichment struct {
	EventID            string         `json:"event_id,omitempty"`
	ScoringSource      string         `json:"scoring_source,omitempty"`
	ComplianceRefs     []string       `json:"compliance_refs,omitempty"`
	BehavioralFlags    []string       `json:"behavioral_flags,omitempty"`
	ScoreDecomposition map[string]any `json:"score_decomposition,omitempty"`
	GNNScore           *float64       `json:"gnn_score,omitempty"`
	Confidence         *float64       `json:"confidence,omitempty"`
	Mitigations        []string       `json:"mitigations,omitempty"`
}

// EnhanceScore calls the remote API and returns an enhanced score.
// Falls back to localScore on any failure (timeout, network error, bad response).
// ctx may be nil for backward compatibility.
func (r *RemoteScorer) EnhanceScore(localScore Score, toolName, argsJSON, subjectID, serverName string, ctx *EventContext) Score {
	req := eventRequest{
		EventID:    fmt.Sprintf("%s:%s:%d", serverName, toolName, time.Now().UnixMilli()),
		CustomerID: r.config.CustomerID,
		AgentID:    subjectID,
		Action:     fmt.Sprintf("mcp:%s:%s.invoke", sanitize(serverName), sanitize(toolName)),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"local_score": localScore.Value,
			"local_level": localScore.Level,
		},
	}

	// Include tool arguments
	if argsJSON != "" {
		req.Parameters = json.RawMessage(argsJSON)
	} else {
		req.Parameters = json.RawMessage("{}")
	}

	// Extract sensitive data fields and target from tool arguments
	classifiedFields := ExtractFields(argsJSON)
	if len(classifiedFields) > 0 {
		req.DataFieldsAccessed = classifiedFields
	}
	target := ExtractTarget(serverName, toolName, argsJSON, classifiedFields)
	if target != nil {
		req.Target = &TargetInfoPayload{
			ResourceType:     target.ResourceType,
			ResourceID:       target.ResourceID,
			SensitivityLevel: target.SensitivityLevel,
		}
	}

	// Enrich from EventContext if provided
	if ctx != nil {
		if ctx.AgentID != "" {
			agentType := ctx.AgentType
			if agentType == "" {
				agentType = "generic"
			}
			req.Agent = &AgentInfoPayload{
				AgentID:   ctx.AgentID,
				AgentType: agentType,
				Framework: "quint-proxy",
			}
		}

		if ctx.SessionID != "" {
			req.Session = &SessionInfoPayload{
				SessionID: ctx.SessionID,
			}
		}

		req.MCPContext = &MCPContextPayload{
			ServerName: ctx.ServerName,
			Transport:  ctx.Transport,
			IsVerified: ctx.IsVerified,
			ToolName:   ctx.ToolName,
		}

		if len(ctx.PrecedingActions) > 0 {
			req.PrecedingActions = ctx.PrecedingActions
		}

		// Override action with the canonical format if available
		if ctx.CanonicalAction != "" {
			req.Action = ctx.CanonicalAction
		} else if ctx.ToolName != "" {
			req.Action = fmt.Sprintf("mcp:%s:%s.invoke", ctx.ServerName, ctx.ToolName)
		}
	}

	body, _ := json.Marshal(req)

	qlog.Info("remote risk API request: %s", string(body))

	httpReq, err := http.NewRequest("POST", r.config.URL+"/events", bytes.NewReader(body))
	if err != nil {
		qlog.Debug("remote risk: failed to create request: %v", err)
		return localScore
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if r.config.APIKey != "" {
		httpReq.Header.Set("X-API-Key", r.config.APIKey)
	}

	resp, err := r.client.Do(httpReq)
	if err != nil {
		qlog.Warn("remote risk: API unreachable, falling back to local score: %v", err)
		return localScore
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	qlog.Info("remote risk API response [%d]: %s", resp.StatusCode, string(respBody))

	if resp.StatusCode != 200 {
		qlog.Warn("remote risk: API returned %d, falling back to local score", resp.StatusCode)
		return localScore
	}

	var result eventResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		qlog.Warn("remote risk: failed to parse response, falling back to local score: %v", err)
		return localScore
	}

	qlog.Info("remote risk: action=%s local=%d remote=%d level=%s source=%s reasoning=%q violations=%v gnn=%v confidence=%v",
		req.Action, localScore.Value, result.Score, result.RiskLevel, result.ScoringSource,
		result.Reasoning, result.Violations, result.GNNScore, result.Confidence)

	// Only use remote score if it's higher than local (never lower the security bar)
	finalScore := localScore.Value
	if result.Score > finalScore {
		finalScore = result.Score
	}

	// Merge reasons
	reasons := make([]string, len(localScore.Reasons))
	copy(reasons, localScore.Reasons)
	for _, v := range result.Violations {
		reasons = append(reasons, v)
	}
	if result.Reasoning != "" {
		reasons = append(reasons, "remote: "+result.Reasoning)
	}

	level := result.RiskLevel
	if level == "" {
		level = localScore.Level
	}

	qlog.Debug("remote risk: local=%d → remote=%d (final=%d, level=%s)", localScore.Value, result.Score, finalScore, level)

	enriched := Score{
		Value:         finalScore,
		BaseScore:     localScore.BaseScore,
		ArgBoost:      localScore.ArgBoost,
		BehaviorBoost: localScore.BehaviorBoost,
		Level:         level,
		Reasons:       reasons,
	}

	// Attach enrichment data for audit logging
	enriched.RemoteEnrichment = &RemoteEnrichment{
		EventID:            result.EventID,
		ScoringSource:      result.ScoringSource,
		ComplianceRefs:     result.ComplianceRefs,
		BehavioralFlags:    result.BehavioralFlags,
		ScoreDecomposition: result.ScoreDecomposition,
		GNNScore:           result.GNNScore,
		Confidence:         result.Confidence,
		Mitigations:        result.Mitigations,
	}

	return enriched
}
