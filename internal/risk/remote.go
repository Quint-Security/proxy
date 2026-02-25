package risk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

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
	return 3 * time.Second
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

// eventRequest is the payload sent to POST /events.
type eventRequest struct {
	EventID    string          `json:"event_id"`
	CustomerID string          `json:"customer_id"`
	AgentID    string          `json:"agent_id"`
	Action     string          `json:"action"`
	Parameters json.RawMessage `json:"parameters"`
	Timestamp  string          `json:"timestamp"`
	LocalScore int             `json:"local_score"`
	LocalLevel string          `json:"local_level"`
}

// eventResponse is the response from POST /events.
type eventResponse struct {
	Score         int      `json:"score"`
	RiskLevel     string   `json:"risk_level"`
	Violations    []string `json:"violations"`
	Reasoning     string   `json:"reasoning"`
	ScoringSource string   `json:"scoring_source"`
}

// EnhanceScore calls the remote API and returns an enhanced score.
// Falls back to localScore on any failure (timeout, network error, bad response).
func (r *RemoteScorer) EnhanceScore(localScore Score, toolName, argsJSON, subjectID, serverName string) Score {
	req := eventRequest{
		EventID:    fmt.Sprintf("%s:%s:%d", serverName, toolName, time.Now().UnixMilli()),
		CustomerID: r.config.CustomerID,
		AgentID:    subjectID,
		Action:     fmt.Sprintf("tool_call:%s.%s", serverName, toolName),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		LocalScore: localScore.Value,
		LocalLevel: localScore.Level,
	}

	// Include tool arguments if available
	if argsJSON != "" {
		req.Parameters = json.RawMessage(argsJSON)
	} else {
		req.Parameters = json.RawMessage("{}")
	}

	body, _ := json.Marshal(req)

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

	if resp.StatusCode != 200 {
		qlog.Warn("remote risk: API returned %d, falling back to local score", resp.StatusCode)
		return localScore
	}

	var result eventResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		qlog.Warn("remote risk: failed to parse response, falling back to local score: %v", err)
		return localScore
	}

	qlog.Info("remote risk: action=%s local=%d remote=%d level=%s source=%s reasoning=%q violations=%v",
		req.Action, localScore.Value, result.Score, result.RiskLevel, result.ScoringSource, result.Reasoning, result.Violations)

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

	return Score{
		Value:         finalScore,
		BaseScore:     localScore.BaseScore,
		ArgBoost:      localScore.ArgBoost,
		BehaviorBoost: localScore.BehaviorBoost,
		Level:         level,
		Reasons:       reasons,
	}
}
