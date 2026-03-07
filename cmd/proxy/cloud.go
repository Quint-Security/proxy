package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/intercept"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

// cloudEntry is the metadata sent to the cloud dashboard (no raw args/PII).
type cloudEntry struct {
	Timestamp           string              `json:"timestamp"`
	ServerName          string              `json:"server_name"`
	ToolName            string              `json:"tool_name,omitempty"`
	Direction           string              `json:"direction"`
	Method              string              `json:"method,omitempty"`
	Verdict             string              `json:"verdict"`
	RiskScore           *int                `json:"risk_score,omitempty"`
	RiskLevel           *string             `json:"risk_level,omitempty"`
	ScoringSource       string              `json:"scoring_source,omitempty"`
	LocalScore          *int                `json:"local_score,omitempty"`
	FieldClassifications []fieldClassification `json:"field_classifications,omitempty"`
	AgentID             string              `json:"agent_id,omitempty"`
	AgentName           string              `json:"agent_name,omitempty"`
	Signature           string              `json:"signature,omitempty"`
	PrevHash            string              `json:"prev_hash,omitempty"`
	PolicyHash          string              `json:"policy_hash,omitempty"`
}

type fieldClassification struct {
	Field          string `json:"field"`
	Classification string `json:"classification"`
}

type cloudPayload struct {
	ProxyID string       `json:"proxy_id"`
	Entries []cloudEntry `json:"entries"`
}

var cloudClient = &http.Client{Timeout: 5 * time.Second}

// forwardToCloud sends metadata (no raw arguments) to the cloud dashboard.
// Runs in a goroutine — fire-and-forget, never blocks the hook.
func forwardToCloud(
	cfg *intercept.CloudConfig,
	serverName string,
	input hookInput,
	verdict string,
	score risk.Score,
) {
	if cfg == nil || cfg.URL == "" || cfg.APIKey == "" {
		return
	}

	riskScore := score.Value
	riskLevel := score.Level

	// Extract field classifications from tool_input keys (no values)
	var classifications []fieldClassification
	for key := range input.ToolInput {
		classifications = append(classifications, fieldClassification{
			Field:          key,
			Classification: "none",
		})
	}

	entry := cloudEntry{
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		ServerName:           serverName,
		ToolName:             input.ToolName,
		Direction:            "request",
		Method:               "tools/call",
		Verdict:              verdict,
		RiskScore:            &riskScore,
		RiskLevel:            &riskLevel,
		ScoringSource:        "local",
		LocalScore:           &riskScore,
		FieldClassifications: classifications,
	}

	payload := cloudPayload{
		ProxyID: "hook",
		Entries: []cloudEntry{entry},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(body))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := cloudClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
