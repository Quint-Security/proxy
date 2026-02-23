package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
)

const batchSize = 500

// State tracks sync progress.
type State struct {
	LastSyncedID int64  `json:"last_synced_id"`
	LastSyncedAt string `json:"last_synced_at"`
}

// Config holds sync configuration.
type Config struct {
	APIURL string `json:"api_url"`
	APIKey string `json:"api_key"`
}

// LoadState loads sync state from disk.
func LoadState(dataDir string) State {
	path := filepath.Join(dataDir, "sync.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}
	}
	var s State
	json.Unmarshal(data, &s)
	return s
}

// SaveState persists sync state.
func SaveState(dataDir string, s State) {
	path := filepath.Join(dataDir, "sync.json")
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(path, data, 0o644)
}

// LoadConfig loads sync configuration from disk or environment.
func LoadConfig(dataDir string) Config {
	cfg := Config{
		APIURL: os.Getenv("QUINT_API_URL"),
		APIKey: os.Getenv("QUINT_API_KEY"),
	}

	path := filepath.Join(dataDir, "config.json")
	data, err := os.ReadFile(path)
	if err == nil {
		var fileCfg Config
		json.Unmarshal(data, &fileCfg)
		if cfg.APIURL == "" {
			cfg.APIURL = fileCfg.APIURL
		}
		if cfg.APIKey == "" {
			cfg.APIKey = fileCfg.APIKey
		}
	}

	return cfg
}

// entryPayload is the JSON format for API submission.
type entryPayload struct {
	Timestamp     string  `json:"timestamp"`
	ServerName    string  `json:"server_name"`
	Direction     string  `json:"direction"`
	Method        string  `json:"method"`
	MessageID     *string `json:"message_id"`
	ToolName      *string `json:"tool_name"`
	ArgumentsJSON *string `json:"arguments_json"`
	ResponseJSON  *string `json:"response_json"`
	Verdict       string  `json:"verdict"`
	RiskScore     *int    `json:"risk_score"`
	RiskLevel     *string `json:"risk_level"`
	PolicyHash    string  `json:"policy_hash"`
	PrevHash      string  `json:"prev_hash"`
	Nonce         string  `json:"nonce"`
	Signature     string  `json:"signature"`
	PublicKey     string  `json:"public_key"`
	AgentID       *string `json:"agent_id"`
	AgentName     *string `json:"agent_name"`
}

func toPayload(e audit.Entry) entryPayload {
	return entryPayload{
		Timestamp: e.Timestamp, ServerName: e.ServerName, Direction: e.Direction,
		Method: e.Method, MessageID: e.MessageID, ToolName: e.ToolName,
		ArgumentsJSON: e.ArgumentsJSON, ResponseJSON: e.ResponseJSON,
		Verdict: e.Verdict, RiskScore: e.RiskScore, RiskLevel: e.RiskLevel,
		PolicyHash: e.PolicyHash, PrevHash: e.PrevHash, Nonce: e.Nonce,
		Signature: e.Signature, PublicKey: e.PublicKey,
		AgentID: e.AgentID, AgentName: e.AgentName,
	}
}

const (
	maxRetries = 3
	retryBase  = 500 * time.Millisecond
)

// Run performs a single sync: pushes new audit entries to the API.
func Run(db *audit.DB, dataDir string, apiURL, apiKey string, verbose bool) (int, error) {
	state := LoadState(dataDir)
	synced := 0

	for {
		entries, err := db.GetAfterID(state.LastSyncedID, batchSize)
		if err != nil {
			return synced, fmt.Errorf("query entries: %w", err)
		}
		if len(entries) == 0 {
			break
		}

		if verbose {
			fmt.Printf("  Syncing batch of %d entries (IDs %d-%d)...\n",
				len(entries), entries[0].ID, entries[len(entries)-1].ID)
		}

		ingested, err := pushBatchWithRetry(apiURL, apiKey, entries, verbose)
		if err != nil {
			return synced, fmt.Errorf("push batch: %w", err)
		}
		synced += ingested

		// Only advance the cursor by the number actually ingested
		if ingested > 0 && ingested <= len(entries) {
			state.LastSyncedID = entries[ingested-1].ID
		} else if ingested == 0 {
			// Nothing ingested but no error — skip this batch to avoid infinite loop
			// (e.g., all entries are duplicates)
			state.LastSyncedID = entries[len(entries)-1].ID
		}
		state.LastSyncedAt = time.Now().UTC().Format(time.RFC3339)
		SaveState(dataDir, state)

		// If we didn't ingest the full batch, stop — partial success means
		// some entries were rejected and we need to re-evaluate from the new cursor
		if ingested < len(entries) && ingested > 0 {
			if verbose {
				fmt.Printf("  Partial batch: %d/%d ingested, will retry remaining on next sync\n", ingested, len(entries))
			}
			break
		}
	}

	return synced, nil
}

func pushBatchWithRetry(apiURL, apiKey string, entries []audit.Entry, verbose bool) (int, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			wait := retryBase * time.Duration(1<<uint(attempt-1))
			if verbose {
				fmt.Printf("  Retry %d/%d after %v...\n", attempt, maxRetries, wait)
			}
			time.Sleep(wait)
		}

		ingested, err := pushBatch(apiURL, apiKey, entries)
		if err == nil {
			return ingested, nil
		}
		lastErr = err

		// Only retry on transient errors (network, 5xx)
		if !isRetryable(err) {
			return 0, err
		}
	}
	return 0, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

func isRetryable(err error) bool {
	s := err.Error()
	// Network errors are retryable
	if !strings.Contains(s, "API returned") {
		return true
	}
	// 5xx server errors are retryable
	for _, code := range []string{"500", "502", "503", "504"} {
		if strings.Contains(s, "API returned "+code) {
			return true
		}
	}
	// 4xx client errors are not retryable
	return false
}

func pushBatch(apiURL, apiKey string, entries []audit.Entry) (int, error) {
	payloads := make([]entryPayload, len(entries))
	for i, e := range entries {
		payloads[i] = toPayload(e)
	}

	body, err := json.Marshal(map[string]any{"entries": payloads})
	if err != nil {
		return 0, fmt.Errorf("marshal entries: %w", err)
	}
	endpoint := fmt.Sprintf("%s/v1/audit/entries", apiURL)

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("API returned %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Ingested int `json:"ingested"`
	}
	json.Unmarshal(respBody, &result)
	return result.Ingested, nil
}

// PullPolicy fetches the active policy from the API and writes it locally.
func PullPolicy(dataDir, apiURL, apiKey string) (bool, error) {
	url := fmt.Sprintf("%s/v1/policies/active", apiURL)

	// Check ETag
	etagPath := filepath.Join(dataDir, "policy_etag.txt")
	var etag string
	if data, err := os.ReadFile(etagPath); err == nil {
		etag = string(data)
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 304 {
		return false, nil
	}
	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("API returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Name       string `json:"name"`
		Version    int    `json:"version"`
		ConfigJSON any    `json:"config_json"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	// Write policy
	policyPath := filepath.Join(dataDir, "policy.json")
	policyData, _ := json.MarshalIndent(result.ConfigJSON, "", "  ")
	os.WriteFile(policyPath, policyData, 0o644)

	// Save ETag
	if newEtag := resp.Header.Get("ETag"); newEtag != "" {
		os.WriteFile(etagPath, []byte(newEtag), 0o644)
	}

	fmt.Printf("  Policy updated: %s v%d\n", result.Name, result.Version)
	return true, nil
}
