package cloud

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// Client communicates with the Quint cloud API for machine registration,
// heartbeats, and event ingestion.
type Client struct {
	apiURL    string
	token     string
	machineID string
	cloudUUID string
	http      *http.Client
}

// registerRequest is the body sent to POST /v1/machines/register.
type registerRequest struct {
	MachineID    string `json:"machine_id"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
}

// registerResponse is the response from POST /v1/machines/register.
type registerResponse struct {
	MachineID string `json:"machine_id"`
	OrgID     string `json:"org_id"`
}

// heartbeatRequest is the body sent to POST /v1/machines/{id}/heartbeat.
type heartbeatRequest struct {
	AgentVersion string `json:"agent_version"`
	Uptime       int64  `json:"uptime"`
	ActiveAgents int    `json:"active_agents"`
	EventsToday  int    `json:"events_today"`
}

// EventPayload is a single event to push to the cloud.
// Field names match the quint-api EventInput schema.
type EventPayload struct {
	EventID   string            `json:"event_id"`
	Action    string            `json:"action"`
	Agent     string            `json:"agent"`
	Timestamp string            `json:"timestamp"`
	RiskScore *int              `json:"risk_score,omitempty"`
	Blocked   bool              `json:"blocked"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// eventsRequest is the body sent to POST /v1/machines/{id}/events.
type eventsRequest struct {
	Events []EventPayload `json:"events"`
}

// NewClient creates a new cloud API client.
func NewClient(apiURL, token string) *Client {
	return &Client{
		apiURL:    apiURL,
		token:     token,
		machineID: generateMachineID(),
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// MachineID returns the deterministic machine identifier.
func (c *Client) MachineID() string {
	return c.machineID
}

// CloudUUID returns the UUID assigned by the cloud after registration.
func (c *Client) CloudUUID() string {
	return c.cloudUUID
}

// Register registers this machine with the cloud API.
// Stores the returned cloud UUID for subsequent requests.
func (c *Client) Register(version string) error {
	hostname, _ := os.Hostname()

	body := registerRequest{
		MachineID:    c.machineID,
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		AgentVersion: version,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal register request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/machines/register", c.apiURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create register request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("register returned status %d", resp.StatusCode)
	}

	var result registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode register response: %w", err)
	}

	c.cloudUUID = result.MachineID
	qlog.Info("registered with cloud: machine_id=%s, cloud_uuid=%s", c.machineID, c.cloudUUID)
	return nil
}

// HeartbeatResult holds the parsed heartbeat response.
type HeartbeatResult struct {
	ConfigVersion string   `json:"config_version"`
	PolicyHash    string   `json:"policy_hash"`
	Domains       []string `json:"domains,omitempty"`
}

// Heartbeat sends a heartbeat to the cloud API and returns the response
// (including policy_hash for change detection).
func (c *Client) Heartbeat(version string, uptime int64, activeAgents, eventsToday int) (*HeartbeatResult, error) {
	if c.cloudUUID == "" {
		return nil, fmt.Errorf("not registered (no cloud UUID)")
	}

	body := heartbeatRequest{
		AgentVersion: version,
		Uptime:       uptime,
		ActiveAgents: activeAgents,
		EventsToday:  eventsToday,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal heartbeat: %w", err)
	}

	url := fmt.Sprintf("%s/v1/machines/%s/heartbeat", c.apiURL, c.cloudUUID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create heartbeat request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("heartbeat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("heartbeat returned status %d", resp.StatusCode)
	}

	// Parse heartbeat response — may contain policy_hash for change detection
	var result HeartbeatResult
	if resp.StatusCode == http.StatusOK {
		// Best-effort decode; if it fails, we still have a successful heartbeat
		_ = json.NewDecoder(resp.Body).Decode(&result)
	}

	qlog.Debug("heartbeat sent: uptime=%ds, agents=%d, events=%d, policy_hash=%s", uptime, activeAgents, eventsToday, result.PolicyHash)
	return &result, nil
}

// FetchPolicies fetches enforcement policies for this machine.
// Supports ETag caching — pass the current hash as etag. Returns nil policies if 304.
func (c *Client) FetchPolicies(etag string) ([]CloudPolicy, string, error) {
	if c.cloudUUID == "" {
		return nil, "", fmt.Errorf("not registered (no cloud UUID)")
	}

	url := fmt.Sprintf("%s/v1/machines/%s/policies", c.apiURL, c.cloudUUID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create policies request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("policies request failed: %w", err)
	}
	defer resp.Body.Close()

	// 304 Not Modified — policies haven't changed
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("policies fetch returned status %d", resp.StatusCode)
	}

	var policies []CloudPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return nil, "", fmt.Errorf("decode policies response: %w", err)
	}

	// Extract ETag from response header
	newETag := resp.Header.Get("ETag")
	if newETag == "" {
		// Fallback: use the policy_hash from heartbeat if no ETag header
		newETag = etag
	}

	qlog.Info("fetched %d cloud policies (etag=%s)", len(policies), newETag)
	return policies, newETag, nil
}

// PushEvents sends a batch of events to the cloud API.
func (c *Client) PushEvents(events []EventPayload) error {
	if c.cloudUUID == "" {
		return fmt.Errorf("not registered (no cloud UUID)")
	}

	body := eventsRequest{Events: events}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	url := fmt.Sprintf("%s/v1/machines/%s/events", c.apiURL, c.cloudUUID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create events request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("events request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("events push returned status %d", resp.StatusCode)
	}

	qlog.Debug("pushed %d events to cloud", len(events))
	return nil
}

// GraphPayload is a single agent graph to push to the cloud.
type GraphPayload struct {
	ID            string          `json:"id"`
	RootAgentID   string          `json:"root_agent_id"`
	RootAgentName string          `json:"root_agent_name"`
	Status        string          `json:"status"`
	TotalNodes    int             `json:"total_nodes"`
	Nodes         json.RawMessage `json:"nodes"`
	StartedAt     string          `json:"started_at"`
	CompletedAt   string          `json:"completed_at,omitempty"`
}

type graphsRequest struct {
	Graphs []GraphPayload `json:"graphs"`
}

// PushGraphs sends agent graph data to the cloud API.
// Retries once on failure with a 2-second delay.
func (c *Client) PushGraphs(graphs []GraphPayload) error {
	if c.cloudUUID == "" {
		return fmt.Errorf("not registered (no cloud UUID)")
	}

	body := graphsRequest{Graphs: graphs}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal graphs: %w", err)
	}

	url := fmt.Sprintf("%s/v1/machines/%s/graphs", c.apiURL, c.cloudUUID)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		req, err := http.NewRequest("POST", url, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("create graphs request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("graphs request failed: %w", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			qlog.Debug("pushed %d graphs to cloud", len(graphs))
			return nil
		}
		lastErr = fmt.Errorf("graphs push returned status %d", resp.StatusCode)
	}
	return lastErr
}

// AgentInventoryEntry represents a detected AI agent process.
type AgentInventoryEntry struct {
	Platform   string  `json:"platform"`
	PID        int     `json:"pid"`
	BinaryPath string  `json:"binary_path,omitempty"`
	State      string  `json:"state"`
	CPUPercent float64 `json:"cpu_percent,omitempty"`
	MemoryMB   int     `json:"memory_mb,omitempty"`
	StartedAt  string  `json:"started_at,omitempty"`
}

type agentInventoryRequest struct {
	Agents []AgentInventoryEntry `json:"agents"`
}

// ReportAgentInventory sends the current agent process inventory to the cloud.
func (c *Client) ReportAgentInventory(agents []AgentInventoryEntry) error {
	if c.cloudUUID == "" {
		return nil
	}

	body := agentInventoryRequest{Agents: agents}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal agent inventory: %w", err)
	}

	url := fmt.Sprintf("%s/v1/machines/%s/agents", c.apiURL, c.cloudUUID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create agent inventory request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent inventory request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("agent inventory report returned status %d", resp.StatusCode)
	}

	qlog.Debug("reported %d agent processes to cloud", len(agents))
	return nil
}

// generateMachineID produces a deterministic machine identifier from
// hostname, OS, and architecture: sha256(hostname:os:arch) truncated to 32 hex chars.
func generateMachineID() string {
	hostname, _ := os.Hostname()
	input := fmt.Sprintf("%s:%s:%s", hostname, runtime.GOOS, runtime.GOARCH)
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)[:32]
}
