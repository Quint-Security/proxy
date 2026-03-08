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
	EventID   string `json:"event_id"`
	Action    string `json:"action"`
	Agent     string `json:"agent"`
	Timestamp string `json:"timestamp"`
	RiskScore *int   `json:"risk_score,omitempty"`
	Blocked   bool   `json:"blocked"`
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

// Heartbeat sends a heartbeat to the cloud API.
func (c *Client) Heartbeat(version string, uptime int64, activeAgents, eventsToday int) error {
	if c.cloudUUID == "" {
		return fmt.Errorf("not registered (no cloud UUID)")
	}

	body := heartbeatRequest{
		AgentVersion: version,
		Uptime:       uptime,
		ActiveAgents: activeAgents,
		EventsToday:  eventsToday,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	url := fmt.Sprintf("%s/v1/machines/%s/heartbeat", c.apiURL, c.cloudUUID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create heartbeat request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("heartbeat returned status %d", resp.StatusCode)
	}

	qlog.Debug("heartbeat sent: uptime=%ds, agents=%d, events=%d", uptime, activeAgents, eventsToday)
	return nil
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
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create graphs request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("graphs request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("graphs push returned status %d", resp.StatusCode)
	}

	qlog.Debug("pushed %d graphs to cloud", len(graphs))
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
