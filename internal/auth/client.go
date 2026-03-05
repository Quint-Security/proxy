package auth

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

// AuthServiceClient communicates with the cloud auth service API.
type AuthServiceClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewAuthServiceClient creates an auth service client. Returns nil if baseURL is empty.
func NewAuthServiceClient(baseURL string, timeoutMs int) *AuthServiceClient {
	if baseURL == "" {
		return nil
	}
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	return &AuthServiceClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond},
	}
}

// tokenResponse is the common response from token creation endpoints.
type tokenResponse struct {
	Token  string      `json:"token"`
	Claims CloudClaims `json:"claims"`
}

// RequestSubagentToken requests a subagent token with narrowed RBAC.
func (c *AuthServiceClient) RequestSubagentToken(parentToken, agentID string, narrowedRBAC *RBACPolicy) (string, *CloudClaims, error) {
	body := map[string]any{
		"agent_id": agentID,
	}
	if narrowedRBAC != nil {
		body["rbac"] = narrowedRBAC
	}

	token, claims, err := c.requestToken("/tokens/subagent", parentToken, body)
	if err != nil {
		return "", nil, fmt.Errorf("request subagent token: %w", err)
	}
	return token, claims, nil
}

// RequestSessionToken requests a session token from an agent token.
func (c *AuthServiceClient) RequestSessionToken(agentToken, sessionID string, maxEvents int) (string, *CloudClaims, error) {
	body := map[string]any{
		"session_id": sessionID,
	}
	if maxEvents > 0 {
		body["max_events"] = maxEvents
	}

	token, claims, err := c.requestToken("/tokens/session", agentToken, body)
	if err != nil {
		return "", nil, fmt.Errorf("request session token: %w", err)
	}
	return token, claims, nil
}

// RequestOverrideToken requests a short-lived override token for an event.
func (c *AuthServiceClient) RequestOverrideToken(agentToken, eventID string, allowedDecisions []string) (string, *CloudClaims, error) {
	body := map[string]any{
		"event_id":          eventID,
		"allowed_decisions": allowedDecisions,
	}

	token, claims, err := c.requestToken("/tokens/override", agentToken, body)
	if err != nil {
		return "", nil, fmt.Errorf("request override token: %w", err)
	}
	return token, claims, nil
}

// RevokeToken revokes a single token by JTI.
func (c *AuthServiceClient) RevokeToken(adminToken, jti string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/tokens/%s", c.baseURL, jti), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke token: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// CascadeRevoke revokes a token and all its children.
func (c *AuthServiceClient) CascadeRevoke(adminToken, jti string) error {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/revoke/cascade/%s", c.baseURL, jti), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cascade revoke: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cascade revoke: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// FetchPublicKeys fetches the signing public keys for a customer.
func (c *AuthServiceClient) FetchPublicKeys(customerID string) ([]PublicKeyEntry, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/keys/public/%s", c.baseURL, customerID))
	if err != nil {
		return nil, fmt.Errorf("fetch public keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch public keys: status %d", resp.StatusCode)
	}

	var result struct {
		Keys []PublicKeyEntry `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode public keys: %w", err)
	}
	return result.Keys, nil
}

// requestToken sends a token creation request to the auth service.
func (c *AuthServiceClient) requestToken(path, bearerToken string, body map[string]any) (string, *CloudClaims, error) {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", nil, err
	}

	req, err := http.NewRequest("POST", c.baseURL+path, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		qlog.Error("auth service %s returned %d: %s", path, resp.StatusCode, string(respBody))
		return "", nil, fmt.Errorf("auth service %s: status %d", path, resp.StatusCode)
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("decode token response: %w", err)
	}

	return result.Token, &result.Claims, nil
}
