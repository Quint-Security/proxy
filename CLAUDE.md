# Plan: Wire Go Proxy → Cloud Scoring API → Dashboard

## Goal
End-to-end flow: Agent → Go Proxy → Railway Scoring API → Web Dashboard

## Current State

### What exists:
- **Go proxy** (`Quint-Security/proxy`): Intercepts MCP tool calls in stdio relay mode and gateway mode. Has local risk scoring (pattern + keyword + behavior). Has `internal/risk/remote.go` that already calls a remote API — but sends a **flat payload** (just tool name, args, subject ID).
- **Python scoring API** (`Quint-Security/infra`): Full 4-layer scoring pipeline on Railway. Accepts rich `AgentEventCreate` schema with `agent`, `session`, `target`, `mcp_context`, `preceding_actions`, `data_fields_accessed`. Returns `EventResponse` with score decomposition, behavioral flags, compliance refs, GNN score, confidence.
- **Dashboard** (`Quint-Security/dashboard`): Next.js app designed to be embedded in the Go proxy binary. Talks to `/api/status`, `/api/audit`, `/api/agents`, `/api/approvals`, `/api/policy`.
- **Auth service** (`Quint-Security/infra` — `src/auth_service/`): Token hierarchy with ES256 JWT.

### The gap:
1. The proxy's `remote.go` sends a **minimal flat payload** to the scoring API. It should send the **full canonical event** with agent info, MCP context, session, preceding actions, sensitivity classification.
2. The proxy doesn't track **preceding actions** (action sequence per session). It only tracks per-subject behavior counts for escalation.
3. The proxy doesn't send **MCP context** (server name, transport type, verified status, tool name).
4. The dashboard only works embedded locally — needs cloud mode.

---

## Task Breakdown (for Claude Code session)

### Task 1: Enrich the remote API payload in the Go proxy

**File: `internal/risk/remote.go`**

Replace the flat `eventRequest` struct with the full canonical schema matching `AgentEventCreate`:

```go
type eventRequest struct {
    EventID           string              `json:"event_id"`
    AgentID           string              `json:"agent_id,omitempty"`
    Action            string              `json:"action"`
    TargetResource    string              `json:"target_resource,omitempty"`
    DataFieldsAccessed []string           `json:"data_fields_accessed,omitempty"`
    UserContext       string              `json:"user_context,omitempty"`
    Metadata          map[string]any      `json:"metadata,omitempty"`
    Timestamp         string              `json:"timestamp"`
    Agent             *AgentInfoPayload   `json:"agent,omitempty"`
    Session           *SessionInfoPayload `json:"session,omitempty"`
    Target            *TargetInfoPayload  `json:"target,omitempty"`
    Parameters        json.RawMessage     `json:"parameters,omitempty"`
    MCPContext        *MCPContextPayload  `json:"mcp_context,omitempty"`
    PrecedingActions  []string            `json:"preceding_actions,omitempty"`
}

type AgentInfoPayload struct {
    AgentID   string `json:"agent_id"`
    AgentType string `json:"agent_type,omitempty"`
    Framework string `json:"framework,omitempty"`
    Model     string `json:"model,omitempty"`
}

type SessionInfoPayload struct {
    SessionID string `json:"session_id"`
    UserID    string `json:"user_id,omitempty"`
}

type TargetInfoPayload struct {
    ResourceType     string `json:"resource_type,omitempty"`
    ResourceID       string `json:"resource_id,omitempty"`
    SensitivityLevel int    `json:"sensitivity_level,omitempty"`
}

type MCPContextPayload struct {
    ServerName string `json:"server_name"`
    Transport  string `json:"transport,omitempty"`
    IsVerified bool   `json:"is_verified"`
    ToolName   string `json:"tool_name,omitempty"`
}
```

Update `EnhanceScore` signature to accept the richer context:

```go
func (r *RemoteScorer) EnhanceScore(localScore Score, toolName, argsJSON, subjectID, serverName string, ctx *EventContext) Score
```

Where `EventContext` is a new struct:

```go
// EventContext carries enriched context from the proxy to the remote scorer.
type EventContext struct {
    AgentID          string
    AgentName        string
    ServerName       string
    Transport        string   // "stdio" or "http"
    IsVerified       bool
    ToolName         string
    PrecedingActions []string
    SessionID        string
}
```

### Task 2: Track preceding actions per session

**New file: `internal/risk/session.go`**

```go
// SessionTracker tracks the last N actions per agent/session for behavioral context.
type SessionTracker struct {
    mu       sync.RWMutex
    sessions map[string]*actionWindow
    maxActions int
    windowDuration time.Duration
}

type actionWindow struct {
    actions []string
    times   []time.Time
}

// Record adds an action to the session's history.
func (t *SessionTracker) Record(sessionKey, action string) { ... }

// Recent returns the last N actions for a session within the time window.
func (t *SessionTracker) Recent(sessionKey string) []string { ... }
```

- Default: track last 20 actions per session, 30-minute sliding window.
- Session key = `subjectID` (agent identity) or `"default"` if no identity.
- Used in both relay mode (`handleParentMessage`) and gateway mode (`handleToolsCall`).

### Task 3: Build canonical action strings

**New file: `internal/intercept/classify.go`**

Map tool calls to the canonical `domain:scope:verb` format that the scoring API expects:

```go
// ClassifyAction converts a tool call to canonical action format.
// Format: mcp:{server}:{tool}.{verb}
func ClassifyAction(serverName, toolName, method string) string {
    if method == "tools/call" {
        verb := inferVerb(toolName)
        return fmt.Sprintf("mcp:%s:%s.%s", serverName, toolName, verb)
    }
    if method == "resources/read" {
        return fmt.Sprintf("mcp:%s:resource.read", serverName)
    }
    if method == "prompts/get" {
        return fmt.Sprintf("mcp:%s:prompt.get", serverName)
    }
    return fmt.Sprintf("mcp:%s:%s", serverName, method)
}

// inferVerb extracts a verb from tool name patterns.
func inferVerb(toolName string) string {
    // "list_repos" -> "list", "create_file" -> "create", etc.
    // Split on _ and take the first word if it's a known verb
    ...
}
```

### Task 4: Wire it all together in gateway mode

**File: `internal/gateway/gateway.go`**

In `handleToolsCall`, after policy check and before forwarding to backend:

1. Classify the action: `action := intercept.ClassifyAction(backendName, toolName, "tools/call")`
2. Record in session tracker: `g.sessionTracker.Record(subjectID, action)`
3. Get preceding actions: `preceding := g.sessionTracker.Recent(subjectID)`
4. Build event context with all the enriched fields
5. Pass context to `riskEngine.EnhanceWithRemote(score, toolName, args, subjectID, backendName, eventCtx)`

### Task 5: Wire it in relay mode

**File: `cmd/proxy/main.go`** (and `cmd/proxy/risk_stub.go`)

Same pattern: classify action, track in session, pass context to scorer.

Update the `scoreTool` function signature and the `handleParentMessage` to pass through the server name and build event context.

### Task 6: Parse and use the enriched response

**File: `internal/risk/remote.go`**

Update `eventResponse` to capture the full scoring API response:

```go
type eventResponse struct {
    EventID          string            `json:"event_id"`
    Score            int               `json:"score"`
    RiskLevel        string            `json:"risk_level"`
    Violations       []string          `json:"violations"`
    Reasoning        string            `json:"reasoning"`
    ScoringSource    string            `json:"scoring_source"`
    ComplianceRefs   []string          `json:"compliance_refs"`
    Mitigations      []string          `json:"mitigations"`
    BehavioralFlags  []string          `json:"behavioral_flags"`
    ScoreDecomposition map[string]any  `json:"score_decomposition"`
    GNNScore         *float64          `json:"gnn_score"`
    Confidence       *float64          `json:"confidence"`
}
```

Store the decomposition and behavioral flags in the audit log for the dashboard to display.

---

## File Summary

| File | Action |
|------|--------|
| `internal/risk/remote.go` | Rewrite payload to match `AgentEventCreate` schema, parse rich response |
| `internal/risk/session.go` | New — session action tracker (sliding window) |
| `internal/risk/types.go` | New — `EventContext` struct shared across packages |
| `internal/intercept/classify.go` | New — canonical action classification `mcp:server:tool.verb` |
| `internal/gateway/gateway.go` | Wire session tracking + enriched context into `handleToolsCall` |
| `cmd/proxy/main.go` | Wire session tracking into relay mode `handleParentMessage` |
| `cmd/proxy/risk_stub.go` | Update `scoreTool` to accept and pass `EventContext` |
| `internal/audit/logger.go` | Extend `LogOpts` to include behavioral_flags, compliance_refs, score_decomposition |

## Testing

1. Run the proxy in gateway mode with `risk_api` configured pointing at Railway: `https://api-production-56df.up.railway.app`
2. API key: `sk-acme-b96cb84498324444`, Customer ID: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
3. Make a tool call through the gateway
4. Verify the scoring API receives the full event with MCP context and preceding actions
5. Verify the proxy receives and logs the 4-layer score decomposition
6. Check the dashboard shows the enriched audit entry

## API Endpoint Reference

- **Scoring API**: `POST https://api-production-56df.up.railway.app/events`
- **Health check**: `GET https://api-production-56df.up.railway.app/health`
- **Auth**: `X-API-Key: sk-acme-b96cb84498324444` header

## Important Notes

- The scoring API validates the `action` field — if it has 2+ colons, it must match the taxonomy format `domain:scope:verb`. So `ClassifyAction` output must be valid.
- The scoring API's `AgentEventCreate` has a `model_validator` that promotes `agent_id` → `agent.agent_id` and `target_resource` → `target.resource_id`, so flat fields still work as fallback.
- `preceding_actions` entries are also validated if they contain 2+ colons — make sure the session tracker stores canonical action strings.
- Remote scoring should remain non-blocking with graceful fallback to local scoring on timeout/error (current behavior, preserve it).
- Keep the local scoring as the first layer — remote enriches, never downgrades.
