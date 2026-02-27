package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/credential"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

// Gateway is the MCP multiplexer. It presents as a single MCP server to the
// agent, routing tool calls to the appropriate downstream backend.
type Gateway struct {
	backends       map[string]Backend
	toolIndex      map[string]string // namespacedTool → backendName
	allTools       []Tool            // merged tool list with namespaced names
	policy         intercept.PolicyConfig
	logger         *audit.Logger
	riskEngine     *risk.Engine
	identity       *auth.Identity
	sessionTracker *risk.SessionTracker
}

// New creates a gateway from the given config.
func New(cfg *Config, opts GatewayOpts) (*Gateway, error) {
	g := &Gateway{
		backends:       make(map[string]Backend),
		toolIndex:      make(map[string]string),
		policy:         opts.Policy,
		logger:         opts.Logger,
		riskEngine:     opts.RiskEngine,
		identity:       opts.Identity,
		sessionTracker: risk.NewSessionTracker(20, 0),
	}

	// Create backends
	for name, serverCfg := range cfg.Servers {
		var b Backend
		if serverCfg.IsHTTP() {
			b = NewHTTPBackend(name, serverCfg, opts.CredStore)
		} else {
			b = NewStdioBackend(name, serverCfg, opts.CredStore)
		}
		g.backends[name] = b
	}

	return g, nil
}

// GatewayOpts configures the gateway.
type GatewayOpts struct {
	Policy     intercept.PolicyConfig
	Logger     *audit.Logger
	RiskEngine *risk.Engine
	Identity   *auth.Identity
	CredStore  *credential.Store
}

// Start initializes all backends and builds the tool index.
func (g *Gateway) Start() error {
	qlog.Info("Starting gateway with %d backend(s)...", len(g.backends))

	for name, b := range g.backends {
		if err := b.Start(); err != nil {
			qlog.Error("failed to start backend %s: %v", name, err)
			continue
		}
	}

	// Build merged tool list with namespacing
	g.allTools = nil
	g.toolIndex = make(map[string]string)

	for name, b := range g.backends {
		for _, tool := range b.Tools() {
			nsName := name + "." + tool.Name
			nsTool := Tool{
				Name:        nsName,
				Description: fmt.Sprintf("[%s] %s", name, tool.Description),
				InputSchema: tool.InputSchema,
			}
			g.allTools = append(g.allTools, nsTool)
			g.toolIndex[nsName] = name
		}
	}

	qlog.Info("Gateway ready: %d tools across %d backends", len(g.allTools), len(g.backends))
	return nil
}

// Stop shuts down all backends.
func (g *Gateway) Stop() {
	for _, b := range g.backends {
		b.Stop()
	}
}

// Run reads MCP JSON-RPC from stdin, processes it, and writes responses to stdout.
func (g *Gateway) Run() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		resp := g.handleMessage(line)
		if resp != "" {
			os.Stdout.WriteString(resp + "\n")
		}
	}
}

func (g *Gateway) handleMessage(line string) string {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return ""
	}

	// Check if it has a method (request) or result/error (response)
	methodRaw, hasMethod := msg["method"]
	if !hasMethod {
		return "" // response from agent, ignore
	}

	var method string
	json.Unmarshal(methodRaw, &method)

	idRaw := msg["id"]

	switch method {
	case "initialize":
		return g.handleInitialize(idRaw)
	case "notifications/initialized":
		return "" // no response needed
	case "tools/list":
		return g.handleToolsList(idRaw)
	case "tools/call":
		return g.handleToolsCall(idRaw, msg["params"])
	default:
		// Unknown method — return error
		return g.jsonRpcError(idRaw, -32601, fmt.Sprintf("Method not found: %s", method))
	}
}

func (g *Gateway) handleInitialize(id json.RawMessage) string {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "quint-gateway",
				"version": "1.0.0",
			},
		},
	}
	data, _ := json.Marshal(resp)
	return string(data)
}

func (g *Gateway) handleToolsList(id json.RawMessage) string {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"tools": g.allTools,
		},
	}
	data, _ := json.Marshal(resp)
	return string(data)
}

func (g *Gateway) handleToolsCall(id json.RawMessage, paramsRaw json.RawMessage) string {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return g.jsonRpcError(id, -32600, "Invalid params")
	}

	nsName := params.Name

	// Resolve namespace: "github.list_repos" → backend "github", tool "list_repos"
	backendName, toolName := splitNamespacedTool(nsName)
	if backendName == "" {
		// No namespace — try to find it in any backend
		if bName, ok := g.toolIndex[nsName]; ok {
			backendName = bName
			toolName = nsName
		} else {
			return g.jsonRpcError(id, -32602, fmt.Sprintf("Unknown tool: %s", nsName))
		}
	}

	backend, ok := g.backends[backendName]
	if !ok {
		return g.jsonRpcError(id, -32602, fmt.Sprintf("Unknown backend: %s", backendName))
	}

	// --- Security pipeline ---

	// Policy check — build a proper JSON-RPC message for the interceptor
	inspectMsg, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": json.RawMessage(params.Arguments),
		},
	})
	result := intercept.InspectRequest(string(inspectMsg), backendName, g.policy)

	// Risk scoring (before audit so score is captured in the log)
	var riskScore *int
	var riskLevel *string
	var score risk.Score
	var hasScore bool

	if g.riskEngine != nil {
		subjectID := "gateway:" + backendName
		if g.identity != nil {
			subjectID = g.identity.SubjectID
		}

		// Classify action to canonical format
		action := intercept.ClassifyAction(backendName, toolName, "tools/call")

		// Record in session tracker and get preceding actions
		g.sessionTracker.Record(subjectID, action)
		preceding := g.sessionTracker.Recent(subjectID)

		// Build enriched event context
		eventCtx := &risk.EventContext{
			ServerName:       backendName,
			Transport:        "http",
			IsVerified:       true,
			ToolName:         toolName,
			PrecedingActions: preceding,
			CanonicalAction:  action,
		}
		if g.identity != nil {
			eventCtx.AgentID = g.identity.AgentID
			eventCtx.AgentName = g.identity.AgentName
			eventCtx.SessionID = g.identity.SubjectID
		}

		score = g.riskEngine.ScoreToolCall(toolName, string(params.Arguments), subjectID)
		score = g.riskEngine.EnhanceWithRemote(score, toolName, string(params.Arguments), subjectID, backendName, eventCtx)
		riskScore = &score.Value
		riskLevel = &score.Level
		hasScore = true

		riskAction := g.riskEngine.Evaluate(score.Value)
		if riskAction == "deny" {
			qlog.Warn("risk-denied %s.%s (score=%d)", backendName, toolName, score.Value)
			return g.jsonRpcError(id, -32600, fmt.Sprintf("Quint: %s.%s blocked by risk score (%d)", backendName, toolName, score.Value))
		}
		if riskAction == "flag" {
			qlog.Warn("high-risk %s.%s (score=%d, level=%s)", backendName, toolName, score.Value, score.Level)
		}
	}

	// Audit request (includes risk score)
	if g.logger != nil {
		agentID, agentName := "", ""
		if g.identity != nil {
			agentID = g.identity.AgentID
			agentName = g.identity.AgentName
		}

		// Extract remote enrichment data if available
		logOpts := audit.LogOpts{
			ServerName:    backendName,
			Direction:     "request",
			Method:        "tools/call",
			ToolName:      toolName,
			ArgumentsJSON: string(params.Arguments),
			Verdict:       string(result.Verdict),
			RiskScore:     riskScore,
			RiskLevel:     riskLevel,
			AgentID:       agentID,
			AgentName:     agentName,
		}

		// Add enrichment data from remote scorer
		if hasScore && score.RemoteEnrichment != nil {
			enrichment := score.RemoteEnrichment
			logOpts.ComplianceRefs = enrichment.ComplianceRefs
			logOpts.BehavioralFlags = enrichment.BehavioralFlags
			logOpts.ScoreDecomposition = enrichment.ScoreDecomposition
			logOpts.GNNScore = enrichment.GNNScore
			logOpts.Confidence = enrichment.Confidence
			logOpts.Mitigations = enrichment.Mitigations
			logOpts.ScoringSource = enrichment.ScoringSource
			logOpts.CloudEventID = enrichment.EventID
			if logOpts.ScoringSource == "" {
				logOpts.ScoringSource = "remote"
			}
			logOpts.LocalScore = &score.BaseScore
			logOpts.RemoteScore = riskScore
		} else if riskScore != nil {
			logOpts.ScoringSource = "local"
			logOpts.LocalScore = riskScore
		}

		g.logger.Log(logOpts)
	}

	if result.Verdict == intercept.VerdictDeny {
		qlog.Info("denied %s.%s by policy", backendName, toolName)
		return g.jsonRpcError(id, -32600, fmt.Sprintf("Quint: tool %s.%s denied by policy", backendName, toolName))
	}

	// Scope enforcement
	if g.identity != nil && g.identity.IsAgent {
		if scope, ok := auth.EnforceScope(g.identity, toolName); !ok {
			qlog.Info("scope-denied %s.%s (requires %s)", backendName, toolName, scope)
			return g.jsonRpcError(id, -32600, fmt.Sprintf("Quint: insufficient scope for %s.%s (requires %s)", backendName, toolName, scope))
		}
	}

	// --- Forward to backend ---
	resp, err := backend.Call(id, toolName, params.Arguments)
	if err != nil {
		qlog.Error("backend %s call failed: %v", backendName, err)
		return g.jsonRpcError(id, -32603, fmt.Sprintf("Backend error: %v", err))
	}

	// Rewrite the response ID to match the original request ID
	var respObj map[string]json.RawMessage
	if err := json.Unmarshal(resp, &respObj); err == nil {
		respObj["id"] = id
		rewritten, _ := json.Marshal(respObj)

		// Audit response
		if g.logger != nil {
			method, msgID, respJSON := intercept.InspectResponse(string(rewritten))
			agentID, agentName := "", ""
			if g.identity != nil {
				agentID = g.identity.AgentID
				agentName = g.identity.AgentName
			}
			g.logger.Log(audit.LogOpts{
				ServerName:   backendName,
				Direction:    "response",
				Method:       method,
				MessageID:    msgID,
				ResponseJSON: respJSON,
				Verdict:      "passthrough",
				AgentID:      agentID,
				AgentName:    agentName,
			})
		}

		return string(rewritten)
	}

	return string(resp)
}

func (g *Gateway) jsonRpcError(id json.RawMessage, code int, message string) string {
	idPart := "null"
	if id != nil && len(id) > 0 {
		idPart = string(id)
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"%s"}}`, idPart, code, escapeJSON(message))
}

func splitNamespacedTool(name string) (backend, tool string) {
	idx := strings.IndexByte(name, '.')
	if idx < 0 {
		return "", name
	}
	return name[:idx], name[idx+1:]
}

func escapeJSON(s string) string {
	// Use json.Marshal to properly escape all special characters
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	// Strip the surrounding quotes that Marshal adds
	return string(b[1 : len(b)-1])
}
