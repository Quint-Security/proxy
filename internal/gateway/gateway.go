package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/credential"
	"github.com/Quint-Security/quint-proxy/internal/forwardproxy"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
	"github.com/Quint-Security/quint-proxy/internal/stream"
)

// Gateway is the MCP multiplexer. It presents as a single MCP server to the
// agent, routing tool calls to the appropriate downstream backend.
type Gateway struct {
	backends          map[string]Backend
	toolIndex         map[string]string // namespacedTool → backendName
	allTools          []Tool            // merged tool list with namespaced names
	policy            intercept.PolicyConfig
	logger            *audit.Logger
	riskEngine        *risk.Engine
	identity          *auth.Identity
	sessionTracker    *risk.SessionTracker
	spawnDetector     *intercept.SpawnDetector
	correlationEngine *intercept.CorrelationEngine
	kafkaProducer     *stream.Producer
	tokenResolver     *auth.TokenResolver
	cloudClient       *auth.AuthServiceClient
	authDB            *auth.DB
	ticketSigner      *intercept.SpawnTicketSigner
}

// New creates a gateway from the given config.
func New(cfg *Config, opts GatewayOpts) (*Gateway, error) {
	ticketSigner, err := intercept.NewSpawnTicketSigner(0)
	if err != nil {
		qlog.Warn("failed to initialize spawn ticket signer: %v", err)
	}

	g := &Gateway{
		backends:          make(map[string]Backend),
		toolIndex:         make(map[string]string),
		policy:            opts.Policy,
		logger:            opts.Logger,
		riskEngine:        opts.RiskEngine,
		identity:          opts.Identity,
		sessionTracker:    risk.NewSessionTracker(20, 0),
		spawnDetector:     intercept.NewSpawnDetector(nil),
		correlationEngine: intercept.NewCorrelationEngine(),
		kafkaProducer:     opts.KafkaProducer,
		tokenResolver:     opts.TokenResolver,
		cloudClient:       opts.CloudClient,
		authDB:            opts.AuthDB,
		ticketSigner:      ticketSigner,
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
	Policy        intercept.PolicyConfig
	Logger        *audit.Logger
	RiskEngine    *risk.Engine
	Identity      *auth.Identity
	CredStore     *credential.Store
	KafkaProducer *stream.Producer
	TokenResolver *auth.TokenResolver
	CloudClient   *auth.AuthServiceClient
	AuthDB        *auth.DB
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

// Stop shuts down all backends and the Kafka producer.
func (g *Gateway) Stop() {
	for _, b := range g.backends {
		b.Stop()
	}
	if g.kafkaProducer != nil {
		g.kafkaProducer.Close()
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

func (g *Gateway) handleMessage(line string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			failMode := g.policy.GetFailMode()
			qlog.Error("panic in gateway message handler (fail_mode=%s): %v", failMode, r)
			if failMode == "open" {
				out = line // forward raw
			} else {
				out = ""
			}
		}
	}()

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
		return g.handleInitialize(idRaw, msg["params"])
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

func (g *Gateway) handleInitialize(id json.RawMessage, paramsRaw json.RawMessage) string {
	// Parse clientInfo from initialize params
	var initParams struct {
		ClientInfo *struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	}
	if paramsRaw != nil {
		json.Unmarshal(paramsRaw, &initParams)
	}

	// Resolve session identity (overrides startup fallback if successful)
	if resolved := g.resolveSessionIdentity(paramsRaw, initParams.ClientInfo); resolved != nil {
		g.identity = resolved
		qlog.Info("session identity: agent=%q (source=%s)", resolved.AgentName, resolved.Source)
	} else if initParams.ClientInfo != nil {
		qlog.Info("client connected: %s (no identity resolved, using fallback)", initParams.ClientInfo.Name)
	}

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

// resolveSessionIdentity resolves identity from initialize params in priority order:
// 1. _quint in-band auth (api_key or token)
// 2. clientInfo.name → registered agent lookup
// 3. Auto-registration (if enabled in policy)
// Returns nil to keep the startup fallback identity.
func (g *Gateway) resolveSessionIdentity(paramsRaw json.RawMessage, clientInfo *struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}) *auth.Identity {
	// 0. Spawn ticket (highest priority — HMAC-verified, confidence 1.0)
	if quintAuth := intercept.ExtractQuintAuth(paramsRaw); quintAuth != nil && quintAuth.SpawnTicket != "" && g.ticketSigner != nil {
		claims, err := g.ticketSigner.Validate(quintAuth.SpawnTicket)
		if err != nil {
			qlog.Warn("spawn ticket validation failed: %v", err)
		} else {
			qlog.Info("spawn ticket validated: parent=%s child=%s depth=%d", claims.ParentAgentID, claims.ChildHint, claims.Depth)

			// Record deterministic relationship in correlation engine
			childName := claims.ChildHint
			if clientInfo != nil && clientInfo.Name != "" {
				childName = clientInfo.Name
			}
			if g.correlationEngine != nil {
				rel := g.correlationEngine.AddSignatureSignal(
					claims.ParentAgentID, childName, claims.TraceID, claims.Depth, claims.SpawnType)
				if rel != nil && g.logger != nil {
					g.logger.RecordRelationship(rel.ParentAgent, rel.ChildAgent, rel.Confidence, rel.Depth, rel.SpawnType, "signature")
				}
			}

			// Register or find the subagent
			if g.authDB != nil && childName != "" {
				scopes := claims.Scopes
				if scopes == "" {
					scopes = "tools:read"
				}
				id, _, regErr := g.authDB.FindOrCreateSubagent(childName, claims.ParentAgentID, scopes, claims.Depth)
				if regErr != nil {
					qlog.Warn("failed to register spawn-ticket agent %s: %v", childName, regErr)
				} else if id != nil {
					id.Source = "spawn_ticket"
					id.Depth = claims.Depth
					id.ParentJTI = claims.ParentAgentID
					return id
				}
			}

			// Even without auth DB, return a minimal identity
			return &auth.Identity{
				SubjectID: childName,
				AgentName: childName,
				AgentType: auth.InferAgentType(childName),
				IsAgent:   true,
				Depth:     claims.Depth,
				ParentJTI: claims.ParentAgentID,
				Source:    "spawn_ticket",
			}
		}
	}

	// 1. _quint auth (api_key or token)
	if quintAuth := intercept.ExtractQuintAuth(paramsRaw); quintAuth != nil {
		if quintAuth.APIKey != "" && g.authDB != nil {
			if id, _ := g.authDB.ResolveIdentity(quintAuth.APIKey); id != nil {
				id.Source = "quint_auth"
				return id
			}
		}
		if quintAuth.Token != "" && g.tokenResolver != nil {
			if id, _ := g.tokenResolver.ResolveToken(quintAuth.Token); id != nil {
				id.Source = "quint_auth"
				return id
			}
		}
	}

	// 2. clientInfo.name → registered agent
	if clientInfo != nil && clientInfo.Name != "" && g.authDB != nil {
		if id, err := g.authDB.ResolveAgentByName(clientInfo.Name); err == nil {
			id.Source = "client_info"
			return id
		}

		// 3. Auto-register if enabled
		if g.policy.AutoRegisterAgents {
			scopes := g.policy.DefaultAgentScopes
			if scopes == "" {
				scopes = "tools:read"
			} else {
				scopes = auth.NormalizeScopeString(scopes)
			}
			if id, _, err := g.authDB.FindOrCreateAgent(clientInfo.Name, auth.InferAgentType(clientInfo.Name), scopes); err == nil {
				id.Source = "auto_register"
				qlog.Info("auto-registered agent %q (scopes=%s)", clientInfo.Name, scopes)
				return id
			}
		}
	}

	return nil
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
	var spawnEvent *intercept.SpawnEvent
	var spawnJSON string

	subjectID := "gateway:" + backendName
	if g.identity != nil {
		subjectID = g.identity.SubjectID
	}

	// Classify action to canonical format
	action := intercept.ClassifyAction(backendName, toolName, "tools/call")

	// Record in session tracker and get preceding actions
	g.sessionTracker.Record(subjectID, action)
	preceding := g.sessionTracker.Recent(subjectID)

	// Spawn detection
	if g.spawnDetector != nil {
		spawnEvent = g.spawnDetector.DetectSpawn(backendName, toolName, string(params.Arguments), subjectID)
		if spawnEvent != nil {
			qlog.Info("spawn detected: pattern=%s parent=%s child=%s confidence=%.2f",
				spawnEvent.PatternID, spawnEvent.ParentAgent, spawnEvent.ChildHint, spawnEvent.Confidence)

			// Record in correlation engine
			if g.correlationEngine != nil {
				rel := g.correlationEngine.AddSpawnEvent(spawnEvent)
				if rel != nil {
					qlog.Info("relationship updated: %s→%s (confidence=%.2f, depth=%d)",
						rel.ParentAgent, rel.ChildAgent, rel.Confidence, rel.Depth)

					// Persist to audit DB
					if g.logger != nil {
						g.logger.RecordRelationship(rel.ParentAgent, rel.ChildAgent, rel.Confidence, rel.Depth, rel.SpawnType, "spawn")
					}

					// Publish to Kafka
					if g.kafkaProducer != nil {
						g.kafkaProducer.PublishRelationship(rel.ParentAgent, stream.RelationshipMessage{
							Timestamp:   time.Now().UTC().Format(time.RFC3339),
							ParentAgent: rel.ParentAgent,
							ChildAgent:  rel.ChildAgent,
							Confidence:  rel.Confidence,
							Depth:       rel.Depth,
							SpawnType:   rel.SpawnType,
							SignalType:  "spawn",
							SignalCount: rel.SignalCount,
						})
					}
				}
			}

			// Publish spawn event to Kafka
			if g.kafkaProducer != nil {
				g.kafkaProducer.PublishSpawn(subjectID, stream.SpawnEventMessage{
					EventID:      fmt.Sprintf("spawn:%s:%d", spawnEvent.PatternID, time.Now().UnixMilli()),
					Timestamp:    spawnEvent.DetectedAt.Format(time.RFC3339),
					PatternID:    spawnEvent.PatternID,
					ParentAgent:  spawnEvent.ParentAgent,
					ChildHint:    spawnEvent.ChildHint,
					SpawnType:    spawnEvent.SpawnType,
					Confidence:   spawnEvent.Confidence,
					ToolName:     spawnEvent.ToolName,
					ServerName:   spawnEvent.ServerName,
					ArgumentsRef: spawnEvent.ArgumentsRef,
				})
			}

			// Request subagent token on spawn if cloud auth is active
			if g.cloudClient != nil && g.identity != nil && g.identity.IsCloudToken && g.identity.RBAC != nil {
				narrowed := auth.NarrowRBAC(g.identity.RBAC, g.identity.RBAC)
				_, subClaims, err := g.cloudClient.RequestSubagentToken(
					g.identity.JTI, spawnEvent.ChildHint, narrowed)
				if err != nil {
					qlog.Warn("failed to request subagent token for %s: %v", spawnEvent.ChildHint, err)
				} else if subClaims != nil {
					qlog.Info("issued subagent token for child %s (depth=%d)", spawnEvent.ChildHint, subClaims.Depth)
				}
			}

			// Auto-register spawned child agent in auth DB
			if spawnEvent.ChildHint != "" && g.authDB != nil {
				parentScopes := "tools:read"
				if g.identity != nil && len(g.identity.Scopes) > 0 {
					parentScopes = strings.Join(auth.NormalizeScopes(g.identity.Scopes), ",")
				}
				parentID := ""
				if g.identity != nil {
					parentID = g.identity.AgentID
				}
				depth := 1
				if g.correlationEngine != nil {
					depth = g.correlationEngine.GetDepth(subjectID) + 1
				}
				_, created, regErr := g.authDB.FindOrCreateSubagent(
					spawnEvent.ChildHint, parentID, parentScopes, depth)
				if regErr != nil {
					qlog.Warn("failed to register spawned agent %s: %v", spawnEvent.ChildHint, regErr)
				} else if created {
					qlog.Info("registered spawned agent %q (parent=%s, depth=%d)", spawnEvent.ChildHint, parentID, depth)
				}
			}

			// Issue spawn ticket and inject into forwarded arguments
			if g.ticketSigner != nil {
				parentID := subjectID
				if g.identity != nil && g.identity.AgentID != "" {
					parentID = g.identity.AgentID
				}
				parentName := ""
				if g.identity != nil {
					parentName = g.identity.AgentName
				}
				scopes := "tools:read"
				if g.identity != nil && len(g.identity.Scopes) > 0 {
					scopes = strings.Join(auth.NormalizeScopes(g.identity.Scopes), ",")
				}
				depth := 1
				if g.correlationEngine != nil {
					depth = g.correlationEngine.GetDepth(subjectID) + 1
				}
				// Use derived naming for spawn ticket child hint
				childHint := forwardproxy.DeriveChildName(parentName, parentID, depth)
				ticket, ticketErr := g.ticketSigner.Issue(intercept.SpawnTicketClaims{
					ParentAgentID:   parentID,
					ParentAgentName: parentName,
					ChildHint:       childHint,
					Depth:           depth,
					Scopes:          scopes,
					SpawnType:       spawnEvent.SpawnType,
				})
				if ticketErr != nil {
					qlog.Warn("failed to issue spawn ticket: %v", ticketErr)
				} else {
					params.Arguments = intercept.InjectSpawnTicket(params.Arguments, ticket)
					qlog.Info("injected spawn ticket for child %s (depth=%d)", childHint, depth)
				}
			}

			// Serialize for audit log
			if b, err := json.Marshal(spawnEvent); err == nil {
				spawnJSON = string(b)
			}
		}
	}

	// Build enriched event context
	eventCtx := &risk.EventContext{
		ServerName:       backendName,
		Transport:        "http",
		IsVerified:       true,
		ToolName:         toolName,
		PrecedingActions: preceding,
		CanonicalAction:  action,
		SpawnDetected:    spawnEvent != nil,
	}
	if g.identity != nil {
		eventCtx.AgentID = g.identity.AgentID
		eventCtx.AgentName = g.identity.AgentName
		eventCtx.AgentType = g.identity.AgentType
		eventCtx.SessionID = g.identity.SubjectID
	}

	// Agent depth from correlation engine
	if g.correlationEngine != nil {
		eventCtx.Depth = g.correlationEngine.GetDepth(subjectID)
		if parent := g.correlationEngine.GetParent(subjectID); parent != nil {
			eventCtx.ParentAgentID = parent.ParentAgent
		}
	}

	if g.riskEngine != nil {
		// Use context-aware scoring (includes depth penalty and burst detection)
		score = g.riskEngine.ScoreWithContext(toolName, string(params.Arguments), subjectID, eventCtx, g.sessionTracker)
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
			TraceID:       eventCtx.TraceID,
			AgentDepth:    &eventCtx.Depth,
			ParentAgentID: eventCtx.ParentAgentID,
			SpawnDetected: spawnJSON,
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

	// Publish event to Kafka (non-blocking)
	if g.kafkaProducer != nil {
		agentID, agentName := "", ""
		if g.identity != nil {
			agentID = g.identity.AgentID
			agentName = g.identity.AgentName
		}
		riskScoreVal := 0
		riskLevelVal := "low"
		if riskScore != nil {
			riskScoreVal = *riskScore
		}
		if riskLevel != nil {
			riskLevelVal = *riskLevel
		}
		var behavioralFlags []string
		if hasScore && score.RemoteEnrichment != nil {
			behavioralFlags = score.RemoteEnrichment.BehavioralFlags
		}
		g.kafkaProducer.PublishEvent(subjectID, stream.AgentEventMessage{
			EventID:         fmt.Sprintf("%s:%s:%d", backendName, toolName, time.Now().UnixMilli()),
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			AgentID:         agentID,
			AgentName:       agentName,
			SessionID:       eventCtx.SessionID,
			ServerName:      backendName,
			ToolName:        toolName,
			Action:          action,
			RiskScore:       riskScoreVal,
			RiskLevel:       riskLevelVal,
			Verdict:         string(result.Verdict),
			TraceID:         eventCtx.TraceID,
			Depth:           eventCtx.Depth,
			ParentAgentID:   eventCtx.ParentAgentID,
			Transport:       "http",
			BehavioralFlags: behavioralFlags,
		})
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

	// Cloud RBAC evaluation (additive — runs alongside scope enforcement)
	if g.identity != nil && g.identity.IsCloudToken && g.identity.RBAC != nil {
		decision := auth.EvaluateRBAC(g.identity.RBAC, action, "", 0)
		if !decision.Allowed {
			qlog.Info("rbac-denied %s.%s: %s (step=%d/%s)", backendName, toolName, decision.Reason, decision.Step, decision.StepName)
			return g.jsonRpcError(id, -32600, fmt.Sprintf("Quint: %s.%s denied by RBAC policy (%s)", backendName, toolName, decision.StepName))
		}
	}

	// Max risk score enforcement from RBAC policy
	if g.identity != nil && g.identity.MaxRiskScore > 0 && hasScore && score.Value > g.identity.MaxRiskScore {
		qlog.Warn("rbac-risk-denied %s.%s (score=%d exceeds max=%d)", backendName, toolName, score.Value, g.identity.MaxRiskScore)
		return g.jsonRpcError(id, -32600, fmt.Sprintf("Quint: %s.%s risk score %d exceeds token limit %d", backendName, toolName, score.Value, g.identity.MaxRiskScore))
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
	// Fast path: check if escaping is needed at all
	needsEscape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' || c < 0x20 {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return s
	}

	// Use json.Marshal for strings that actually need escaping
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	return string(b[1 : len(b)-1])
}
