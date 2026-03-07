package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/relay"
	"github.com/Quint-Security/quint-proxy/internal/stream"
)

var version = "dev"

// riskResult holds risk scoring output.
type riskResult struct {
	score              int
	level              string
	scoringSource      string
	localScore         int
	complianceRefs     []string
	behavioralFlags    []string
	scoreDecomposition map[string]any
	gnnScore           *float64
	confidence         *float64
	mitigations        []string
	cloudEventID       string
}

// Function type aliases used across phases.
type logEntryFunc func(serverName, direction, method, messageID, toolName, argsJSON, respJSON string, verdict string, riskScore *int, riskLevel *string, enrichment *riskResult)
type scoreFunc func(toolName, argsJSON, subjectID, serverName string) *riskResult
type evalFunc func(score int) string
type revokeFunc func(subjectID string) bool

func main() {
	// Check for subcommands before flag parsing
	if len(os.Args) > 1 {
		switch os.Args[1] {
		// Primary commands — the ones a new user sees
		case "setup":
			runSetup(os.Args[2:])
			return
		case "start":
			runStart(os.Args[2:])
			return
		case "status":
			runStatus(os.Args[2:])
			return
		case "watch":
			runWatch(os.Args[2:])
			return
		case "export":
			runExport(os.Args[2:])
			return
		case "shell":
			runShell(os.Args[2:])
			return

		// Admin — advanced commands behind a subcommand
		case "admin":
			runAdmin(os.Args[2:])
			return

		// Version
		case "--version", "version":
			fmt.Println(version)
			return

		// Backward compat: advanced commands still work without "admin" prefix
		case "init":
			runInit(os.Args[2:])
			return
		case "connect":
			runConnectShorthand(os.Args[2:])
			return
		case "agent":
			runAgent(os.Args[2:])
			return
		case "verify":
			runVerify(os.Args[2:])
			return
		case "approve":
			runApprove(os.Args[2:])
			return
		case "deny":
			runDeny(os.Args[2:])
			return
		case "approvals":
			runApprovals(os.Args[2:])
			return
		case "sync":
			runSync(os.Args[2:])
			return
		case "http-proxy":
			runHTTPProxy(os.Args[2:])
			return
		}
	}

	// No args: show status if configured, or setup prompt
	if len(os.Args) == 1 {
		home, _ := os.UserHomeDir()
		quintDir := filepath.Join(home, ".quint")
		if _, err := os.Stat(quintDir); err == nil {
			runStatus(nil)
		} else {
			fmt.Println("Quint — Security gateway for AI agents")
			fmt.Println()
			fmt.Println("Run `quint setup` to get started.")
		}
		return
	}

	// Default: stdio proxy mode (with --name flag)
	serverName := flag.String("name", "", "MCP server name (used in audit log)")
	policyPath := flag.String("policy", "", "Path to policy.json or directory containing it")
	agentName := flag.String("agent", "", "Agent name for identity resolution (or set QUINT_AGENT)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Quint — Security gateway for AI agents\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  quint setup              Interactive setup wizard\n")
		fmt.Fprintf(os.Stderr, "  quint start              Run the gateway\n")
		fmt.Fprintf(os.Stderr, "  quint status             Health check\n")
		fmt.Fprintf(os.Stderr, "  quint watch              HTTP/HTTPS forward proxy + API server\n")
		fmt.Fprintf(os.Stderr, "    --port <port>          Proxy port (default 9090)\n")
		fmt.Fprintf(os.Stderr, "    --api-port <port>      API server port (default 8080)\n")
		fmt.Fprintf(os.Stderr, "  quint export             Export audit proof bundle\n\n")
		fmt.Fprintf(os.Stderr, "Advanced:\n")
		fmt.Fprintf(os.Stderr, "  quint admin <command>    Run an advanced command (quint admin --help)\n\n")
		fmt.Fprintf(os.Stderr, "Stdio proxy mode:\n")
		fmt.Fprintf(os.Stderr, "  quint --name <server> -- <command> [args...]\n\n")
		fmt.Fprintf(os.Stderr, "https://github.com/Quint-Security/proxy\n")
	}
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// Everything after -- is the child command
	childArgs := flag.Args()
	if len(childArgs) == 0 || *serverName == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Load policy
	policy, err := intercept.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint: failed to load policy: %v\n", err)
		os.Exit(1)
	}

	qlog.SetLevel(policy.LogLevel)
	dataDir := intercept.ResolveDataDir(policy.DataDir)
	qlog.Info("starting proxy for %q (data_dir=%s)", *serverName, dataDir)

	// Resolve agent identity for stdio mode
	resolvedAgent := *agentName
	if resolvedAgent == "" {
		resolvedAgent = os.Getenv("QUINT_AGENT")
	}

	var agentIdentity *auth.Identity
	if resolvedAgent != "" {
		authDB, err := auth.OpenDB(dataDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quint: --agent requires auth database: %v\n", err)
			os.Exit(1)
		}
		identity, err := authDB.ResolveAgentByName(resolvedAgent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quint: %v\n", err)
			os.Exit(1)
		}
		agentIdentity = identity
		cleanupFuncs = append(cleanupFuncs, func() { authDB.Close() })
		qlog.Info("running as agent %q (%s, scopes=%v)", identity.AgentName, identity.AgentID, identity.Scopes)
	}

	// Check QUINT_TOKEN for cloud JWT tokens (takes precedence over --agent)
	if token := os.Getenv("QUINT_TOKEN"); token != "" && auth.IsCloudToken(token) {
		if policy.AuthService != nil && policy.AuthService.Enabled {
			cloudValidator := auth.NewCloudValidator(&auth.CloudValidatorConfig{
				BaseURL:    policy.AuthService.BaseURL,
				CustomerID: policy.AuthService.CustomerID,
				TimeoutMs:  policy.AuthService.TimeoutMs,
			})
			resolver := auth.NewTokenResolver(nil, cloudValidator, nil)
			cloudIdentity, tokenErr := resolver.ResolveToken(token)
			if tokenErr != nil {
				fmt.Fprintf(os.Stderr, "quint: cloud token invalid: %v\n", tokenErr)
				os.Exit(1)
			}
			if cloudIdentity != nil {
				agentIdentity = cloudIdentity
				qlog.Info("relay mode: authenticated via cloud token (type=%s, agent_id=%s)", cloudIdentity.TokenType, cloudIdentity.AgentID)
			}
		} else {
			qlog.Warn("QUINT_TOKEN set but auth_service not enabled in policy")
		}
	}

	// Initialize with stubs — phases replace these
	var logEntry logEntryFunc = func(_, _, _, _, _, _, _ string, _ string, _ *int, _ *string, _ *riskResult) {}
	var scoreTool scoreFunc = func(_, _, _, _ string) *riskResult { return nil }
	var evalRisk evalFunc = func(_ int) string { return "allow" }
	var revoke revokeFunc = func(_ string) bool { return false }

	// Phase 2: Wire crypto + audit
	initAudit(dataDir, policy, &logEntry, agentIdentity)

	// Phase 3: Wire risk engine
	initRisk(dataDir, policy, &scoreTool, &evalRisk, &revoke, agentIdentity)

	// Build relay callbacks
	sn := *serverName
	callbacks := relay.Callbacks{
		OnParentMessage: func(line string) string {
			return handleParentMessage(line, sn, policy, logEntry, scoreTool, evalRisk, revoke, agentIdentity)
		},
		OnChildMessage: func(line string) string {
			return handleChildMessage(line, sn, logEntry, agentIdentity)
		},
	}

	r := relay.New(childArgs[0], childArgs[1:], callbacks)

	// Signal handling with audit logging
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		qlog.Info("received signal %v, shutting down gracefully", sig)

		// Log shutdown event to audit database before stopping
		riskScore := 0
		riskLevel := "info"
		logEntry(*serverName, "proxy", "shutdown", "", "",
			fmt.Sprintf(`{"signal":"%s","reason":"graceful_shutdown"}`, sig.String()),
			"", "shutdown", &riskScore, &riskLevel, nil)

		r.Stop()
	}()

	code := r.Start()
	qlog.Info("child exited with code %d", code)

	// Log normal exit to audit database
	riskScore := 0
	riskLevel := "info"
	logEntry(*serverName, "proxy", "exit", "", "",
		fmt.Sprintf(`{"exit_code":%d,"reason":"normal_exit"}`, code),
		"", "exit", &riskScore, &riskLevel, nil)

	cleanup()
	os.Exit(code)
}

// handleParentMessage processes a message from the AI agent heading to the MCP server.
func handleParentMessage(
	line string,
	serverName string,
	policy intercept.PolicyConfig,
	logEntry logEntryFunc,
	scoreTool scoreFunc,
	evalRisk evalFunc,
	revoke revokeFunc,
	identity *auth.Identity,
) (out string) {
	// On panic: forward (fail-open) or drop (fail-closed) depending on policy
	failMode := policy.GetFailMode()
	defer func() {
		if r := recover(); r != nil {
			if failMode == "open" {
				qlog.Error("panic in parent message handler, forwarding (fail_mode=open): %v", r)
				out = line
			} else {
				qlog.Error("panic in parent message handler, dropping (fail_mode=closed): %v", r)
				out = ""
			}
		}
	}()

	result := intercept.InspectRequest(line, serverName, policy)

	subjectID := "anonymous"
	if identity != nil {
		subjectID = identity.SubjectID
	}

	if result.ToolName == "" || result.Verdict == intercept.VerdictDeny {
		logEntry(serverName, "request", result.Method, result.MessageID, result.ToolName, result.ArgumentsJson, "", string(result.Verdict), nil, nil, nil)

		if result.Verdict == intercept.VerdictDeny {
			denyResp := intercept.BuildDenyResponse(result.RawID)
			qlog.Info("denied %s on %s", result.ToolName, serverName)
			logEntry(serverName, "response", result.Method, result.MessageID, result.ToolName, "", denyResp, string(intercept.VerdictDeny), nil, nil, nil)
			os.Stdout.WriteString(denyResp + "\n")
			return ""
		}

		qlog.Debug("forwarding %s (%s) to child", result.Method, result.Verdict)
		return line
	}

	// Scope enforcement (agents only, after policy check)
	if requiredScope, ok := auth.EnforceScope(identity, result.ToolName); !ok {
		denyResp := intercept.BuildScopeDenyResponse(result.RawID, result.ToolName, requiredScope)
		qlog.Info("scope-denied %s for agent %s (requires %s)", result.ToolName, identity.AgentName, requiredScope)
		logEntry(serverName, "request", result.Method, result.MessageID, result.ToolName, result.ArgumentsJson, "", "scope_denied", nil, nil, nil)
		logEntry(serverName, "response", result.Method, result.MessageID, result.ToolName, "", denyResp, "scope_denied", nil, nil, nil)
		os.Stdout.WriteString(denyResp + "\n")
		return ""
	}

	// Cloud RBAC evaluation (additive — runs alongside scope enforcement)
	if identity != nil && identity.IsCloudToken && identity.RBAC != nil {
		action := intercept.ClassifyAction(serverName, result.ToolName, "tools/call")
		decision := auth.EvaluateRBAC(identity.RBAC, action, "", 0)
		if !decision.Allowed {
			denyResp := intercept.BuildDenyResponse(result.RawID)
			qlog.Info("rbac-denied %s: %s (step=%d/%s)", result.ToolName, decision.Reason, decision.Step, decision.StepName)
			logEntry(serverName, "request", result.Method, result.MessageID, result.ToolName, result.ArgumentsJson, "", "rbac_denied", nil, nil, nil)
			logEntry(serverName, "response", result.Method, result.MessageID, result.ToolName, "", denyResp, "rbac_denied", nil, nil, nil)
			os.Stdout.WriteString(denyResp + "\n")
			return ""
		}
	}

	// Classify action and track in session
	action := intercept.ClassifyAction(serverName, result.ToolName, "tools/call")
	if sessionTracker != nil {
		sessionTracker.Record(subjectID, action)
	}

	// Spawn detection
	var spawnJSON string
	if spawnDetector != nil {
		spawnEvent := spawnDetector.DetectSpawn(serverName, result.ToolName, result.ArgumentsJson, subjectID)
		if spawnEvent != nil {
			qlog.Info("spawn detected: pattern=%s parent=%s child=%s confidence=%.2f",
				spawnEvent.PatternID, spawnEvent.ParentAgent, spawnEvent.ChildHint, spawnEvent.Confidence)

			if correlationEngine != nil {
				rel := correlationEngine.AddSpawnEvent(spawnEvent)
				if rel != nil {
					qlog.Info("relationship: %s→%s (confidence=%.2f, depth=%d)",
						rel.ParentAgent, rel.ChildAgent, rel.Confidence, rel.Depth)

					// Publish to Kafka
					if kafkaProducer != nil {
						kafkaProducer.PublishRelationship(rel.ParentAgent, stream.RelationshipMessage{
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
			if kafkaProducer != nil {
				kafkaProducer.PublishSpawn(subjectID, stream.SpawnEventMessage{
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

			// Issue spawn ticket and inject into forwarded JSON-RPC line
			if ticketSigner != nil {
				parentID := subjectID
				if identity != nil && identity.AgentID != "" {
					parentID = identity.AgentID
				}
				parentName := ""
				if identity != nil {
					parentName = identity.AgentName
				}
				depth := 1
				if correlationEngine != nil {
					depth = correlationEngine.GetDepth(subjectID) + 1
				}
				ticket, ticketErr := ticketSigner.Issue(intercept.SpawnTicketClaims{
					ParentAgentID:   parentID,
					ParentAgentName: parentName,
					ChildHint:       spawnEvent.ChildHint,
					Depth:           depth,
					SpawnType:       spawnEvent.SpawnType,
				})
				if ticketErr != nil {
					qlog.Warn("failed to issue spawn ticket: %v", ticketErr)
				} else {
					// Rewrite the JSON-RPC line with the injected ticket
					var rpcMsg map[string]json.RawMessage
					if err := json.Unmarshal([]byte(line), &rpcMsg); err == nil {
						var rpcParams map[string]json.RawMessage
						if err := json.Unmarshal(rpcMsg["params"], &rpcParams); err == nil {
							rpcParams["arguments"] = intercept.InjectSpawnTicket(rpcParams["arguments"], ticket)
							if newParams, err := json.Marshal(rpcParams); err == nil {
								rpcMsg["params"] = newParams
								if newLine, err := json.Marshal(rpcMsg); err == nil {
									line = string(newLine)
									qlog.Info("injected spawn ticket for child %s (depth=%d)", spawnEvent.ChildHint, depth)
								}
							}
						}
					}
				}
			}

			if b, err := json.Marshal(spawnEvent); err == nil {
				spawnJSON = string(b)
			}
		}
	}

	// Tool call — score risk
	riskRes := scoreTool(result.ToolName, result.ArgumentsJson, subjectID, serverName)
	var riskScore *int
	var riskLevel *string
	if riskRes != nil {
		riskScore = &riskRes.score
		riskLevel = &riskRes.level
	}

	// Publish event to Kafka (non-blocking)
	if kafkaProducer != nil {
		riskScoreVal := 0
		riskLevelVal := "low"
		if riskScore != nil {
			riskScoreVal = *riskScore
		}
		if riskLevel != nil {
			riskLevelVal = *riskLevel
		}
		var behavioralFlags []string
		if riskRes != nil {
			behavioralFlags = riskRes.behavioralFlags
		}
		agentID := subjectID
		if identity != nil {
			agentID = identity.AgentID
		}
		kafkaProducer.PublishEvent(subjectID, stream.AgentEventMessage{
			EventID:         fmt.Sprintf("%s:%s:%d", serverName, result.ToolName, time.Now().UnixMilli()),
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			AgentID:         agentID,
			SessionID:       subjectID,
			ServerName:      serverName,
			ToolName:        result.ToolName,
			Action:          action,
			RiskScore:       riskScoreVal,
			RiskLevel:       riskLevelVal,
			Verdict:         string(result.Verdict),
			Transport:       "stdio",
			BehavioralFlags: behavioralFlags,
		})
	}

	_ = spawnJSON // available for audit enrichment via logEntry
	logEntry(serverName, "request", result.Method, result.MessageID, result.ToolName, result.ArgumentsJson, "", string(result.Verdict), riskScore, riskLevel, riskRes)

	if riskRes != nil {
		riskAction := evalRisk(riskRes.score)
		if riskAction == "deny" {
			denyResp := intercept.BuildDenyResponse(result.RawID)
			qlog.Warn("risk-denied %s (score=%d, level=%s)", result.ToolName, riskRes.score, riskRes.level)
			logEntry(serverName, "response", result.Method, result.MessageID, result.ToolName, "", denyResp, string(intercept.VerdictDeny), riskScore, riskLevel, riskRes)
			os.Stdout.WriteString(denyResp + "\n")
			return ""
		}
		if riskAction == "flag" {
			// In stdio mode, flagged calls use fail_mode (no approval hold)
			qlog.Warn("high-risk %s (score=%d, level=%s)", result.ToolName, riskRes.score, riskRes.level)
			if failMode == "closed" {
				denyResp := intercept.BuildDenyResponse(result.RawID)
				qlog.Warn("flag-denied %s in stdio mode (fail_mode=closed)", result.ToolName)
				logEntry(serverName, "response", result.Method, result.MessageID, result.ToolName, "", denyResp, "flag_denied", riskScore, riskLevel, riskRes)
				os.Stdout.WriteString(denyResp + "\n")
				return ""
			}
		}
	}

	if revoke(subjectID) {
		qlog.Warn("repeated high-risk actions detected - consider revoking agent credentials for %s", subjectID)
	}

	if riskRes != nil {
		qlog.Debug("forwarding %s (risk=%d) to child", result.Method, riskRes.score)
	} else {
		qlog.Debug("forwarding %s to child", result.Method)
	}
	return line
}

// handleChildMessage processes a response from the MCP server heading to the AI agent.
func handleChildMessage(line string, serverName string, logEntry logEntryFunc, _ *auth.Identity) string {
	defer func() {
		if r := recover(); r != nil {
			qlog.Error("panic in child message handler: %v", r)
		}
	}()

	method, msgID, respJSON := intercept.InspectResponse(line)
	logEntry(serverName, "response", method, msgID, "", "", respJSON, string(intercept.VerdictPassthrough), nil, nil, nil)
	return line
}

// cleanup closes databases. Populated by initAudit/initRisk.
var cleanupFuncs []func()

func cleanup() {
	for _, f := range cleanupFuncs {
		func() {
			defer func() { recover() }()
			f()
		}()
	}
}
