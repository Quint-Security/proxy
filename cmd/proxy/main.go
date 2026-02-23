package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/relay"
)

var version = "dev"

// riskResult holds risk scoring output.
type riskResult struct {
	score int
	level string
}

// Function type aliases used across phases.
type logEntryFunc func(serverName, direction, method, messageID, toolName, argsJSON, respJSON string, verdict intercept.Verdict, riskScore *int, riskLevel *string)
type scoreFunc func(toolName, argsJSON, subjectID string) *riskResult
type evalFunc func(score int) string
type revokeFunc func(subjectID string) bool

func main() {
	// Check for subcommands before flag parsing
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "http-proxy":
			runHTTPProxy(os.Args[2:])
			return
		case "init":
			runInit(os.Args[2:])
			return
		case "--version", "version":
			fmt.Println(version)
			return
		}
	}

	// Default: stdio proxy mode
	serverName := flag.String("name", "", "MCP server name (used in audit log)")
	policyPath := flag.String("policy", "", "Path to policy.json or directory containing it")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  quint-proxy --name <server> [--policy <path>] -- <command> [args...]   (stdio proxy)\n")
		fmt.Fprintf(os.Stderr, "  quint-proxy http-proxy --name <server> --target <url> [--port <port>]  (HTTP proxy)\n")
		fmt.Fprintf(os.Stderr, "  quint-proxy init [--role <preset>] [--apply] [--revert]                (setup wizard)\n\n")
		flag.PrintDefaults()
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

	// Initialize with stubs — phases replace these
	var logEntry logEntryFunc = func(_, _, _, _, _, _, _ string, _ intercept.Verdict, _ *int, _ *string) {}
	var scoreTool scoreFunc = func(_, _, _ string) *riskResult { return nil }
	var evalRisk evalFunc = func(_ int) string { return "allow" }
	var revoke revokeFunc = func(_ string) bool { return false }

	// Phase 2: Wire crypto + audit
	initAudit(dataDir, policy, &logEntry)

	// Phase 3: Wire risk engine
	initRisk(dataDir, &scoreTool, &evalRisk, &revoke)

	// Build relay callbacks
	sn := *serverName
	callbacks := relay.Callbacks{
		OnParentMessage: func(line string) string {
			return handleParentMessage(line, sn, policy, logEntry, scoreTool, evalRisk, revoke)
		},
		OnChildMessage: func(line string) string {
			return handleChildMessage(line, sn, logEntry)
		},
	}

	r := relay.New(childArgs[0], childArgs[1:], callbacks)

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		qlog.Info("received signal, shutting down")
		r.Stop()
	}()

	code := r.Start()
	qlog.Info("child exited with code %d", code)
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
) string {
	// Fail-open: if our processing throws, forward the message
	defer func() {
		if r := recover(); r != nil {
			qlog.Error("panic in parent message handler: %v", r)
		}
	}()

	result := intercept.InspectRequest(line, serverName, policy)

	if result.ToolName == "" || result.Verdict == intercept.VerdictDeny {
		logEntry(serverName, "request", result.Method, result.MessageID, result.ToolName, result.ArgumentsJson, "", result.Verdict, nil, nil)

		if result.Verdict == intercept.VerdictDeny {
			denyResp := intercept.BuildDenyResponse(result.RawID)
			qlog.Info("denied %s on %s", result.ToolName, serverName)
			logEntry(serverName, "response", result.Method, result.MessageID, result.ToolName, "", denyResp, intercept.VerdictDeny, nil, nil)
			os.Stdout.WriteString(denyResp + "\n")
			return ""
		}

		qlog.Debug("forwarding %s (%s) to child", result.Method, result.Verdict)
		return line
	}

	// Tool call — score risk
	risk := scoreTool(result.ToolName, result.ArgumentsJson, "anonymous")
	var riskScore *int
	var riskLevel *string
	if risk != nil {
		riskScore = &risk.score
		riskLevel = &risk.level
	}

	logEntry(serverName, "request", result.Method, result.MessageID, result.ToolName, result.ArgumentsJson, "", result.Verdict, riskScore, riskLevel)

	if risk != nil {
		action := evalRisk(risk.score)
		if action == "deny" {
			denyResp := intercept.BuildDenyResponse(result.RawID)
			qlog.Warn("risk-denied %s (score=%d, level=%s)", result.ToolName, risk.score, risk.level)
			logEntry(serverName, "response", result.Method, result.MessageID, result.ToolName, "", denyResp, intercept.VerdictDeny, riskScore, riskLevel)
			os.Stdout.WriteString(denyResp + "\n")
			return ""
		}
		if action == "flag" {
			qlog.Warn("high-risk %s (score=%d, level=%s)", result.ToolName, risk.score, risk.level)
		}
	}

	if revoke("anonymous") {
		qlog.Warn("repeated high-risk actions detected - consider revoking agent credentials")
	}

	if risk != nil {
		qlog.Debug("forwarding %s (risk=%d) to child", result.Method, risk.score)
	} else {
		qlog.Debug("forwarding %s to child", result.Method)
	}
	return line
}

// handleChildMessage processes a response from the MCP server heading to the AI agent.
func handleChildMessage(line string, serverName string, logEntry logEntryFunc) string {
	defer func() {
		if r := recover(); r != nil {
			qlog.Error("panic in child message handler: %v", r)
		}
	}()

	method, msgID, respJSON := intercept.InspectResponse(line)
	logEntry(serverName, "response", method, msgID, "", "", respJSON, intercept.VerdictPassthrough, nil, nil)
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
