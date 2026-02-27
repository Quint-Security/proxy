package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// runShell handles: quint shell [-c "command"]
// Acts as a transparent shell wrapper that logs and risk-scores commands.
func runShell(args []string) {
	fs := flag.NewFlagSet("shell", flag.ExitOnError)
	cFlag := fs.String("c", "", "Execute command string")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: quint shell [-c \"command\"]\n")
		fmt.Fprintf(os.Stderr, "\nTransparent shell wrapper for AI agent command monitoring.\n")
		fmt.Fprintf(os.Stderr, "Logs and risk-scores all shell commands before execution.\n")
	}
	fs.Parse(args)

	// Detect the real shell
	realShell := os.Getenv("SHELL")
	if realShell == "" {
		realShell = "/bin/bash"
	}

	// Avoid infinite recursion if someone set SHELL=quint
	self, _ := os.Executable()
	if strings.Contains(realShell, "quint") || realShell == self {
		fmt.Fprintf(os.Stderr, "quint: error: SHELL points to quint (infinite loop avoided)\n")
		os.Exit(1)
	}

	// Interactive mode: just exec the real shell
	if *cFlag == "" {
		syscall.Exec(realShell, []string{realShell}, os.Environ())
		fmt.Fprintf(os.Stderr, "quint: failed to exec %s\n", realShell)
		os.Exit(1)
	}

	// Command execution mode: log, score, and execute
	command := *cFlag

	// Load policy
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".quint")
	policyPath := filepath.Join(dataDir, "policy.json")

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		// Fail open if policy is missing (setup not complete)
		qlog.Debug("shell wrapper: no policy found, allowing command: %v", err)
		execCommand(realShell, command)
		return
	}

	qlog.SetLevel(policy.LogLevel)

	// Initialize audit and risk (reusing the stub patterns)
	var logEntry logEntryFunc = func(_, _, _, _, _, _, _ string, _ string, _ *int, _ *string, _ *riskResult) {}
	var scoreTool scoreFunc = func(_, _, _, _ string) *riskResult { return nil }
	var evalRisk evalFunc = func(_ int) string { return "allow" }
	var revoke revokeFunc = func(_ string) bool { return false }

	initAudit(dataDir, policy, &logEntry, nil)
	initRisk(dataDir, policy, &scoreTool, &evalRisk, &revoke)

	// Extract base command (first word) for policy checking and scoring
	baseCommand := extractBaseCommand(command)

	// Check policy for "shell" server
	shellPolicy := findShellPolicy(policy.Servers)
	verdict := checkToolPolicy(shellPolicy, baseCommand)

	if verdict == intercept.VerdictDeny {
		fmt.Fprintf(os.Stderr, "quint: command denied by policy: %s\n", baseCommand)
		logEntry("shell", "request", "bash", "", baseCommand, command, "", "deny", nil, nil, nil)
		os.Exit(1)
	}

	// Score the command (local only for speed)
	subjectID := "shell-user"
	risk := scoreTool(baseCommand, command, subjectID, "shell")

	var riskScore *int
	var riskLevel *string
	if risk != nil {
		riskScore = &risk.score
		riskLevel = &risk.level
	}

	logEntry("shell", "request", "bash", "", baseCommand, command, "", string(verdict), riskScore, riskLevel, risk)

	// Evaluate risk
	if risk != nil {
		action := evalRisk(risk.score)
		if action == "deny" {
			fmt.Fprintf(os.Stderr, "quint: command denied by risk score (%d): %s\n", risk.score, baseCommand)
			os.Exit(1)
		}
		if action == "flag" {
			// In shell mode, flags are warnings but allowed (fail-open)
			qlog.Warn("high-risk shell command (score=%d): %s", risk.score, command)
		}
	}

	// Execute the command
	exitCode := execCommand(realShell, command)

	// Log response with exit code
	responseJSON := fmt.Sprintf(`{"exit_code": %d}`, exitCode)
	logEntry("shell", "response", "bash", "", baseCommand, "", responseJSON, "allow", riskScore, riskLevel, risk)

	cleanup()
	os.Exit(exitCode)
}

// execCommand runs the command in the real shell and returns the exit code.
func execCommand(shell, command string) int {
	cmd := exec.Command(shell, "-c", command)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		// Command failed to start
		return 127
	}
	return 0
}

// extractBaseCommand returns the first word of a command string.
// "git commit -m foo" -> "git"
// "  rm -rf /  " -> "rm"
func extractBaseCommand(command string) string {
	trimmed := strings.TrimSpace(command)
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// findShellPolicy searches for a "shell" server in the policy.
func findShellPolicy(servers []intercept.ServerPolicy) *intercept.ServerPolicy {
	for _, s := range servers {
		if s.Server == "shell" {
			return &s
		}
	}
	return nil
}

// checkToolPolicy checks if a tool is allowed by the policy.
func checkToolPolicy(policy *intercept.ServerPolicy, toolName string) intercept.Verdict {
	if policy == nil {
		return intercept.VerdictAllow // No shell policy, allow by default
	}

	// Check tool rules
	for _, rule := range policy.Tools {
		if matchPattern(rule.Tool, toolName) {
			switch rule.Action {
			case intercept.ActionDeny:
				return intercept.VerdictDeny
			case intercept.ActionAllow:
				return intercept.VerdictAllow
			}
		}
	}

	// Fall back to default action
	switch policy.DefaultAction {
	case intercept.ActionDeny:
		return intercept.VerdictDeny
	default:
		return intercept.VerdictAllow
	}
}

// matchPattern checks if a tool name matches a pattern (with * wildcard).
func matchPattern(pattern, toolName string) bool {
	// Simple glob matching: * matches anything
	if pattern == "*" {
		return true
	}

	// Exact match
	if pattern == toolName {
		return true
	}

	// Prefix match: "rm*" matches "rm", "rmdir", "rm_old"
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(toolName, prefix)
	}

	// Suffix match: "*rm" matches "rm", "xrm", "myrm"
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(toolName, suffix)
	}

	// Contains match: "*rm*" matches anything with "rm"
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		middle := strings.Trim(pattern, "*")
		return strings.Contains(toolName, middle)
	}

	return false
}
