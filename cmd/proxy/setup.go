package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runSetup handles: quint setup
// Interactive wizard that runs init + configures risk scoring.
func runSetup(args []string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Welcome to Quint — security gateway for AI agents")
	fmt.Println()

	// Step 1: Init
	fmt.Println("[1/2] Detecting MCP servers and generating keys...")
	fmt.Println()
	serverCount := runInit(append(args, "--apply"))
	fmt.Println()

	// Step 1.5: Configure cloud risk scoring
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".quint")
	configureCloudRiskScoring(reader, dataDir)

	// Step 1.6: Configure shell monitoring
	configureShellMonitoring()

	// Step 2: Done
	if serverCount > 0 {
		fmt.Println("[2/2] Setup complete!")
		fmt.Println()
		fmt.Println("  Your AI agents are now secured through Quint.")
		fmt.Println("  Every tool call is intercepted, risk-scored, and signed.")
		fmt.Println("  Shell commands are monitored and audited.")
		fmt.Println()
		fmt.Println("  Next steps:")
		fmt.Println("    quint watch        Start the proxy + API server")
		fmt.Println("    quint status       Quick health check")
		fmt.Println("    quint verify       Verify audit trail integrity")
	} else {
		fmt.Println("[2/2] Partially complete")
		fmt.Println()
		fmt.Println("  Keys generated, but no MCP servers are being proxied yet.")
		fmt.Println()
		fmt.Println("  To finish setup:")
		fmt.Println("    1. Add MCP servers to your editor (Claude Code, Cursor, etc.)")
		fmt.Println("    2. Run `quint setup` again to start proxying")
	}
	fmt.Println()
}

// configureShellMonitoring configures Claude Code to use quint as its shell wrapper.
func configureShellMonitoring() {
	home, _ := os.UserHomeDir()
	claudeConfigPath := filepath.Join(home, ".claude.json")

	data, err := os.ReadFile(claudeConfigPath)
	if err != nil {
		return
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	self, err := os.Executable()
	if err != nil {
		return
	}

	if existingShell, ok := config["shellCommand"].(string); ok {
		if strings.Contains(existingShell, "quint") {
			return
		}
		saveOriginalShell(existingShell)
	}

	config["shellCommand"] = fmt.Sprintf("%s shell", self)

	updated, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return
	}

	if err := os.WriteFile(claudeConfigPath, append(updated, '\n'), 0o644); err == nil {
		fmt.Println("  Configured shell monitoring for Claude Code")
	}
}

func saveOriginalShell(originalShell string) {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".quint")
	os.MkdirAll(dataDir, 0o700)

	shellConfig := map[string]string{"shellCommand": originalShell}
	data, _ := json.MarshalIndent(shellConfig, "", "  ")
	os.WriteFile(filepath.Join(dataDir, "original_shell.json"), append(data, '\n'), 0o644)
}

func configureCloudRiskScoring(reader *bufio.Reader, dataDir string) {
	policyPath := filepath.Join(dataDir, "policy.json")

	data, err := os.ReadFile(policyPath)
	if err != nil {
		return
	}

	var policy map[string]any
	if err := json.Unmarshal(data, &policy); err != nil {
		return
	}

	if risk, ok := policy["risk"].(map[string]any); ok {
		if riskAPI, ok := risk["risk_api"].(map[string]any); ok {
			if url, ok := riskAPI["url"].(string); ok && url != "" {
				return
			}
		}
	}

	fmt.Print("  Configure cloud risk scoring? [y/N] ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer != "y" && answer != "yes" {
		return
	}

	fmt.Println()
	fmt.Println("  Cloud risk scoring configuration:")

	fmt.Print("    API URL (default: https://api-production-5aa1.up.railway.app): ")
	apiURL, _ := reader.ReadString('\n')
	apiURL = strings.TrimSpace(apiURL)
	if apiURL == "" {
		apiURL = "https://api-production-5aa1.up.railway.app"
	}

	fmt.Print("    API Key: ")
	apiKey, _ := reader.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		fmt.Println("    Skipping cloud risk scoring (no API key provided)")
		return
	}

	fmt.Print("    Customer ID: ")
	customerID, _ := reader.ReadString('\n')
	customerID = strings.TrimSpace(customerID)
	if customerID == "" {
		fmt.Println("    Skipping cloud risk scoring (no customer ID provided)")
		return
	}

	riskConfig := map[string]any{
		"flag": 25,
		"deny": 40,
		"risk_api": map[string]any{
			"url":         apiURL,
			"api_key":     apiKey,
			"customer_id": customerID,
			"enabled":     true,
			"timeout_ms":  15000,
		},
	}

	if existingRisk, ok := policy["risk"].(map[string]any); ok {
		existingRisk["risk_api"] = riskConfig["risk_api"]
	} else {
		policy["risk"] = riskConfig
	}

	updatedData, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "    Failed to serialize policy: %v\n", err)
		return
	}

	if err := os.WriteFile(policyPath, append(updatedData, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "    Failed to write policy: %v\n", err)
		return
	}

	fmt.Println("    Cloud risk scoring configured successfully")
}
