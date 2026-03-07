package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Quint-Security/quint-proxy/internal/connect"
	"github.com/Quint-Security/quint-proxy/internal/gateway"
)

// runSetup handles: quint setup
// Interactive wizard that runs init + connect + starts the dashboard.
func runSetup(args []string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Welcome to Quint — security gateway for AI agents")
	fmt.Println()

	// Step 1: Init
	fmt.Println("[1/3] Detecting MCP servers and generating keys...")
	fmt.Println()
	serverCount := runInit(append(args, "--apply"))
	fmt.Println()

	// Step 2: Connect providers
	fmt.Println("[2/3] Connect services")
	fmt.Println()

	// Check which providers are already connected
	store, _ := openCredStore("")
	var connected map[string]bool
	if store != nil {
		connected = make(map[string]bool)
		creds, _ := store.List()
		for _, c := range creds {
			if !store.IsExpired(c.ID) {
				connected[c.ID] = true
			}
		}
		store.Close()
	}

	// Offer providers for connection
	offered := 0
	for _, name := range []string{"github", "notion", "sentry", "slack"} {
		p := connect.Providers[name]
		if connected[name] {
			fmt.Printf("  %s — already connected\n", p.Name)
			continue
		}
		// Skip providers without OAuth config (secrets moved server-side)
		if p.ClientID == "" && p.ClientSecret == "" {
			continue
		}
		offered++
		fmt.Printf("  Connect %s? [Y/n] ", p.Name)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "" || answer == "y" || answer == "yes" {
			runConnectAdd([]string{name})
			fmt.Println()
		}
	}
	if offered == 0 {
		fmt.Println("  All providers already connected.")
	}
	fmt.Println()

	// Step 2.5: Reconcile connected providers with gateway servers.json
	// Always runs — ensures every connected provider has a matching MCP server.
	// Also checks existing servers.json for credential references to detect providers
	// that were connected outside the setup flow.
	store2, dataDir := openCredStore("")
	if store2 != nil {
		connected = make(map[string]bool)
		creds, _ := store2.List()
		for _, c := range creds {
			if !store2.IsExpired(c.ID) {
				connected[c.ID] = true
			}
		}
		store2.Close()

		// Load current gateway servers
		gatewayCfg, _ := gateway.LoadConfig(dataDir)
		existingServers := map[string]bool{}
		if gatewayCfg != nil {
			for name, srv := range gatewayCfg.Servers {
				existingServers[name] = true
				// Also detect providers from credential placeholders in existing servers
				// e.g. "__CREDENTIAL:notion__" means notion is connected
				for _, v := range srv.Env {
					if strings.HasPrefix(v, "__CREDENTIAL:") && strings.HasSuffix(v, "__") {
						provider := strings.TrimSuffix(strings.TrimPrefix(v, "__CREDENTIAL:"), "__")
						connected[provider] = true
					}
				}
			}
		}

		// Auto-add MCP servers for connected providers
		added := 0
		for provider, mcpCfg := range providerMCPServers {
			if !connected[provider] {
				continue
			}
			if existingServers[provider] {
				continue
			}
			if gatewayCfg == nil {
				gatewayCfg = &gateway.Config{Servers: map[string]gateway.ServerConfig{}}
			}
			gatewayCfg.Servers[provider] = mcpCfg
			existingServers[provider] = true
			added++
			fmt.Printf("  Added %s MCP server to gateway\n", provider)
		}

		if added > 0 {
			serversPath := filepath.Join(dataDir, "servers.json")
			data, err := json.MarshalIndent(gatewayCfg, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Failed to serialize servers config: %v\n", err)
			} else if err := os.WriteFile(serversPath, append(data, '\n'), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "  Failed to write servers.json: %v\n", err)
			} else {
				fmt.Printf("\n  Updated servers.json with %d new server(s).\n", added)
				fmt.Println("  Restart Claude Code for changes to take effect.")
			}
		}
	}
	fmt.Println()

	// Step 2.6: Configure cloud risk scoring
	configureCloudRiskScoring(reader, dataDir)

	// Step 2.7: Configure shell monitoring
	configureShellMonitoring()

	// Step 3: Done
	if serverCount > 0 {
		fmt.Println("[3/3] Setup complete!")
		fmt.Println()
		fmt.Println("  Your AI agents are now secured through Quint.")
		fmt.Println("  Every tool call is intercepted, risk-scored, and signed.")
		fmt.Println("  Shell commands are monitored and audited.")
		fmt.Println()
		fmt.Println("  Next steps:")
		fmt.Println("    quint dashboard    Open the web dashboard")
		fmt.Println("    quint status       Quick health check")
		fmt.Println("    quint verify       Verify audit trail integrity")
		fmt.Println("    quint connect      See connected services")
	} else {
		fmt.Println("[3/3] Partially complete")
		fmt.Println()
		fmt.Println("  Keys generated and providers connected, but no MCP servers")
		fmt.Println("  are being proxied yet.")
		fmt.Println()
		fmt.Println("  To finish setup:")
		fmt.Println("    1. Add MCP servers to your editor (Claude Code, Cursor, etc.)")
		fmt.Println("    2. Run `quint setup` again to start proxying")
	}
	fmt.Println()
}

// providerMCPServers maps OAuth provider names to their MCP server configurations.
// When a provider is connected but has no matching MCP server, setup offers to add it.
var providerMCPServers = map[string]gateway.ServerConfig{
	"github": {
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-github"},
		Env:     map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": "__CREDENTIAL:github__"},
	},
	"notion": {
		Command: "npx",
		Args:    []string{"-y", "@notionhq/notion-mcp-server"},
		Env:     map[string]string{"NOTION_TOKEN": "__CREDENTIAL:notion__"},
	},
	// TODO: Slack MCP server requires SLACK_TEAM_ID in addition to the OAuth token.
	// The connect flow needs to prompt for team ID after OAuth before we can auto-add this.
	// "slack": { ... }
	"sentry": {
		Command: "npx",
		Args:    []string{"-y", "@sentry/mcp-server-sentry"},
		Env:     map[string]string{"SENTRY_AUTH_TOKEN": "__CREDENTIAL:sentry__"},
	},
}

// configureShellMonitoring configures Claude Code to use quint as its shell wrapper.
func configureShellMonitoring() {
	home, _ := os.UserHomeDir()
	claudeConfigPath := filepath.Join(home, ".claude.json")

	// Check if Claude Code config exists
	data, err := os.ReadFile(claudeConfigPath)
	if err != nil {
		// Claude Code not installed or configured, skip shell monitoring
		return
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	// Get path to this binary
	self, err := os.Executable()
	if err != nil {
		return
	}

	// Check if shellCommand is already set to quint
	if existingShell, ok := config["shellCommand"].(string); ok {
		if strings.Contains(existingShell, "quint") {
			// Already configured
			return
		}
		// Save original shell command for revert
		saveOriginalShell(existingShell)
	}

	// Set shellCommand to quint shell
	config["shellCommand"] = fmt.Sprintf("%s shell", self)

	// Write updated config
	updated, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return
	}

	if err := os.WriteFile(claudeConfigPath, append(updated, '\n'), 0o644); err == nil {
		fmt.Println("  Configured shell monitoring for Claude Code")
	}
}

// saveOriginalShell saves the original shellCommand for revert.
func saveOriginalShell(originalShell string) {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".quint")
	os.MkdirAll(dataDir, 0o700)

	shellConfig := map[string]string{"shellCommand": originalShell}
	data, _ := json.MarshalIndent(shellConfig, "", "  ")
	os.WriteFile(filepath.Join(dataDir, "original_shell.json"), append(data, '\n'), 0o644)
}

// configureCloudRiskScoring prompts the user to configure cloud risk scoring.
func configureCloudRiskScoring(reader *bufio.Reader, dataDir string) {
	// Import the intercept package types
	policyPath := filepath.Join(dataDir, "policy.json")

	// Check if policy.json exists
	data, err := os.ReadFile(policyPath)
	if err != nil {
		// No policy.json yet, skip cloud config
		return
	}

	// Parse existing policy
	var policy map[string]any
	if err := json.Unmarshal(data, &policy); err != nil {
		return
	}

	// Check if risk config already exists
	if risk, ok := policy["risk"].(map[string]any); ok {
		if riskAPI, ok := risk["risk_api"].(map[string]any); ok {
			if url, ok := riskAPI["url"].(string); ok && url != "" {
				// Already configured
				return
			}
		}
	}

	// Prompt user
	fmt.Print("  Configure cloud risk scoring? [y/N] ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer != "y" && answer != "yes" {
		return
	}

	fmt.Println()
	fmt.Println("  Cloud risk scoring configuration:")

	// Prompt for API URL
	fmt.Print("    API URL (default: https://api-production-5aa1.up.railway.app): ")
	apiURL, _ := reader.ReadString('\n')
	apiURL = strings.TrimSpace(apiURL)
	if apiURL == "" {
		apiURL = "https://api-production-5aa1.up.railway.app"
	}

	// Prompt for API key
	fmt.Print("    API Key: ")
	apiKey, _ := reader.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		fmt.Println("    Skipping cloud risk scoring (no API key provided)")
		return
	}

	// Prompt for customer ID
	fmt.Print("    Customer ID: ")
	customerID, _ := reader.ReadString('\n')
	customerID = strings.TrimSpace(customerID)
	if customerID == "" {
		fmt.Println("    Skipping cloud risk scoring (no customer ID provided)")
		return
	}

	// Build risk config
	riskConfig := map[string]any{
		"flag":       25,
		"deny":       40,
		"risk_api": map[string]any{
			"url":         apiURL,
			"api_key":     apiKey,
			"customer_id": customerID,
			"enabled":     true,
			"timeout_ms":  15000,
		},
	}

	// Merge into existing policy
	if existingRisk, ok := policy["risk"].(map[string]any); ok {
		// Preserve existing risk settings, only add risk_api
		existingRisk["risk_api"] = riskConfig["risk_api"]
	} else {
		// Create new risk config
		policy["risk"] = riskConfig
	}

	// Write updated policy
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
