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

	// Offer providers that have built-in OAuth credentials
	offered := 0
	for _, name := range []string{"github", "notion", "sentry", "slack"} {
		p := connect.Providers[name]
		if p.ClientID == "" && p.ClientSecret == "" {
			continue
		}
		if connected[name] {
			fmt.Printf("  %s — already connected\n", p.Name)
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

	// Step 2.5: Suggest MCP servers for connected providers that aren't configured
	// Re-read connected providers (may have changed after connect step)
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
			for name := range gatewayCfg.Servers {
				existingServers[name] = true
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

	// Step 3: Done
	if serverCount > 0 {
		fmt.Println("[3/3] Setup complete!")
		fmt.Println()
		fmt.Println("  Your AI agents are now secured through Quint.")
		fmt.Println("  Every tool call is intercepted, risk-scored, and signed.")
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
	// TODO: Slack MCP server requires SLACK_TEAM_ID in addition to the OAuth token.
	// The connect flow needs to prompt for team ID after OAuth before we can auto-add this.
	// "slack": { ... }
	"sentry": {
		Command: "npx",
		Args:    []string{"-y", "@sentry/mcp-server-sentry"},
		Env:     map[string]string{"SENTRY_AUTH_TOKEN": "__CREDENTIAL:sentry__"},
	},
}
