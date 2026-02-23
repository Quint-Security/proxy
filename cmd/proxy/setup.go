package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Quint-Security/quint-proxy/internal/connect"
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
	runInit(append(args, "--apply"))
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

	// Step 3: Done
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
	fmt.Println()
}
