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

	for name, p := range connect.Providers {
		if p.ClientID == "" {
			continue // skip providers without built-in OAuth
		}
		fmt.Printf("  Connect %s? [Y/n] ", p.Name)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "" || answer == "y" || answer == "yes" {
			runConnectAdd([]string{name})
			fmt.Println()
		}
	}

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
