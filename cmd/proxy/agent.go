package main

import (
	"fmt"
	"os"

	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runAgent handles: quint-proxy agent create/list/suspend/revoke
func runAgent(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy agent <create|list|suspend|revoke> [options]\n")
		os.Exit(1)
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "create":
		runAgentCreate(subargs)
	case "list":
		runAgentList(subargs)
	case "suspend":
		runAgentSetStatus(subargs, "suspended")
	case "revoke":
		runAgentSetStatus(subargs, "revoked")
	default:
		fmt.Fprintf(os.Stderr, "Unknown agent command: %s\nUsage: quint-proxy agent <create|list|suspend|revoke>\n", subcmd)
		os.Exit(1)
	}
}

func runAgentCreate(args []string) {
	var name, agentType, scopes, description, policyPath string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--type":
			i++
			if i < len(args) {
				agentType = args[i]
			}
		case "--scopes":
			i++
			if i < len(args) {
				scopes = args[i]
			}
		case "--description":
			i++
			if i < len(args) {
				description = args[i]
			}
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		default:
			if name == "" && !hasPrefix(args[i], "--") {
				name = args[i]
			}
		}
	}

	if name == "" {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy agent create <name> [--type <type>] [--scopes <scopes>] [--description <desc>]\n")
		os.Exit(1)
	}
	if agentType == "" {
		agentType = "generic"
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	db, err := auth.OpenDB(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open auth DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	agent, rawKey, err := db.CreateAgent(name, agentType, description, scopes, "operator")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create agent: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Agent created:\n")
	fmt.Printf("  ID:     %s\n", agent.ID)
	fmt.Printf("  Name:   %s\n", agent.Name)
	fmt.Printf("  Type:   %s\n", agent.Type)
	fmt.Printf("  Scopes: %s\n", agent.Scopes)
	fmt.Printf("  Status: %s\n", agent.Status)
	fmt.Printf("\n")
	fmt.Printf("  API Key (shown once): %s\n", rawKey)
	fmt.Printf("\n  Store this key securely. It cannot be retrieved later.\n")
}

func runAgentList(args []string) {
	var policyPath string
	for i := 0; i < len(args); i++ {
		if args[i] == "--policy" {
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		}
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	db, err := auth.OpenDB(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open auth DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	agents, err := db.ListAgents()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list agents: %v\n", err)
		os.Exit(1)
	}

	if len(agents) == 0 {
		fmt.Println("No agents found.")
		return
	}

	fmt.Printf("%-20s %-12s %-12s %-30s %s\n", "NAME", "TYPE", "STATUS", "SCOPES", "ID")
	for _, a := range agents {
		fmt.Printf("%-20s %-12s %-12s %-30s %s\n", a.Name, a.Type, a.Status, a.Scopes, a.ID)
	}
}

func runAgentSetStatus(args []string, status string) {
	var name, policyPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		default:
			if name == "" && !hasPrefix(args[i], "--") {
				name = args[i]
			}
		}
	}

	if name == "" {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy agent %s <name>\n", status)
		os.Exit(1)
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	db, err := auth.OpenDB(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open auth DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.UpdateAgentStatus(name, status); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to %s agent: %v\n", status, err)
		os.Exit(1)
	}
	fmt.Printf("Agent %q is now %s.\n", name, status)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
