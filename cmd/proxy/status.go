package main

import (
	"fmt"
	"os"

	"github.com/Quint-Security/quint-proxy/internal/approval"
	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runStatus handles: quint-proxy status
func runStatus(args []string) {
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

	fmt.Printf("Quint Status\n")
	fmt.Printf("  Data dir: %s\n", dataDir)
	fmt.Printf("  Policy:   v%d, %d server(s), fail_mode=%s\n", policy.Version, len(policy.Servers), policy.GetFailMode())

	if policy.ApprovalRequired {
		fmt.Printf("  Approval: required (timeout=%ds)\n", policy.GetApprovalTimeout())
	}

	// Audit stats
	auditDB, err := audit.OpenDB(dataDir)
	if err == nil {
		stats := auditDB.Stats()
		fmt.Printf("\n  Audit Log\n")
		fmt.Printf("    Total entries: %v\n", stats["total_entries"])
		fmt.Printf("    Denied:        %v\n", stats["denied"])
		fmt.Printf("    High risk:     %v\n", stats["high_risk"])
		if ts, ok := stats["last_entry"].(string); ok && ts != "" {
			fmt.Printf("    Last entry:    %s\n", ts)
		}
		auditDB.Close()
	}

	// Agents
	authDB, err := auth.OpenDB(dataDir)
	if err == nil {
		agents, _ := authDB.ListAgents()
		active := 0
		for _, a := range agents {
			if a.Status == "active" {
				active++
			}
		}
		fmt.Printf("\n  Agents\n")
		fmt.Printf("    Total:  %d\n", len(agents))
		fmt.Printf("    Active: %d\n", active)
		authDB.Close()
	}

	// Approvals
	approvalDB, err := approval.OpenDB(dataDir)
	if err == nil {
		pending, _ := approvalDB.ListPending()
		fmt.Printf("\n  Approvals\n")
		fmt.Printf("    Pending: %d\n", len(pending))
		approvalDB.Close()
	}

	fmt.Println()
}
