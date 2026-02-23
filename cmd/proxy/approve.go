package main

import (
	"fmt"
	"os"

	"github.com/Quint-Security/quint-proxy/internal/approval"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runApprovals handles: quint-proxy approvals
func runApprovals(args []string) {
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

	db, err := approval.OpenDB(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open approval DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	pending, err := db.ListPending()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list approvals: %v\n", err)
		os.Exit(1)
	}

	if len(pending) == 0 {
		fmt.Println("No pending approval requests.")
		return
	}

	fmt.Printf("Pending approval requests:\n\n")
	for _, r := range pending {
		riskInfo := ""
		if r.RiskScore != nil {
			riskInfo = fmt.Sprintf(" (risk=%d", *r.RiskScore)
			if r.RiskLevel != nil {
				riskInfo += fmt.Sprintf(", level=%s", *r.RiskLevel)
			}
			riskInfo += ")"
		}
		fmt.Printf("  ID:     %s\n", r.ID)
		fmt.Printf("  Agent:  %s (%s)\n", r.AgentName, r.AgentID)
		fmt.Printf("  Tool:   %s%s\n", r.ToolName, riskInfo)
		fmt.Printf("  Server: %s\n", r.ServerName)
		fmt.Printf("  Time:   %s (expires %s)\n", r.CreatedAt, r.ExpiresAt)
		fmt.Printf("\n")
	}
	fmt.Printf("To approve: quint-proxy approve <id>\nTo deny:    quint-proxy deny <id>\n")
}

// runApprove handles: quint-proxy approve <id>
func runApprove(args []string) {
	decideApproval(args, true)
}

// runDeny handles: quint-proxy deny <id>
func runDeny(args []string) {
	decideApproval(args, false)
}

func decideApproval(args []string, approved bool) {
	var id, policyPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		default:
			if id == "" && !hasPrefix(args[i], "--") {
				id = args[i]
			}
		}
	}

	action := "approve"
	if !approved {
		action = "deny"
	}

	if id == "" {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy %s <approval-id>\n", action)
		os.Exit(1)
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	db, err := approval.OpenDB(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open approval DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Sign the decision
	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load signing keys: %v\n", err)
		os.Exit(1)
	}

	decisionData := fmt.Sprintf("%s:%s", id, action)
	sig, err := crypto.SignData(decisionData, kp.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign decision: %v\n", err)
		os.Exit(1)
	}

	if err := db.Decide(id, approved, "operator", sig); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to %s: %v\n", action, err)
		os.Exit(1)
	}

	verb := "Approved"
	if !approved {
		verb = "Denied"
	}
	fmt.Printf("%s approval %s (signed)\n", verb, id)
}
