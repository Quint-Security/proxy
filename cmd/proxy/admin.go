package main

import (
	"fmt"
	"os"
)

// runAdmin handles: quint admin <subcommand> [args...]
func runAdmin(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printAdminUsage()
		return
	}

	switch args[0] {
	case "agent":
		runAgent(args[1:])
	case "verify":
		runVerify(args[1:])
	case "approve":
		runApprove(args[1:])
	case "deny":
		runDeny(args[1:])
	case "approvals":
		runApprovals(args[1:])
	case "init":
		runInit(args[1:])
	case "sync":
		runSync(args[1:])
	case "http-proxy":
		runHTTPProxy(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "quint admin: unknown command %q\n\n", args[0])
		printAdminUsage()
		os.Exit(1)
	}
}

func printAdminUsage() {
	fmt.Fprintf(os.Stderr, "Quint Admin — Advanced commands\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  quint admin agent              Agent identity management\n")
	fmt.Fprintf(os.Stderr, "  quint admin verify             Verify audit trail integrity\n")
	fmt.Fprintf(os.Stderr, "  quint admin approve <id>       Approve a pending request\n")
	fmt.Fprintf(os.Stderr, "  quint admin deny <id>          Deny a pending request\n")
	fmt.Fprintf(os.Stderr, "  quint admin approvals          List pending approvals\n")
	fmt.Fprintf(os.Stderr, "  quint admin init               Low-level initialization\n")
	fmt.Fprintf(os.Stderr, "  quint admin sync               Sync audit logs to cloud\n")
	fmt.Fprintf(os.Stderr, "  quint admin http-proxy          Run HTTP proxy mode\n")
}
