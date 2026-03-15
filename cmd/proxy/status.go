package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Quint-Security/quint-proxy/internal/approval"
	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runStatus handles: quint-proxy status
func runStatus(args []string) {
	var policyPath string
	var apiPort int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		case "--api-port":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &apiPort)
			}
		}
	}
	if apiPort == 0 {
		apiPort = 8080
	}

	// Try the live health endpoint first
	if printLiveHealth(apiPort) {
		return
	}

	// Fall back to reading from local databases
	fmt.Println("  (daemon not running — showing local data)")
	fmt.Println()

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

// printLiveHealth calls the /health endpoint on the running daemon and
// prints a formatted status. Returns true if the daemon was reachable.
func printLiveHealth(apiPort int) bool {
	url := fmt.Sprintf("http://localhost:%d/health", apiPort)
	resp, err := httpGetQuick(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var health struct {
		Status        string   `json:"status"`
		Version       string   `json:"version"`
		UptimeSeconds int64    `json:"uptime_seconds"`
		Proxy         struct {
			Listening bool `json:"listening"`
			Port      int  `json:"port"`
		} `json:"proxy"`
		CA struct {
			Trusted  bool   `json:"trusted"`
			CertPath string `json:"cert_path"`
		} `json:"ca"`
		AgentsDetected []string `json:"agents_detected"`
		Stats          struct {
			EventsTotal   int `json:"events_total"`
			EventsBlocked int `json:"events_blocked"`
		} `json:"stats"`
		Cloud struct {
			Connected     bool   `json:"connected"`
			LastHeartbeat string `json:"last_heartbeat"`
		} `json:"cloud"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		return false
	}

	fmt.Println()
	fmt.Println("  Quint Status")
	fmt.Println("  ============")
	fmt.Println()
	fmt.Printf("  Status:   %s\n", health.Status)
	fmt.Printf("  Version:  %s\n", health.Version)
	fmt.Printf("  Uptime:   %s\n", formatUptime(health.UptimeSeconds))
	fmt.Println()

	fmt.Println("  Proxy")
	if health.Proxy.Listening {
		fmt.Printf("    Listening: port %d\n", health.Proxy.Port)
	} else {
		fmt.Printf("    Listening: no\n")
	}
	fmt.Println()

	fmt.Println("  CA Certificate")
	if health.CA.Trusted {
		fmt.Printf("    Trusted:   yes\n")
	} else {
		fmt.Printf("    Trusted:   no\n")
	}
	fmt.Printf("    Path:      %s\n", health.CA.CertPath)
	fmt.Println()

	fmt.Println("  Events")
	fmt.Printf("    Total:     %d\n", health.Stats.EventsTotal)
	fmt.Printf("    Blocked:   %d\n", health.Stats.EventsBlocked)
	fmt.Println()

	if len(health.AgentsDetected) > 0 {
		fmt.Println("  Agents Detected")
		fmt.Printf("    %s\n", strings.Join(health.AgentsDetected, ", "))
		fmt.Println()
	}

	fmt.Println("  Cloud")
	if health.Cloud.Connected {
		fmt.Printf("    Connected: yes\n")
		if health.Cloud.LastHeartbeat != "" {
			fmt.Printf("    Last heartbeat: %s\n", health.Cloud.LastHeartbeat)
		}
	} else {
		fmt.Printf("    Connected: no\n")
	}
	fmt.Println()

	return true
}

// formatUptime converts seconds to a human-readable duration string.
func formatUptime(seconds int64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
	}
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	if hours < 24 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	days := hours / 24
	hours = hours % 24
	return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
}
