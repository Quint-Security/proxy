package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/gateway"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

type rolePreset struct {
	Name          string
	Description   string
	DefaultAction intercept.Action
	Tools         []intercept.ToolRule
}

var rolePresets = map[string]rolePreset{
	"coding-assistant": {
		Name: "Coding Assistant", Description: "Read/write project files, run builds and tests. Block destructive ops.",
		DefaultAction: intercept.ActionAllow,
		Tools: []intercept.ToolRule{
			{Tool: "Delete*", Action: intercept.ActionDeny},
			{Tool: "Remove*", Action: intercept.ActionDeny},
			{Tool: "Drop*", Action: intercept.ActionDeny},
		},
	},
	"research-agent": {
		Name: "Research Agent", Description: "Read-only access. All write/execute operations denied.",
		DefaultAction: intercept.ActionDeny,
		Tools: []intercept.ToolRule{
			{Tool: "Read*", Action: intercept.ActionAllow},
			{Tool: "Get*", Action: intercept.ActionAllow},
			{Tool: "List*", Action: intercept.ActionAllow},
			{Tool: "Search*", Action: intercept.ActionAllow},
			{Tool: "Fetch*", Action: intercept.ActionAllow},
		},
	},
	"strict": {
		Name: "Strict", Description: "Deny everything by default. Manually allowlist tools.",
		DefaultAction: intercept.ActionDeny, Tools: []intercept.ToolRule{},
	},
	"permissive": {
		Name: "Permissive", Description: "Allow everything, deny only destructive operations.",
		DefaultAction: intercept.ActionAllow,
		Tools: []intercept.ToolRule{
			{Tool: "Delete*", Action: intercept.ActionDeny},
			{Tool: "Remove*", Action: intercept.ActionDeny},
			{Tool: "Drop*", Action: intercept.ActionDeny},
		},
	},
}

type claudeMcpServer struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	URL     string            `json:"url,omitempty"`
	Type    string            `json:"type,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

type detectedServer struct {
	Name           string
	Config         claudeMcpServer
	Source         string // "global" or "project"
	AlreadyProxied bool
}

func runInit(args []string) int {
	var roleName string
	var apply, revert, dryRun, listRoles bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--role":
			i++
			if i < len(args) {
				roleName = args[i]
			}
		case "--apply":
			apply = true
		case "--revert":
			revert = true
		case "--dry-run":
			dryRun = true
		case "--list-roles":
			listRoles = true
		}
	}

	if listRoles {
		fmt.Println("Available role presets:")
		for id, preset := range rolePresets {
			fmt.Printf("  %s\n    %s\n    Default: %s, %d tool rules\n\n", id, preset.Description, preset.DefaultAction, len(preset.Tools))
		}
		return 0
	}

	if revert {
		runRevert(dryRun)
		return 0
	}

	fmt.Println("Quint Setup")

	// Detect MCP servers
	servers := detectMcpServers()
	if len(servers) == 0 {
		fmt.Println("  No MCP servers detected.")
		fmt.Println("  Quint works by wrapping your existing MCP servers.")
		fmt.Println()
		fmt.Println("  Checked:")
		for _, client := range knownMCPClients() {
			for _, relPath := range client.ConfigPaths {
				fmt.Printf("    ~/%s  (%s)\n", relPath, client.Name)
			}
		}
		fmt.Println()
		fmt.Println("  To get started:")
		fmt.Println("    1. Add MCP servers to Claude Code, Cursor, or Windsurf")
		fmt.Println("    2. Run `quint setup` again")
	} else {
		fmt.Printf("  Found %d MCP server(s):\n\n", len(servers))
		for _, s := range servers {
			status := ""
			if s.AlreadyProxied {
				status = " (already proxied)"
			}
			if s.Config.Command != "" {
				fmt.Printf("    %s [stdio: %s] (%s)%s\n", s.Name, s.Config.Command, s.Source, status)
			} else if s.Config.URL != "" {
				fmt.Printf("    %s [HTTP: %s] (%s)%s\n", s.Name, s.Config.URL, s.Source, status)
			}
		}
	}

	// Generate keys
	fmt.Println()
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".quint")
	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Failed to generate keys: %v\n", err)
		os.Exit(1)
	}
	fingerprint := kp.PublicKey[27:43] // rough fingerprint from PEM body
	fmt.Printf("  Keys:   %s (ready)\n", fingerprint)

	if len(servers) == 0 {
		return 0
	}

	// Generate policy
	var role *rolePreset
	if roleName != "" {
		r, ok := rolePresets[roleName]
		if !ok {
			fmt.Fprintf(os.Stderr, "\n  Unknown role: %s\n  Available: %s\n", roleName, strings.Join(rolePresetNames(), ", "))
			os.Exit(1)
		}
		role = &r
	}

	// Default deny rules block dangerous tool patterns out of the box.
	// These apply to detected servers when no --role is specified.
	defaultDenyRules := []intercept.ToolRule{
		// Destructive operations
		{Tool: "*delete*", Action: intercept.ActionDeny},
		{Tool: "*Delete*", Action: intercept.ActionDeny},
		{Tool: "*remove*", Action: intercept.ActionDeny},
		{Tool: "*Remove*", Action: intercept.ActionDeny},
		{Tool: "*destroy*", Action: intercept.ActionDeny},
		{Tool: "*Destroy*", Action: intercept.ActionDeny},
		// Shell execution
		{Tool: "*execute*", Action: intercept.ActionDeny},
		{Tool: "*Execute*", Action: intercept.ActionDeny},
		{Tool: "*run_command*", Action: intercept.ActionDeny},
		{Tool: "*RunCommand*", Action: intercept.ActionDeny},
		{Tool: "*shell*", Action: intercept.ActionDeny},
		{Tool: "*Shell*", Action: intercept.ActionDeny},
		{Tool: "*bash*", Action: intercept.ActionDeny},
		{Tool: "*Bash*", Action: intercept.ActionDeny},
		{Tool: "*terminal*", Action: intercept.ActionDeny},
		{Tool: "*Terminal*", Action: intercept.ActionDeny},
		// Sensitive path writes
		{Tool: "*write*secret*", Action: intercept.ActionDeny},
		{Tool: "*write*Secret*", Action: intercept.ActionDeny},
		{Tool: "*Write*secret*", Action: intercept.ActionDeny},
		{Tool: "*Write*Secret*", Action: intercept.ActionDeny},
		{Tool: "*write*env*", Action: intercept.ActionDeny},
		{Tool: "*Write*env*", Action: intercept.ActionDeny},
		{Tool: "*Write*Env*", Action: intercept.ActionDeny},
		{Tool: "*write*credential*", Action: intercept.ActionDeny},
		{Tool: "*write*Credential*", Action: intercept.ActionDeny},
		{Tool: "*Write*credential*", Action: intercept.ActionDeny},
		{Tool: "*Write*Credential*", Action: intercept.ActionDeny},
	}

	serverPolicies := make([]intercept.ServerPolicy, 0, len(servers)+1)
	for _, s := range servers {
		sp := intercept.ServerPolicy{Server: s.Name, DefaultAction: intercept.ActionAllow, Tools: []intercept.ToolRule{}}
		if role != nil {
			sp.DefaultAction = role.DefaultAction
			sp.Tools = append(sp.Tools, role.Tools...)
		} else {
			sp.Tools = append(sp.Tools, defaultDenyRules...)
		}
		serverPolicies = append(serverPolicies, sp)
	}
	// Unknown servers are denied by default (fail-closed)
	serverPolicies = append(serverPolicies, intercept.ServerPolicy{Server: "*", DefaultAction: intercept.ActionDeny, Tools: []intercept.ToolRule{}})

	policy := intercept.PolicyConfig{
		Version: 1, DataDir: "~/.quint", LogLevel: "info", Servers: serverPolicies,
	}

	policyPath := filepath.Join(dataDir, "policy.json")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		data, _ := json.MarshalIndent(policy, "", "  ")
		os.WriteFile(policyPath, append(data, '\n'), 0o644)
		roleLabel := ""
		if role != nil {
			roleLabel = fmt.Sprintf(", role: %s", role.Name)
		}
		fmt.Printf("  Policy: %s (created%s)\n", policyPath, roleLabel)
		if role == nil {
			fmt.Println("           Detected servers: allow with deny rules for destructive/shell/sensitive ops")
			fmt.Println("           Unknown servers:  denied (fail-closed)")
			fmt.Println("           Customize: edit policy.json or re-run with --role <preset>")
		}
	} else {
		fmt.Printf("  Policy: %s (exists, not overwritten)\n", policyPath)
	}

	// Gateway mode: generate servers.json and replace all MCP entries with one "quint" entry
	nonProxied := filterUnproxied(servers)
	if len(nonProxied) == 0 {
		// Check if servers.json already exists and has content
		existingCfg, _ := gateway.LoadConfig(dataDir)
		if existingCfg != nil && len(existingCfg.Servers) > 0 {
			fmt.Printf("\n  All servers already proxied through Quint (%d servers configured).\n", len(existingCfg.Servers))
			fmt.Println("\n  Setup complete.")
			return len(servers)
		}
		fmt.Println("\n  No MCP servers found to proxy.")
		fmt.Println("\n  Setup complete.")
		return len(servers)
	}

	self, _ := os.Executable()
	fmt.Printf("\n  Gateway mode: %d server(s) will be managed by Quint\n\n", len(nonProxied))

	// Show what will happen
	for _, s := range nonProxied {
		if s.Config.Command != "" {
			fmt.Printf("    %s [stdio] → managed by quint gateway\n", s.Name)
		} else if s.Config.URL != "" {
			fmt.Printf("    %s [HTTP: %s] → managed by quint gateway\n", s.Name, s.Config.URL)
		}
	}

	fmt.Printf("\n  Claude Code config will be replaced with:\n")
	fmt.Printf("    quint: { command: %s, args: [start] }\n", self)

	if apply && !dryRun {
		// Generate servers.json
		gatewayCfg := buildGatewayConfig(nonProxied)
		serversPath := filepath.Join(dataDir, "servers.json")
		data, _ := json.MarshalIndent(gatewayCfg, "", "  ")
		os.WriteFile(serversPath, append(data, '\n'), 0o644)
		fmt.Printf("\n  Servers config: %s (%d servers)\n", serversPath, len(gatewayCfg.Servers))

		// Save original config for revert
		saveOriginalConfig(dataDir, servers)

		// Replace all MCP entries with single "quint" entry
		applyGatewayConfig(servers, self)
		fmt.Println("  Applied gateway config to ~/.claude.json")
		fmt.Println("  Restart Claude Code for changes to take effect.")
	} else if dryRun {
		fmt.Println("\n  (dry run — no changes made)")
	} else {
		fmt.Println("\n  Run with --apply to apply changes.")
		fmt.Println("  Run with --revert to undo.")
	}

	fmt.Println("\n  Setup complete.")
	return len(servers)
}

func runRevert(dryRun bool) {
	servers := detectMcpServers()
	proxied := filterProxied(servers)

	if len(proxied) == 0 {
		fmt.Println("No Quint-proxied servers found. Nothing to revert.")
		return
	}

	if dryRun {
		fmt.Println("Would revert these servers:")
		for _, s := range proxied {
			origCmd, origArgs := extractOriginalCommand(s.Config)
			fmt.Printf("  %s: quint-proxy → %s %s\n", s.Name, origCmd, strings.Join(origArgs, " "))
		}
		return
	}

	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".claude.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", configPath, err)
		os.Exit(1)
	}

	var config map[string]any
	json.Unmarshal(data, &config)

	reverted := 0
	mcpServers, _ := config["mcpServers"].(map[string]any)
	for _, s := range proxied {
		origCmd, origArgs := extractOriginalCommand(s.Config)
		if origCmd == "" {
			continue
		}
		restored := map[string]any{"command": origCmd, "args": origArgs}
		if mcpServers != nil {
			if _, ok := mcpServers[s.Name]; ok {
				mcpServers[s.Name] = restored
				reverted++
			}
		}
	}

	out, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, append(out, '\n'), 0o644)
	fmt.Printf("Reverted %d server(s). Restart Claude Code for changes to take effect.\n", reverted)
}

// mcpClient describes a known MCP client and its config file locations.
type mcpClient struct {
	Name        string
	ConfigPaths []string // relative to home directory
}

// knownMCPClients lists all supported MCP clients and their config file paths.
func knownMCPClients() []mcpClient {
	return []mcpClient{
		{Name: "Claude Code", ConfigPaths: []string{".claude.json"}},
		{Name: "Cursor", ConfigPaths: []string{".cursor/mcp.json", "Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json"}},
		{Name: "Windsurf", ConfigPaths: []string{".windsurf/mcp.json", ".codeium/windsurf/mcp_config.json"}},
		{Name: "Cline", ConfigPaths: []string{
			"Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
			".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
		}},
	}
}

func detectMcpServers() []detectedServer {
	home, _ := os.UserHomeDir()
	var servers []detectedServer
	seen := map[string]bool{}

	for _, client := range knownMCPClients() {
		for _, relPath := range client.ConfigPaths {
			configPath := filepath.Join(home, relPath)
			data, err := os.ReadFile(configPath)
			if err != nil {
				continue
			}

			var config map[string]any
			if err := json.Unmarshal(data, &config); err != nil {
				continue
			}

			fmt.Printf("  Detected %s (%s)\n", client.Name, relPath)

			// Parse mcpServers at top level
			if mcpServers, ok := config["mcpServers"].(map[string]any); ok {
				for name, srv := range mcpServers {
					if seen[name] {
						continue
					}
					seen[name] = true
					srvMap, _ := srv.(map[string]any)
					cs := parseMcpServer(srvMap)
					servers = append(servers, detectedServer{
						Name: name, Config: cs, Source: "global",
						AlreadyProxied: isAlreadyProxied(cs),
					})
				}
			}

			// Parse project-level servers (Claude Code specific)
			if projects, ok := config["projects"].(map[string]any); ok {
				cwd, _ := os.Getwd()
				for projPath, proj := range projects {
					if !strings.HasPrefix(cwd, projPath) {
						continue
					}
					projMap, _ := proj.(map[string]any)
					mcpServers, _ := projMap["mcpServers"].(map[string]any)
					for name, srv := range mcpServers {
						if seen[name] {
							continue
						}
						seen[name] = true
						srvMap, _ := srv.(map[string]any)
						cs := parseMcpServer(srvMap)
						servers = append(servers, detectedServer{
							Name: name, Config: cs, Source: "project",
							AlreadyProxied: isAlreadyProxied(cs),
						})
					}
				}
			}

			break // found config for this client, don't check alternate paths
		}
	}

	return servers
}

func parseMcpServer(m map[string]any) claudeMcpServer {
	cs := claudeMcpServer{}
	if v, ok := m["command"].(string); ok {
		cs.Command = v
	}
	if v, ok := m["url"].(string); ok {
		cs.URL = v
	}
	if v, ok := m["type"].(string); ok {
		cs.Type = v
	}
	if args, ok := m["args"].([]any); ok {
		for _, a := range args {
			if s, ok := a.(string); ok {
				cs.Args = append(cs.Args, s)
			}
		}
	}
	return cs
}

func isAlreadyProxied(srv claudeMcpServer) bool {
	if strings.HasSuffix(srv.Command, "quint-proxy") || strings.HasSuffix(srv.Command, "/quint") || srv.Command == "quint" {
		return true
	}
	// HTTP servers proxied through localhost with quint port range
	if srv.URL != "" && strings.HasPrefix(srv.URL, "http://localhost:17") {
		return true
	}
	return false
}

func generateWrappedConfig(s detectedServer) *claudeMcpServer {
	if s.AlreadyProxied {
		return nil
	}
	// Get the path to this binary
	self, _ := os.Executable()

	if s.Config.Command != "" {
		// Stdio MCP server — wrap with stdio proxy
		return &claudeMcpServer{
			Command: self,
			Args:    append([]string{"--name", s.Name, "--"}, append([]string{s.Config.Command}, s.Config.Args...)...),
		}
	}
	if s.Config.URL != "" {
		// HTTP/SSE MCP server — rewrite URL to point to local http-proxy.
		// User starts the proxy separately: quint-proxy http-proxy --name <name> --target <url> --port <port>
		port := 17100 + hashPort(s.Name)
		return &claudeMcpServer{
			URL:  fmt.Sprintf("http://localhost:%d", port),
			Type: s.Config.Type,
		}
	}
	return nil
}

// hashPort generates a stable port offset (0-899) from a server name.
func hashPort(name string) int {
	h := 0
	for _, c := range name {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h % 900
}

func extractOriginalCommand(cfg claudeMcpServer) (string, []string) {
	for i, a := range cfg.Args {
		if a == "--" && i+1 < len(cfg.Args) {
			return cfg.Args[i+1], cfg.Args[i+2:]
		}
	}
	return "", nil
}

func applyToClaudeConfig(servers []detectedServer) int {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".claude.json")
	data, _ := os.ReadFile(configPath)

	var config map[string]any
	json.Unmarshal(data, &config)

	applied := 0
	for _, s := range servers {
		wrapped := generateWrappedConfig(s)
		if wrapped == nil {
			continue
		}
		var wrappedMap map[string]any
		if wrapped.Command != "" {
			wrappedMap = map[string]any{"command": wrapped.Command, "args": wrapped.Args}
		} else if wrapped.URL != "" {
			wrappedMap = map[string]any{"url": wrapped.URL}
			if wrapped.Type != "" {
				wrappedMap["type"] = wrapped.Type
			}
		}
		if wrappedMap == nil {
			continue
		}

		// Try top-level mcpServers first
		mcpServers, _ := config["mcpServers"].(map[string]any)
		if mcpServers != nil {
			if _, ok := mcpServers[s.Name]; ok {
				mcpServers[s.Name] = wrappedMap
				applied++
				continue
			}
		}

		// Try project-level mcpServers
		if projects, ok := config["projects"].(map[string]any); ok {
			for _, proj := range projects {
				projMap, _ := proj.(map[string]any)
				projServers, _ := projMap["mcpServers"].(map[string]any)
				if projServers != nil {
					if _, ok := projServers[s.Name]; ok {
						projServers[s.Name] = wrappedMap
						applied++
						break
					}
				}
			}
		}
	}

	out, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, append(out, '\n'), 0o644)
	return applied
}

func filterUnproxied(servers []detectedServer) []detectedServer {
	var out []detectedServer
	for _, s := range servers {
		if !s.AlreadyProxied {
			out = append(out, s)
		}
	}
	return out
}

func filterProxied(servers []detectedServer) []detectedServer {
	var out []detectedServer
	for _, s := range servers {
		if s.AlreadyProxied {
			out = append(out, s)
		}
	}
	return out
}

// stdioAlternatives maps HTTP MCP server URL patterns to their stdio MCP server equivalents.
// When init detects an HTTP server matching a pattern, it uses the stdio version instead,
// which lets the gateway manage auth via the credential vault.
var stdioAlternatives = map[string]gateway.ServerConfig{
	"githubcopilot.com": {
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-github"},
		Env:     map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": "__CREDENTIAL:github__"},
	},
	"sentry.dev": {
		Command: "npx",
		Args:    []string{"-y", "@sentry/mcp-server-sentry"},
		Env:     map[string]string{"SENTRY_AUTH_TOKEN": "__CREDENTIAL:sentry__"},
	},
}

func buildGatewayConfig(servers []detectedServer) gateway.Config {
	cfg := gateway.Config{Servers: map[string]gateway.ServerConfig{}}
	for _, s := range servers {
		if s.Config.Command != "" {
			sc := gateway.ServerConfig{
				Command: s.Config.Command,
				Args:    s.Config.Args,
			}
			if s.Config.Env != nil {
				sc.Env = s.Config.Env
			}
			cfg.Servers[s.Name] = sc
		} else if s.Config.URL != "" {
			// Check if there's a stdio alternative for this HTTP server
			if alt := findStdioAlternative(s.Config.URL); alt != nil {
				cfg.Servers[s.Name] = *alt
			} else {
				sc := gateway.ServerConfig{
					URL:       s.Config.URL,
					Transport: s.Config.Type,
				}
				cfg.Servers[s.Name] = sc
			}
		}
	}
	return cfg
}

func findStdioAlternative(serverURL string) *gateway.ServerConfig {
	for pattern, alt := range stdioAlternatives {
		if strings.Contains(serverURL, pattern) {
			copy := alt
			// Deep copy the env map
			if alt.Env != nil {
				copy.Env = make(map[string]string, len(alt.Env))
				for k, v := range alt.Env {
					copy.Env[k] = v
				}
			}
			return &copy
		}
	}
	return nil
}

func saveOriginalConfig(dataDir string, servers []detectedServer) {
	original := map[string]any{}
	for _, s := range servers {
		entry := map[string]any{}
		if s.Config.Command != "" {
			entry["command"] = s.Config.Command
			entry["args"] = s.Config.Args
		}
		if s.Config.URL != "" {
			entry["url"] = s.Config.URL
		}
		if s.Config.Type != "" {
			entry["type"] = s.Config.Type
		}
		entry["source"] = s.Source
		original[s.Name] = entry
	}
	data, _ := json.MarshalIndent(original, "", "  ")
	os.WriteFile(filepath.Join(dataDir, "original_servers.json"), append(data, '\n'), 0o644)
}

func applyGatewayConfig(servers []detectedServer, selfPath string) {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".claude.json")
	data, _ := os.ReadFile(configPath)

	var config map[string]any
	json.Unmarshal(data, &config)

	quintEntry := map[string]any{
		"command": selfPath,
		"args":    []string{"start"},
	}

	// Replace top-level mcpServers: remove all detected, add "quint"
	topServers, _ := config["mcpServers"].(map[string]any)
	if topServers == nil {
		topServers = map[string]any{}
		config["mcpServers"] = topServers
	}

	for _, s := range servers {
		if s.Source == "global" {
			delete(topServers, s.Name)
		}
	}
	topServers["quint"] = quintEntry

	// Remove only the specific servers we detected and are moving to the gateway.
	// Preserve everything else (user-added servers like shadcn, notion direct, etc.)
	detected := map[string]bool{}
	for _, s := range servers {
		detected[s.Name] = true
	}

	if projects, ok := config["projects"].(map[string]any); ok {
		for _, proj := range projects {
			projMap, _ := proj.(map[string]any)
			projServers, _ := projMap["mcpServers"].(map[string]any)
			if projServers != nil {
				for _, s := range servers {
					if s.Source != "project" {
						continue
					}
					// Keep HTTP servers that have no stdio alternative
					if s.Config.URL != "" && findStdioAlternative(s.Config.URL) == nil {
						continue
					}
					// Only remove servers we detected — leave user-added ones alone
					if detected[s.Name] {
						delete(projServers, s.Name)
					}
				}
			}
		}
	}

	out, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, append(out, '\n'), 0o644)
}

// saveHTTPTargets persists the original URLs for HTTP MCP servers so `start` can forward to them.
func saveHTTPTargets(dataDir string, servers []detectedServer) {
	targets := map[string]httpTarget{}
	for _, s := range servers {
		if s.Config.URL != "" && !s.AlreadyProxied {
			port := 17100 + hashPort(s.Name)
			targets[s.Name] = httpTarget{
				OriginalURL: s.Config.URL,
				LocalPort:   port,
			}
		}
	}
	if len(targets) == 0 {
		return
	}
	data, _ := json.MarshalIndent(targets, "", "  ")
	os.MkdirAll(dataDir, 0o700)
	os.WriteFile(filepath.Join(dataDir, "http_targets.json"), data, 0o644)
}

type httpTarget struct {
	OriginalURL string `json:"original_url"`
	LocalPort   int    `json:"local_port"`
}

// loadHTTPTargets reads the saved HTTP proxy targets.
func loadHTTPTargets(dataDir string) map[string]httpTarget {
	path := filepath.Join(dataDir, "http_targets.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var targets map[string]httpTarget
	json.Unmarshal(data, &targets)
	return targets
}

func rolePresetNames() []string {
	names := make([]string, 0, len(rolePresets))
	for k := range rolePresets {
		names = append(names, k)
	}
	return names
}
