package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Quint-Security/quint-proxy/internal/crypto"
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

func runInit(args []string) {
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
		return
	}

	if revert {
		runRevert(dryRun)
		return
	}

	fmt.Println("Quint Setup")

	// Detect MCP servers
	servers := detectMcpServers()
	if len(servers) == 0 {
		fmt.Println("  No MCP servers found in ~/.claude.json")
		fmt.Println("  Add MCP servers to Claude Code first, then run quint-proxy init again.")
		return
	}

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

	serverPolicies := make([]intercept.ServerPolicy, 0, len(servers)+1)
	for _, s := range servers {
		sp := intercept.ServerPolicy{Server: s.Name, DefaultAction: intercept.ActionAllow, Tools: []intercept.ToolRule{}}
		if role != nil {
			sp.DefaultAction = role.DefaultAction
			sp.Tools = append(sp.Tools, role.Tools...)
		}
		serverPolicies = append(serverPolicies, sp)
	}
	serverPolicies = append(serverPolicies, intercept.ServerPolicy{Server: "*", DefaultAction: intercept.ActionAllow, Tools: []intercept.ToolRule{}})

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
	} else {
		fmt.Printf("  Policy: %s (exists, not overwritten)\n", policyPath)
	}

	// Show or apply config changes
	toWrap := filterUnproxied(servers)
	if len(toWrap) > 0 {
		fmt.Printf("\n  Config changes needed for %d server(s):\n\n", len(toWrap))
		for _, s := range toWrap {
			wrapped := generateWrappedConfig(s)
			if wrapped == nil {
				continue
			}
			var before, after []byte
			if s.Config.Command != "" {
				before, _ = json.Marshal(map[string]any{"command": s.Config.Command, "args": s.Config.Args})
				after, _ = json.Marshal(map[string]any{"command": wrapped.Command, "args": wrapped.Args})
			} else if s.Config.URL != "" {
				before, _ = json.Marshal(map[string]any{"url": s.Config.URL})
				afterMap := map[string]any{"url": wrapped.URL}
				if wrapped.Type != "" {
					afterMap["type"] = wrapped.Type
				}
				after, _ = json.Marshal(afterMap)
			}
			fmt.Printf("    %s:\n      before: %s\n      after:  %s\n\n", s.Name, before, after)
		}

		if apply && !dryRun {
			applied := applyToClaudeConfig(toWrap)
			fmt.Printf("  Applied %d change(s) to ~/.claude.json\n", applied)
			fmt.Println("  Restart Claude Code for changes to take effect.")
		} else if dryRun {
			fmt.Println("  (dry run — no changes made)")
		} else {
			fmt.Println("  Run with --apply to modify ~/.claude.json automatically.")
			fmt.Println("  Run with --revert to undo Quint proxying.")
		}
	} else {
		fmt.Println("\n  All servers are already proxied through Quint.")
	}

	fmt.Println("\n  Setup complete.")
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

func detectMcpServers() []detectedServer {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".claude.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}

	var servers []detectedServer
	seen := map[string]bool{}

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
	if strings.HasSuffix(srv.Command, "quint-proxy") || srv.Command == "quint" {
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

func rolePresetNames() []string {
	names := make([]string, 0, len(rolePresets))
	for k := range rolePresets {
		names = append(names, k)
	}
	return names
}
