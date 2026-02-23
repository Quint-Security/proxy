package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// runStart handles: quint-proxy start [--policy <path>]
// Starts HTTP proxies for all wrapped HTTP MCP servers.
func runStart(args []string) {
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
	qlog.SetLevel(policy.LogLevel)

	// Detect which servers need HTTP proxies
	servers := detectMcpServers()
	var httpServers []detectedServer
	for _, s := range servers {
		if s.AlreadyProxied && s.Config.URL != "" {
			// This is an HTTP server already proxied through quint — find its original target
			httpServers = append(httpServers, s)
		}
	}

	// Also find un-proxied HTTP servers (in case init hasn't been applied yet)
	for _, s := range servers {
		if !s.AlreadyProxied && s.Config.URL != "" {
			httpServers = append(httpServers, s)
		}
	}

	if len(httpServers) == 0 {
		fmt.Println("No HTTP MCP servers found to proxy.")
		fmt.Println("Run `quint-proxy init --apply` first to configure your MCP servers.")
		return
	}

	fmt.Printf("Starting %d HTTP proxy(ies)...\n\n", len(httpServers))

	// Launch each proxy
	for _, s := range httpServers {
		target := s.Config.URL
		port := 17100 + hashPort(s.Name)

		// If already proxied, target is the localhost URL — we need the original
		// For now, start with the servers that haven't been proxied
		if s.AlreadyProxied {
			// Extract original URL from the before-proxy state
			// The original URL was replaced — we can't recover it from the config.
			// Skip already-proxied servers.
			continue
		}

		proxyArgs := []string{
			"--name", s.Name,
			"--target", target,
			"--port", strconv.Itoa(port),
		}
		if policyPath != "" {
			proxyArgs = append(proxyArgs, "--policy", policyPath)
		}

		fmt.Printf("  %s: http://localhost:%d → %s\n", s.Name, port, target)
		go func(name string, a []string) {
			runHTTPProxy(a)
		}(s.Name, proxyArgs)
	}

	fmt.Println("\nAll proxies running. Press Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	fmt.Println("\nStopping proxies...")
}
