package main

import (
	"fmt"
	"os"
	"path/filepath"

	qcrypto "github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runEnv handles: quint env [--proxy] [--port PORT] [--agent NAME]
// Prints export statements for CA trust env vars.
// With --proxy, also prints HTTP_PROXY/HTTPS_PROXY for routing CLI traffic.
//
// Usage:
//
//	eval $(quint env)          # CA trust only (safe for all shells)
//	eval $(quint env --proxy)  # CA trust + proxy routing for AI agent terminals
func runEnv(args []string) {
	port := 9090
	agent := ""
	includeProxy := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--proxy":
			includeProxy = true
		case "--port":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &port)
			}
		case "--agent":
			i++
			if i < len(args) {
				agent = args[i]
			}
		}
	}

	// Resolve data dir to find CA certs
	policy, _ := intercept.LoadPolicy("")
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	// Prefer user-readable ~/.quint/ca/ over root-owned /var/lib/quint/ca/.
	// The daemon copies certs to ~/.quint/ca/ during setup for user-space access.
	home, _ := os.UserHomeDir()
	userCADir := filepath.Join(home, ".quint", "ca")
	if _, err := os.Stat(filepath.Join(userCADir, "quint-ca.crt")); err == nil {
		dataDir = filepath.Join(home, ".quint")
	} else if _, err := os.Stat("/var/lib/quint/ca"); err == nil {
		dataDir = "/var/lib/quint"
	}

	bundlePath := qcrypto.BundlePath(dataDir)
	certPath := qcrypto.CertPath(dataDir)

	// Verify cert exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "# Error: CA cert not found at %s\n", certPath)
		fmt.Fprintf(os.Stderr, "# Run 'quint watch' or 'quint daemon' first to generate it.\n")
		os.Exit(1)
	}

	// Ensure paths are absolute
	if !filepath.IsAbs(bundlePath) {
		abs, err := filepath.Abs(bundlePath)
		if err == nil {
			bundlePath = abs
		}
	}
	if !filepath.IsAbs(certPath) {
		abs, err := filepath.Abs(certPath)
		if err == nil {
			certPath = abs
		}
	}

	if includeProxy {
		// Blanket proxy mode — route everything through the proxy
		proxyURL := fmt.Sprintf("http://localhost:%d", port)
		if agent != "" {
			proxyURL = fmt.Sprintf("http://%s@localhost:%d", agent, port)
		}
		fmt.Printf("export SSL_CERT_FILE=%s\n", bundlePath)
		fmt.Printf("export NODE_EXTRA_CA_CERTS=%s\n", certPath)
		fmt.Printf("export HTTP_PROXY=%s\n", proxyURL)
		fmt.Printf("export HTTPS_PROXY=%s\n", proxyURL)
	} else {
		// Default: CA trust + agent wrappers (same as env.sh)
		agents := detectAgents()
		fmt.Print(generateEnvSh(bundlePath, certPath, port, agents))
	}
}
