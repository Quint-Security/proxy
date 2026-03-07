package main

import (
	"fmt"
	"os"
	"path/filepath"

	qcrypto "github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

// runEnv handles: quint env [--port PORT] [--agent NAME]
// Prints export statements for proxy env vars.
// Usage: eval $(quint env)
func runEnv(args []string) {
	port := 9090
	agent := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
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

	// Check if daemon data dir exists (installed via install script)
	if _, err := os.Stat("/var/lib/quint/ca"); err == nil {
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

	// Build proxy URL with optional agent name
	proxyURL := fmt.Sprintf("http://localhost:%d", port)
	if agent != "" {
		proxyURL = fmt.Sprintf("http://%s@localhost:%d", agent, port)
	}

	// Ensure bundle path is absolute
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

	fmt.Printf("export SSL_CERT_FILE=%s\n", bundlePath)
	fmt.Printf("export NODE_EXTRA_CA_CERTS=%s\n", certPath)
	fmt.Printf("export HTTP_PROXY=%s\n", proxyURL)
	fmt.Printf("export HTTPS_PROXY=%s\n", proxyURL)
}
