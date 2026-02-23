package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qsync "github.com/Quint-Security/quint-proxy/internal/sync"
)

// runSync handles: quint-proxy sync [--watch] [--pull-policy] [--api-url <url>] [--api-key <key>] [-v]
func runSync(args []string) {
	var policyPath, apiURL, apiKey string
	var watch, pullPolicy, verbose bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		case "--api-url":
			i++
			if i < len(args) {
				apiURL = args[i]
			}
		case "--api-key":
			i++
			if i < len(args) {
				apiKey = args[i]
			}
		case "--watch":
			watch = true
		case "--pull-policy":
			pullPolicy = true
		case "-v", "--verbose":
			verbose = true
		}
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	cfg := qsync.LoadConfig(dataDir)
	if apiURL != "" {
		cfg.APIURL = apiURL
	}
	if apiKey != "" {
		cfg.APIKey = apiKey
	}

	if cfg.APIURL == "" {
		fmt.Fprintf(os.Stderr, "API URL not configured. Set QUINT_API_URL, pass --api-url, or add api_url to ~/.quint/config.json\n")
		os.Exit(1)
	}
	if cfg.APIKey == "" {
		fmt.Fprintf(os.Stderr, "API key not configured. Set QUINT_API_KEY, pass --api-key, or add api_key to ~/.quint/config.json\n")
		os.Exit(1)
	}

	doSync := func() {
		db, err := audit.OpenDB(dataDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open audit DB: %v\n", err)
			return
		}
		defer db.Close()

		synced, err := qsync.Run(db, dataDir, cfg.APIURL, cfg.APIKey, verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sync error: %v\n", err)
			return
		}

		if synced > 0 {
			fmt.Printf("Synced %d entries to %s\n", synced, cfg.APIURL)
		} else {
			fmt.Println("Already up to date")
		}

		if pullPolicy {
			fmt.Println("Checking for policy updates...")
			if _, err := qsync.PullPolicy(dataDir, cfg.APIURL, cfg.APIKey); err != nil {
				fmt.Fprintf(os.Stderr, "  Failed to pull policy: %v\n", err)
			}
		}
	}

	doSync()

	if watch {
		fmt.Println("Watching for new entries (Ctrl+C to stop)...")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				doSync()
			case <-sigCh:
				fmt.Println("\nSync watch stopped")
				return
			}
		}
	}
}
