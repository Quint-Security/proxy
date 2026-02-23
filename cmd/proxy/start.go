package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/credential"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/gateway"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

// runStart handles: quint-proxy start [--policy <path>] [--agent <name>]
// Starts the MCP gateway multiplexer. All downstream servers defined in
// servers.json are started and presented as one unified MCP server via stdio.
func runStart(args []string) {
	var policyPath, agentFlag string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		case "--agent":
			i++
			if i < len(args) {
				agentFlag = args[i]
			}
		}
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	qlog.SetLevel(policy.LogLevel)
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	// Load gateway config
	cfg, err := gateway.LoadConfig(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No servers.json found in %s.\nRun `quint-proxy init --apply` to generate it.\n", dataDir)
		os.Exit(1)
	}

	if len(cfg.Servers) == 0 {
		fmt.Println("No servers configured in servers.json.")
		return
	}

	// Set up audit logger
	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load keys: %v\n", err)
		os.Exit(1)
	}
	auditDB, err := audit.OpenDB(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open audit DB: %v\n", err)
		os.Exit(1)
	}
	defer auditDB.Close()

	policyBytes, _ := json.Marshal(policy)
	var policyMap map[string]any
	json.Unmarshal(policyBytes, &policyMap)
	logger := audit.NewLogger(auditDB, kp.PrivateKey, kp.PublicKey, policyMap)

	// Set up risk engine
	behaviorDB, _ := risk.OpenBehaviorDB(dataDir)
	if behaviorDB != nil {
		defer behaviorDB.Close()
	}
	riskEngine := risk.NewEngine(&risk.EngineOpts{BehaviorDB: behaviorDB})

	// Resolve agent identity
	agentName := agentFlag
	if agentName == "" {
		agentName = os.Getenv("QUINT_AGENT")
	}

	var identity *auth.Identity
	if agentName != "" {
		authDB, err := auth.OpenDB(dataDir)
		if err == nil {
			defer authDB.Close()
			identity, err = authDB.ResolveAgentByName(agentName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "quint: %v\n", err)
				os.Exit(1)
			}
			qlog.Info("running as agent %q", identity.AgentName)
		}
	}

	// Open credential store for HTTP backends
	encKey := credential.DeriveEncryptionKey(passphrase, kp.PrivateKey)
	credStore, err := credential.OpenStore(dataDir, encKey)
	if err != nil {
		qlog.Error("credential store unavailable: %v (HTTP backends won't have auth)", err)
	}
	if credStore != nil {
		defer credStore.Close()
	}

	// Create and start gateway
	gw, err := gateway.New(cfg, gateway.GatewayOpts{
		Policy:     policy,
		Logger:     logger,
		RiskEngine: riskEngine,
		Identity:   identity,
		CredStore:  credStore,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create gateway: %v\n", err)
		os.Exit(1)
	}

	if err := gw.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start gateway: %v\n", err)
		os.Exit(1)
	}

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		gw.Stop()
		os.Exit(0)
	}()

	// Run the stdio MCP server (blocks until stdin closes)
	gw.Run()
	gw.Stop()
}
