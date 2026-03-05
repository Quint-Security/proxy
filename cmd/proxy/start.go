package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/credential"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/gateway"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
	"github.com/Quint-Security/quint-proxy/internal/stream"
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

	// Set up risk engine (loads thresholds, custom patterns, and remote scorer from policy)
	behaviorDB, _ := risk.OpenBehaviorDB(dataDir)
	if behaviorDB != nil {
		defer behaviorDB.Close()
	}
	riskEngine := risk.NewEngineFromPolicy(policy.Risk, behaviorDB)

	// Always open auth DB for session identity resolution
	authDB, dbErr := auth.OpenDB(dataDir)
	if dbErr != nil {
		qlog.Warn("auth DB unavailable: %v (agent identity resolution disabled)", dbErr)
	}
	if authDB != nil {
		defer authDB.Close()
	}

	// Resolve startup agent identity
	agentName := agentFlag
	if agentName == "" {
		agentName = os.Getenv("QUINT_AGENT")
	}

	var identity *auth.Identity
	if agentName != "" && authDB != nil {
		identity, err = authDB.ResolveAgentByName(agentName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "quint: %v\n", err)
			os.Exit(1)
		}
		identity.Source = "cli_flag"
		if agentFlag == "" {
			identity.Source = "env_var"
		}
		qlog.Info("running as agent %q (source=%s)", identity.AgentName, identity.Source)
	}

	// Initialize cloud auth if configured
	var tokenResolver *auth.TokenResolver
	var cloudClient *auth.AuthServiceClient
	if policy.AuthService != nil && policy.AuthService.Enabled {
		refreshTTL := 5 * time.Minute
		if policy.AuthService.KeyRefreshSeconds > 0 {
			refreshTTL = time.Duration(policy.AuthService.KeyRefreshSeconds) * time.Second
		}
		cloudValidator := auth.NewCloudValidator(&auth.CloudValidatorConfig{
			BaseURL:       policy.AuthService.BaseURL,
			CustomerID:    policy.AuthService.CustomerID,
			TimeoutMs:     policy.AuthService.TimeoutMs,
			KeyRefreshTTL: refreshTTL,
		})
		cloudClient = auth.NewAuthServiceClient(policy.AuthService.BaseURL, policy.AuthService.TimeoutMs)
		tokenResolver = auth.NewTokenResolver(authDB, cloudValidator, cloudClient)
		qlog.Info("cloud auth enabled: %s", policy.AuthService.BaseURL)
	} else {
		tokenResolver = auth.NewTokenResolver(authDB, nil, nil)
	}

	// Check QUINT_TOKEN env for cloud JWT tokens (takes precedence over --agent)
	if token := os.Getenv("QUINT_TOKEN"); token != "" && auth.IsCloudToken(token) {
		resolved, tokenErr := tokenResolver.ResolveToken(token)
		if tokenErr != nil {
			fmt.Fprintf(os.Stderr, "quint: invalid cloud token: %v\n", tokenErr)
			os.Exit(1)
		}
		if resolved != nil {
			resolved.Source = "cloud_token"
			identity = resolved
			qlog.Info("authenticated via cloud token (type=%s, agent_id=%s)", resolved.TokenType, resolved.AgentID)
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

	// Initialize Kafka producer if configured
	var kafkaProd *stream.Producer
	if policy.Kafka != nil && policy.Kafka.Enabled {
		kafkaProd = stream.NewProducer(&stream.ProducerConfig{
			Brokers:     policy.Kafka.Brokers,
			Enabled:     policy.Kafka.Enabled,
			Async:       policy.Kafka.Async,
			BatchSize:   policy.Kafka.BatchSize,
			BatchTimeMs: policy.Kafka.BatchTimeMs,
		})
		if kafkaProd != nil {
			defer kafkaProd.Close()
		}
	}

	// Create and start gateway
	gw, err := gateway.New(cfg, gateway.GatewayOpts{
		Policy:        policy,
		Logger:        logger,
		RiskEngine:    riskEngine,
		Identity:      identity,
		CredStore:     credStore,
		KafkaProducer: kafkaProd,
		TokenResolver: tokenResolver,
		CloudClient:   cloudClient,
		AuthDB:        authDB,
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
