package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/cloud"
	qcrypto "github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/dashboard"
	"github.com/Quint-Security/quint-proxy/internal/forwardproxy"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// runDaemon handles: quint daemon [flags]
// Runs the forward proxy as a system daemon with cloud registration,
// heartbeat, and event forwarding (enterprise mode).
func runDaemon(args []string) {
	var (
		tokenFlag  string
		apiURLFlag string
		configPath string
		policyPath string
		port       int
		apiPort    int
	)

	// Parse flags (same manual iteration pattern as runWatch)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--token":
			i++
			if i < len(args) {
				tokenFlag = args[i]
			}
		case "--api-url":
			i++
			if i < len(args) {
				apiURLFlag = args[i]
			}
		case "--config":
			i++
			if i < len(args) {
				configPath = args[i]
			}
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		case "--port":
			i++
			if i < len(args) {
				port, _ = strconv.Atoi(args[i])
			}
		case "--api-port":
			i++
			if i < len(args) {
				apiPort, _ = strconv.Atoi(args[i])
			}
		}
	}

	// Load daemon config from file
	daemonCfg, err := cloud.LoadDaemonConfig(configPath)
	if err != nil && configPath != "" {
		// Explicit config path was given but failed — fatal
		fmt.Fprintf(os.Stderr, "quint: failed to load config %s: %v\n", configPath, err)
		os.Exit(1)
	}
	if daemonCfg == nil {
		// No config file found; use defaults
		daemonCfg = &cloud.DaemonConfig{
			APIURL: cloud.DefaultAPIURL,
		}
	}

	// Flags override config file values
	if tokenFlag != "" {
		daemonCfg.Token = tokenFlag
	}
	if apiURLFlag != "" {
		daemonCfg.APIURL = apiURLFlag
	}

	// Token is required (flag > config file > env var, env already applied in LoadDaemonConfig)
	if daemonCfg.Token == "" {
		// Last resort: check env directly (for case where config file was not loaded)
		if t := os.Getenv("QUINT_DEPLOY_TOKEN"); t != "" {
			daemonCfg.Token = t
		}
	}
	if daemonCfg.Token == "" {
		fmt.Fprintf(os.Stderr, "quint: daemon requires a deploy token (--token, config file, or QUINT_DEPLOY_TOKEN env)\n")
		os.Exit(1)
	}

	// Load proxy policy
	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint: failed to load policy: %v\n", err)
		os.Exit(1)
	}

	// Set log level (flag config overrides policy)
	logLevel := policy.LogLevel
	if daemonCfg.LogLevel != "" {
		logLevel = daemonCfg.LogLevel
	}
	qlog.SetLevel(logLevel)

	dataDir := intercept.ResolveDataDir(policy.DataDir)

	// Daemon mode: if dataDir is still relative (e.g. LaunchDaemon running as root
	// with no HOME), force an absolute path so CA/audit can be created.
	if !filepath.IsAbs(dataDir) {
		dataDir = "/var/lib/quint"
	}

	if port == 0 {
		port = 9090
	}
	if apiPort == 0 {
		apiPort = 8080
	}

	qlog.Info("starting daemon mode (version=%s)", version)

	// --- Cloud registration ---
	client := cloud.NewClient(daemonCfg.APIURL, daemonCfg.Token)
	if err := client.Register(version); err != nil {
		fmt.Fprintf(os.Stderr, "quint: cloud registration failed: %v\n", err)
		os.Exit(1)
	}

	// --- Event forwarder ---
	forwarder := cloud.NewForwarder(client)
	forwarder.Start()

	// --- Heartbeat goroutine ---
	startTime := time.Now()
	heartbeatStop := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				uptime := int64(time.Since(startTime).Seconds())
				eventsBuffered := forwarder.BufferLen()
				if err := client.Heartbeat(version, uptime, 0, eventsBuffered); err != nil {
					qlog.Warn("heartbeat failed: %v", err)
				}
			case <-heartbeatStop:
				return
			}
		}
	}()

	// --- Forward proxy ---
	proxy, err := forwardproxy.New(forwardproxy.Options{
		Port:    port,
		Policy:  policy,
		DataDir: dataDir,
		OnEvent: func(info forwardproxy.EventInfo) {
			forwarder.Enqueue(cloud.EventPayload{
				EventID:   fmt.Sprintf("evt-%d", info.Timestamp.UnixMilli()),
				Action:    info.Action,
				Agent:     info.Agent,
				Timestamp: info.Timestamp.UTC().Format(time.RFC3339),
				RiskScore: info.RiskScore,
				Blocked:   info.Blocked,
			})
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint: failed to create forward proxy: %v\n", err)
		forwarder.Stop()
		os.Exit(1)
	}

	// Print setup instructions
	bundlePath := qcrypto.BundlePath(dataDir)
	certPath := qcrypto.CertPath(dataDir)
	fmt.Println()
	fmt.Println("  Daemon mode — trust the CA + route traffic:")
	fmt.Println()
	fmt.Printf("    export SSL_CERT_FILE=%s\n", bundlePath)
	fmt.Printf("    export NODE_EXTRA_CA_CERTS=%s\n", certPath)
	fmt.Printf("    export HTTP_PROXY=http://localhost:%d\n", port)
	fmt.Printf("    export HTTPS_PROXY=http://localhost:%d\n", port)
	fmt.Println()

	// --- API server ---
	var apiSrv *dashboard.Server
	apiSrv, err = dashboard.NewWithOpts(dashboard.Opts{
		DataDir: dataDir,
		Policy:  policy,
	})
	if err != nil {
		qlog.Error("API server failed to start: %v", err)
	} else {
		if err := apiSrv.StartAsync(apiPort); err != nil {
			qlog.Error("API server listen error: %v", err)
			apiSrv = nil
		} else {
			fmt.Printf("  API: http://localhost:%d\n", apiPort)
			fmt.Println()
		}
	}

	qlog.Info("daemon running: proxy=:%d, api=:%d, cloud=%s", port, apiPort, daemonCfg.APIURL)

	// --- Coordinated shutdown (used by both signal handler and error path) ---
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			close(heartbeatStop)
			<-heartbeatDone
			forwarder.Stop()
			if apiSrv != nil {
				apiSrv.Shutdown()
			}
			proxy.Close()
		})
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		qlog.Info("received signal, shutting down daemon...")
		shutdown()
		os.Exit(0)
	}()

	// Blocking — forward proxy runs in foreground
	if err := proxy.Start(); err != nil {
		qlog.Error("forward proxy error: %v", err)
		shutdown()
		os.Exit(1)
	}
}
