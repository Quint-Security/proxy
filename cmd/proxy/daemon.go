package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/cloud"
	qcrypto "github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/dashboard"
	"github.com/Quint-Security/quint-proxy/internal/forwardproxy"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/pac"
	"github.com/Quint-Security/quint-proxy/internal/procscan"
)

// runDaemon handles: quint daemon [flags]
// Runs the forward proxy as a system daemon with cloud registration,
// heartbeat, and event forwarding (enterprise mode).
func runDaemon(args []string) {
	var (
		tokenFlag    string
		apiURLFlag   string
		configPath   string
		policyPath   string
		port         int
		apiPort      int
		writePACOnly bool
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
		case "--write-pac":
			writePACOnly = true
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

	// Set up log rotation — default to /var/log/quint/quint.log for daemon mode.
	// Override with QUINT_LOG_FILE env var.
	logFile := os.Getenv("QUINT_LOG_FILE")
	if logFile == "" {
		logFile = "/var/log/quint/quint.log"
	}
	_ = os.MkdirAll(filepath.Dir(logFile), 0o755)
	qlog.SetupFileLogging(logFile)

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

	// --- PAC file generation ---
	customDomains, _ := pac.LoadCustomDomains(dataDir)
	allDomains := pac.MergeDomains(pac.DefaultDomains, customDomains)
	pacPath := filepath.Join(dataDir, "proxy.pac")
	if count, err := pac.WritePACFile(pacPath, port, allDomains); err != nil {
		qlog.Warn("failed to write PAC file: %v", err)
	} else {
		qlog.Info("wrote PAC file: %s (%d domains)", pacPath, count)
	}

	if writePACOnly {
		// Copy PAC to user home if running under sudo
		if realUser := os.Getenv("SUDO_USER"); realUser != "" {
			realHome := os.Getenv("HOME")
			if realUser != "" {
				realHome = "/Users/" + realUser // macOS default
				if _, err := os.Stat(realHome); err != nil {
					realHome = "/home/" + realUser // Linux fallback
				}
			}
			userPACDir := filepath.Join(realHome, ".quint")
			_ = os.MkdirAll(userPACDir, 0o755)
			userPACPath := filepath.Join(userPACDir, "proxy.pac")
			if data, err := os.ReadFile(pacPath); err == nil {
				_ = os.WriteFile(userPACPath, data, 0o644)
				qlog.Info("copied PAC file to %s", userPACPath)
			}
		}
		return
	}

	qlog.Info("starting daemon mode (version=%s)", version)

	// --- Cloud registration ---
	client := cloud.NewClient(daemonCfg.APIURL, daemonCfg.Token)
	if err := client.Register(version); err != nil {
		fmt.Fprintf(os.Stderr, "quint: cloud registration failed: %v\n", err)
		os.Exit(1)
	}

	// --- Cloud policy enforcer ---
	enforcer := cloud.NewEnforcer(dataDir)

	// --- Event forwarder ---
	forwarder := cloud.NewForwarder(client)
	forwarder.Start()

	// Declare apiSrv early so the heartbeat goroutine can record heartbeats.
	var apiSrv *dashboard.Server

	// --- Heartbeat goroutine (with policy sync) ---
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
				result, err := client.Heartbeat(version, uptime, 0, eventsBuffered)
				if err != nil {
					qlog.Warn("heartbeat failed: %v", err)
				} else if result != nil {
					if apiSrv != nil {
						apiSrv.RecordHeartbeat()
					}
					// Policy version changed — fetch new policies
					if result.PolicyHash != "" && result.PolicyHash != enforcer.Hash() {
						policies, newHash, fetchErr := client.FetchPolicies(enforcer.Hash())
						if fetchErr != nil {
							qlog.Warn("policy fetch failed: %v", fetchErr)
						} else if policies != nil {
							enforcer.Update(policies, newHash)
							qlog.Info("updated cloud policies: %d policies, hash=%s", len(policies), newHash)
						}
					}
					// Domain list update — regenerate PAC file
					if len(result.Domains) > 0 {
						if err := pac.SaveCustomDomains(dataDir, result.Domains); err != nil {
							qlog.Warn("failed to save custom domains: %v", err)
						} else {
							merged := pac.MergeDomains(pac.DefaultDomains, result.Domains)
							if _, err := pac.WritePACFile(filepath.Join(dataDir, "proxy.pac"), port, merged); err != nil {
								qlog.Warn("failed to update PAC file: %v", err)
							} else {
								qlog.Info("updated PAC file with %d domains from cloud", len(result.Domains))
							}
						}
					}
				}
			case <-heartbeatStop:
				return
			}
		}
	}()

	// --- Graph push goroutine (push agent graphs to cloud every 30s) ---
	graphStop := make(chan struct{})
	graphDone := make(chan struct{})
	go func() {
		defer close(graphDone)
		// Wait for API server to start
		time.Sleep(5 * time.Second)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		pushGraphs := func() {
			// Fetch graphs from local dashboard API
			resp, err := http.Get(fmt.Sprintf("http://localhost:%d/api/agents/graphs", apiPort))
			if err != nil {
				return
			}
			defer resp.Body.Close()

			var result struct {
				Graphs []json.RawMessage `json:"graphs"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Graphs) == 0 {
				return
			}

			var payloads []cloud.GraphPayload
			for _, raw := range result.Graphs {
				var g struct {
					ID            string          `json:"id"`
					RootAgentID   string          `json:"rootAgentId"`
					RootAgentName string          `json:"rootAgentName"`
					Status        string          `json:"status"`
					TotalNodes    int             `json:"totalNodes"`
					Nodes         json.RawMessage `json:"nodes"`
					StartedAt     string          `json:"startedAt"`
					CompletedAt   string          `json:"completedAt"`
				}
				if err := json.Unmarshal(raw, &g); err != nil {
					continue
				}
				payloads = append(payloads, cloud.GraphPayload{
					ID:            g.ID,
					RootAgentID:   g.RootAgentID,
					RootAgentName: g.RootAgentName,
					Status:        g.Status,
					TotalNodes:    g.TotalNodes,
					Nodes:         raw, // send the full graph JSON as nodes
					StartedAt:     g.StartedAt,
					CompletedAt:   g.CompletedAt,
				})
			}

			if len(payloads) > 0 {
				if err := client.PushGraphs(payloads); err != nil {
					qlog.Warn("graph push failed: %v", err)
				}
			}
		}

		pushGraphs() // push immediately on start
		for {
			select {
			case <-ticker.C:
				pushGraphs()
			case <-graphStop:
				return
			}
		}
	}()

	// --- Process scanner ---
	scanner := procscan.NewScanner(5*time.Second, func(agents []procscan.AgentProcess) {
		entries := make([]cloud.AgentInventoryEntry, len(agents))
		for i, a := range agents {
			entries[i] = cloud.AgentInventoryEntry{
				Platform:   a.Platform,
				PID:        a.PID,
				BinaryPath: a.BinaryPath,
				State:      a.State,
				CPUPercent: a.CPUPercent,
				MemoryMB:   a.MemoryMB,
			}
			if !a.StartedAt.IsZero() {
				entries[i].StartedAt = a.StartedAt.UTC().Format(time.RFC3339)
			}
		}
		if err := client.ReportAgentInventory(entries); err != nil {
			qlog.Warn("agent inventory report failed: %v", err)
		}
	})
	scanCtx, scanCancel := context.WithCancel(context.Background())
	go scanner.Start(scanCtx)

	// --- Forward proxy ---
	proxy, err := forwardproxy.New(forwardproxy.Options{
		Port:     port,
		Policy:   policy,
		DataDir:  dataDir,
		Enforcer: newEnforcerAdapter(enforcer),
		OnEvent: func(info forwardproxy.EventInfo) {
			// Skip TLS handshake noise — adds no value to cloud events
			if strings.Contains(info.Action, "connect.root") {
				return
			}
			metadata := map[string]string{}
			if info.ProcessName != "" {
				metadata["process_name"] = info.ProcessName
			}
			if info.ProcessPID > 0 {
				metadata["process_pid"] = strconv.Itoa(info.ProcessPID)
			}
			if info.ProcessPath != "" {
				metadata["process_path"] = info.ProcessPath
			}
			if info.Platform != "" {
				metadata["platform"] = info.Platform
			}
			forwarder.Enqueue(cloud.EventPayload{
				EventID:   fmt.Sprintf("evt-%d", info.Timestamp.UnixMilli()),
				Action:    info.Action,
				Agent:     info.Agent,
				Timestamp: info.Timestamp.UTC().Format(time.RFC3339),
				RiskScore: info.RiskScore,
				Blocked:   info.Blocked,
				Metadata:  metadata,
			})
		},
		OnToolCall: func(evt forwardproxy.AgentToolEvent) {
			agent := evt.ProcessName
			if agent == "" {
				agent = evt.Agent
			}
			if agent == "" && evt.Provider != "" {
				agent = evt.Provider
			}
			if agent == "" && evt.Model != "" {
				agent = evt.Model
			}

			metadata := map[string]string{}
			if evt.ToolArgs != "" {
				metadata["args"] = evt.ToolArgs
			}
			if evt.ToolResult != "" {
				result := evt.ToolResult
				if len(result) > 1024 {
					result = result[:1024] + "..."
				}
				metadata["result"] = result
			}
			if evt.Model != "" {
				metadata["model"] = evt.Model
			}
			if evt.Provider != "" {
				metadata["provider"] = evt.Provider
			}
			if evt.ProcessName != "" {
				metadata["process_name"] = evt.ProcessName
			}
			if evt.ProcessPID > 0 {
				metadata["process_pid"] = strconv.Itoa(evt.ProcessPID)
			}
			if evt.Platform != "" {
				metadata["platform"] = evt.Platform
			}

			// Cloud policy enforcement metadata
			if enforcer != nil {
				enfResult := enforcer.Evaluate(evt.ToolName, agent, evt.ToolArgs)
				if enfResult.PolicyID != "" {
					metadata["policy_id"] = enfResult.PolicyID
					metadata["policy_name"] = enfResult.PolicyName
					metadata["enforcement_action"] = enfResult.Action
				}
			}

			forwarder.Enqueue(cloud.EventPayload{
				EventID:   evt.EventID,
				Action:    fmt.Sprintf("tool:%s", evt.ToolName),
				Agent:     agent,
				Timestamp: evt.Timestamp.UTC().Format(time.RFC3339),
				RiskScore: &evt.RiskScore,
				Blocked:   evt.Blocked,
				Metadata:  metadata,
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
	apiSrv, err = dashboard.NewWithOpts(dashboard.Opts{
		DataDir:    dataDir,
		Policy:     policy,
		Version:    version,
		ProxyPort:  port,
		CACertPath: qcrypto.CertPath(dataDir),
	})
	if err != nil {
		qlog.Error("API server failed to start: %v", err)
	} else {
		apiSrv.SetCloudStatus(true) // daemon mode always has cloud
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
			scanCancel()
			scanner.Stop()
			close(heartbeatStop)
			<-heartbeatDone
			close(graphStop)
			<-graphDone
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
