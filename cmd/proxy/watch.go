package main

import (
	"fmt"
	"os"
	"os/signal"
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

// runWatch handles: quint watch [flags]
// Starts an HTTP/HTTPS forward proxy with MITM TLS interception + API server.
// If a deploy token is available (--token, QUINT_DEPLOY_TOKEN, or config file),
// also registers with the cloud and forwards events.
func runWatch(args []string) {
	var policyPath string
	var tokenFlag string
	var apiURLFlag string
	var port, apiPort int

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port":
			i++
			if i < len(args) {
				port, _ = strconv.Atoi(args[i])
			}
		case "--policy":
			i++
			if i < len(args) {
				policyPath = args[i]
			}
		case "--api-port", "--dashboard-port":
			i++
			if i < len(args) {
				apiPort, _ = strconv.Atoi(args[i])
			}
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
		case "--no-dashboard", "--no-open", "--static-dir":
			// Ignored for backward compatibility
			if args[i] == "--static-dir" {
				i++ // skip the value
			}
		}
	}

	if port == 0 {
		port = 9090
	}
	if apiPort == 0 {
		apiPort = 8080
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint: failed to load policy: %v\n", err)
		os.Exit(1)
	}
	qlog.SetLevel(policy.LogLevel)
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	// --- Cloud push (opt-in via --token or QUINT_DEPLOY_TOKEN) ---
	deployToken := tokenFlag
	if deployToken == "" {
		deployToken = os.Getenv("QUINT_DEPLOY_TOKEN")
	}

	cloudAPIURL := apiURLFlag
	if cloudAPIURL == "" {
		cloudAPIURL = os.Getenv("QUINT_API_URL")
	}
	if cloudAPIURL == "" {
		cloudAPIURL = cloud.DefaultAPIURL
	}

	var forwarder *cloud.Forwarder
	var heartbeatStop chan struct{}
	var heartbeatDone chan struct{}

	if deployToken != "" {
		client := cloud.NewClient(cloudAPIURL, deployToken)
		if err := client.Register(version); err != nil {
			qlog.Warn("cloud registration failed (continuing without cloud): %v", err)
		} else {
			forwarder = cloud.NewForwarder(client)
			forwarder.Start()

			// Heartbeat goroutine
			startTime := time.Now()
			heartbeatStop = make(chan struct{})
			heartbeatDone = make(chan struct{})
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

			qlog.Info("cloud push enabled: %s", cloudAPIURL)
		}
	}

	proxyOpts := forwardproxy.Options{
		Port:    port,
		Policy:  policy,
		DataDir: dataDir,
	}

	// Hook OnEvent if cloud forwarding is active
	if forwarder != nil {
		proxyOpts.OnEvent = func(info forwardproxy.EventInfo) {
			forwarder.Enqueue(cloud.EventPayload{
				EventID:   fmt.Sprintf("evt-%d", info.Timestamp.UnixMilli()),
				Action:    info.Action,
				Agent:     info.Agent,
				Timestamp: info.Timestamp.UTC().Format(time.RFC3339),
				RiskScore: info.RiskScore,
				Blocked:   info.Blocked,
			})
		}
	}

	proxy, err := forwardproxy.New(proxyOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint: failed to create forward proxy: %v\n", err)
		os.Exit(1)
	}

	// Print setup instructions with combined CA bundle path
	bundlePath := qcrypto.BundlePath(dataDir)
	certPath := qcrypto.CertPath(dataDir)
	fmt.Println()
	fmt.Println("  Trust the CA + route traffic (paste into agent's terminal):")
	fmt.Println()
	fmt.Printf("    export SSL_CERT_FILE=%s\n", bundlePath)
	fmt.Printf("    export NODE_EXTRA_CA_CERTS=%s\n", certPath)
	fmt.Printf("    export HTTP_PROXY=http://localhost:%d\n", port)
	fmt.Printf("    export HTTPS_PROXY=http://localhost:%d\n", port)
	fmt.Println()
	fmt.Println("  Identify your agent (unique name per instance):")
	fmt.Println()
	fmt.Printf("    export HTTP_PROXY=http://my-agent@localhost:%d\n", port)
	fmt.Printf("    export HTTPS_PROXY=http://my-agent@localhost:%d\n", port)
	fmt.Println()

	// Start API server (non-blocking)
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

	// Coordinated shutdown (used by both signal handler and error path)
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			if heartbeatStop != nil {
				close(heartbeatStop)
				<-heartbeatDone
			}
			if forwarder != nil {
				forwarder.Stop()
			}
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
		qlog.Info("received signal, shutting down...")
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
