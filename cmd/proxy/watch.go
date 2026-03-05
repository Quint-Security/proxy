package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	qcrypto "github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/dashboard"
	"github.com/Quint-Security/quint-proxy/internal/forwardproxy"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// runWatch handles: quint watch [flags]
// Starts an HTTP/HTTPS forward proxy with MITM TLS interception + dashboard.
func runWatch(args []string) {
	var policyPath, staticDir string
	var port, dashboardPort int
	var noDashboard, noOpen bool

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
		case "--dashboard-port":
			i++
			if i < len(args) {
				dashboardPort, _ = strconv.Atoi(args[i])
			}
		case "--static-dir":
			i++
			if i < len(args) {
				staticDir = args[i]
			}
		case "--no-dashboard":
			noDashboard = true
		case "--no-open":
			noOpen = true
		}
	}

	if port == 0 {
		port = 9090
	}
	if dashboardPort == 0 {
		dashboardPort = 8080
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint: failed to load policy: %v\n", err)
		os.Exit(1)
	}
	qlog.SetLevel(policy.LogLevel)
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	proxy, err := forwardproxy.New(forwardproxy.Options{
		Port:    port,
		Policy:  policy,
		DataDir: dataDir,
	})
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

	// Start dashboard (non-blocking)
	var dashSrv *dashboard.Server
	if !noDashboard {
		dashSrv, err = dashboard.NewWithOpts(dashboard.Opts{
			DataDir:   dataDir,
			Policy:    policy,
			StaticDir: staticDir,
		})
		if err != nil {
			qlog.Error("dashboard failed to start: %v", err)
		} else {
			if err := dashSrv.StartAsync(dashboardPort); err != nil {
				qlog.Error("dashboard listen error: %v", err)
				dashSrv = nil
			} else {
				fmt.Printf("  Dashboard: http://localhost:%d\n", dashboardPort)
				fmt.Println()
				if !noOpen {
					go openBrowser(fmt.Sprintf("http://localhost:%d", dashboardPort))
				}
			}
		}
	}

	// Signal handling — coordinated shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		qlog.Info("received signal, shutting down...")
		if dashSrv != nil {
			dashSrv.Shutdown()
		}
		proxy.Close()
		os.Exit(0)
	}()

	// Blocking — forward proxy runs in foreground
	if err := proxy.Start(); err != nil {
		qlog.Error("forward proxy error: %v", err)
		if dashSrv != nil {
			dashSrv.Shutdown()
		}
		proxy.Close()
		os.Exit(1)
	}
}
