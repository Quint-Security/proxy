package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Quint-Security/quint-proxy/internal/httpproxy"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// runHTTPProxy starts the HTTP proxy mode.
// Args: --name <server> --target <url> --port <port> [--auth] [--policy <path>]
func runHTTPProxy(args []string) {
	var serverName, targetURL, policyPath string
	var port int
	var requireAuth bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			i++
			if i < len(args) {
				serverName = args[i]
			}
		case "--target":
			i++
			if i < len(args) {
				targetURL = args[i]
			}
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
		case "--auth":
			requireAuth = true
		}
	}

	if serverName == "" || targetURL == "" {
		fmt.Fprintf(os.Stderr, "Usage: quint-proxy http-proxy --name <server> --target <url> [--port <port>] [--auth] [--policy <path>]\n")
		os.Exit(1)
	}
	if port == 0 {
		port = 8888
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint: failed to load policy: %v\n", err)
		os.Exit(1)
	}
	qlog.SetLevel(policy.LogLevel)

	proxy, err := httpproxy.New(httpproxy.Options{
		ServerName:  serverName,
		Port:        port,
		TargetURL:   targetURL,
		Policy:      policy,
		RequireAuth: requireAuth,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "quint: failed to create HTTP proxy: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		qlog.Info("received signal, shutting down HTTP proxy")
		proxy.Close()
		os.Exit(0)
	}()

	if err := proxy.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "quint: HTTP proxy error: %v\n", err)
		proxy.Close()
		os.Exit(1)
	}
}
