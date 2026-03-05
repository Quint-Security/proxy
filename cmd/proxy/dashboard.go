package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"github.com/Quint-Security/quint-proxy/internal/dashboard"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// runDashboard handles: quint-proxy dashboard [--port <port>] [--static-dir <path>] [--no-open]
func runDashboard(args []string) {
	var policyPath string
	var port int
	var noOpen bool
	var staticDir string

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
		case "--static-dir":
			i++
			if i < len(args) {
				staticDir = args[i]
			}
		case "--no-open":
			noOpen = true
		}
	}

	if port == 0 {
		port = 8080
	}

	policy, err := intercept.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}
	qlog.SetLevel(policy.LogLevel)
	dataDir := intercept.ResolveDataDir(policy.DataDir)

	srv, err := dashboard.NewWithOpts(dashboard.Opts{
		DataDir:   dataDir,
		Policy:    policy,
		StaticDir: staticDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start dashboard: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		srv.Close()
		os.Exit(0)
	}()

	if !noOpen {
		go openBrowser(fmt.Sprintf("http://localhost:%d", port))
	}

	if err := srv.Start(port); err != nil {
		fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
		os.Exit(1)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	}
	if cmd != nil {
		cmd.Run()
	}
}
