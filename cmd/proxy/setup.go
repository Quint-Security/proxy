package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	qcrypto "github.com/Quint-Security/quint-proxy/internal/crypto"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/pac"
)

// runSetup handles: quint setup [flags]
// One-command install: generates CA, trusts it, writes shell env, optionally
// installs and starts the daemon. Designed to be called by the install script:
//
//	curl -fsSL https://get.quintai.dev | sudo sh -s -- --token <token>
func runSetup(args []string) {
	var (
		tokenFlag  string
		apiURLFlag string
		noDaemon   bool
		envOnly    bool
		port       int
		apiPort    int
	)

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
		case "--port":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &port)
			}
		case "--api-port":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &apiPort)
			}
		case "--no-daemon":
			noDaemon = true
		case "--env-only":
			envOnly = true
		}
	}

	if port == 0 {
		port = 9090
	}
	if apiPort == 0 {
		apiPort = 8080
	}
	if apiURLFlag == "" {
		apiURLFlag = "https://api.quintai.dev"
	}

	// --env-only: just regenerate ~/.quint/env.sh (and env.fish) with agent wrappers.
	// Does NOT require root since it only writes to user-space files.
	if envOnly {
		realHome := os.Getenv("HOME")
		if realHome == "" {
			// Fallback: try to detect from SUDO_USER if running as root
			if os.Geteuid() == 0 {
				_, realHome = detectRealUser()
			} else {
				home, err := os.UserHomeDir()
				if err != nil {
					fatal("cannot determine home directory: %v", err)
				}
				realHome = home
			}
		}
		runEnvOnly(realHome, port)
		return
	}

	isRoot := os.Geteuid() == 0
	if !isRoot {
		fmt.Fprintf(os.Stderr, "quint setup: must be run as root (sudo quint setup ...)\n")
		os.Exit(1)
	}

	// Detect real user's home directory
	realUser, realHome := detectRealUser()

	fmt.Println()
	fmt.Println("  Quint Setup")
	fmt.Println("  ===========")
	fmt.Println()

	// --- Step 1: Create daemon data directory ---
	daemonDataDir := "/var/lib/quint"
	if err := os.MkdirAll(daemonDataDir, 0o755); err != nil {
		fatal("create data dir: %v", err)
	}
	step("Created %s", daemonDataDir)

	// --- Step 2: Generate CA certificate + bundle ---
	ca, err := qcrypto.EnsureCA(daemonDataDir)
	if err != nil {
		fatal("generate CA: %v", err)
	}
	_ = ca
	step("Generated CA certificate")

	// --- Step 3: Generate Ed25519 signing keypair ---
	if _, err := qcrypto.EnsureKeyPair(daemonDataDir, ""); err != nil {
		fatal("generate signing keys: %v", err)
	}
	step("Generated Ed25519 signing keypair")

	// --- Step 4: Trust CA in system trust store ---
	certPath := qcrypto.CertPath(daemonDataDir)
	if err := trustCA(certPath); err != nil {
		warn("CA trust failed: %v (HTTPS interception may not work for all apps)", err)
	} else {
		step("Trusted CA in system keychain")
	}

	// --- Step 5: Inject env vars for GUI apps (LaunchAgent) ---
	// Terminal apps get env vars from ~/.zshrc, but GUI apps (Claude Desktop,
	// Cursor, VS Code) are launched by launchd and never read shell profiles.
	// Without NODE_EXTRA_CA_CERTS, Node.js apps reject the MITM cert.
	//
	// Solution: install a user LaunchAgent that runs at login and calls
	// `launchctl setenv` in the USER's session context. (Running it from
	// root/sudo context is blocked by SIP, but user context works.)
	if runtime.GOOS == "darwin" && realUser != "" && realUser != "root" {
		installEnvAgent(realHome, certPath, qcrypto.BundlePath(daemonDataDir), port, realUser)
	}

	// --- Step 6: Generate PAC file + set system proxy ---
	// Even with HTTP_PROXY env vars, some apps ignore them. The macOS system
	// proxy setting (auto-proxy URL pointing to a PAC file) catches everything
	// at the OS level.
	pacPath := filepath.Join(daemonDataDir, "proxy.pac")
	allDomains := pac.MergeDomains(pac.DefaultDomains, nil)
	if count, err := pac.WritePACFile(pacPath, port, allDomains); err != nil {
		warn("PAC file generation failed: %v", err)
	} else {
		step("Generated PAC file (%d domains)", count)
		if runtime.GOOS == "darwin" {
			setSystemProxy(pacPath)
		}
	}

	// --- Step 8: Create user config directory + copy CA ---
	userQuintDir := filepath.Join(realHome, ".quint")
	userCADir := filepath.Join(userQuintDir, "ca")
	if err := os.MkdirAll(userCADir, 0o755); err != nil {
		fatal("create user config dir: %v", err)
	}

	// Copy CA cert and bundle to user-accessible location
	for _, name := range []string{"quint-ca.crt", "quint-ca-bundle.pem"} {
		src := filepath.Join(daemonDataDir, "ca", name)
		dst := filepath.Join(userCADir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			fatal("read %s: %v", src, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			fatal("write %s: %v", dst, err)
		}
	}
	step("Copied CA to %s", userCADir)

	// --- Step 9: Write env.sh with agent wrappers ---
	envPath := filepath.Join(userQuintDir, "env.sh")
	bundlePath := filepath.Join(userCADir, "quint-ca-bundle.pem")
	userCertPath := filepath.Join(userCADir, "quint-ca.crt")

	agents := detectAgents()
	envContent := generateEnvSh(bundlePath, userCertPath, port, agents)

	if err := os.WriteFile(envPath, []byte(envContent), 0o644); err != nil {
		fatal("write env.sh: %v", err)
	}
	if len(agents) > 0 {
		names := make([]string, len(agents))
		for i, a := range agents {
			names[i] = a.Binary
		}
		step("Wrote %s (%d agent wrappers: %s)", envPath, len(agents), strings.Join(names, ", "))
	} else {
		step("Wrote %s (no agent CLIs detected)", envPath)
	}

	// --- Step 9b: Write env.fish if fish shell is installed ---
	if hasFishConfig(realHome) {
		fishPath := filepath.Join(userQuintDir, "env.fish")
		fishContent := generateEnvFish(bundlePath, userCertPath, port, agents)
		if err := os.WriteFile(fishPath, []byte(fishContent), 0o644); err != nil {
			warn("write env.fish: %v", err)
		} else {
			step("Wrote %s", fishPath)
		}
	}

	// --- Step 10: Add source line to shell profiles ---
	sourceLine := fmt.Sprintf("[ -f %s ] && source %s", envPath, envPath)
	profilesModified := 0
	for _, profile := range []string{".zshrc", ".bashrc"} {
		profilePath := filepath.Join(realHome, profile)
		if addLineToFile(profilePath, sourceLine, ".quint/env.sh") {
			profilesModified++
			step("Added source line to ~/%s", profile)
		}
	}

	// Fish shell profile
	if hasFishConfig(realHome) {
		fishPath := filepath.Join(userQuintDir, "env.fish")
		fishConfigPath := filepath.Join(realHome, ".config", "fish", "config.fish")
		fishSourceLine := fmt.Sprintf("source %s", fishPath)
		if addLineToFile(fishConfigPath, fishSourceLine, ".quint/env.fish") {
			profilesModified++
			step("Added source line to ~/.config/fish/config.fish")
		}
	}

	if profilesModified == 0 {
		step("Shell profiles already configured")
	}

	// Linux: also write /etc/profile.d/ and /etc/environment for system-wide coverage
	if runtime.GOOS == "linux" {
		setupLinuxSystemEnv(bundlePath, userCertPath, port)
	}

	// --- Step 11: Fix ownership (we're running as root via sudo) ---
	if realUser != "" && realUser != "root" {
		chownRecursive(userQuintDir, realUser)
		step("Set ownership to %s", realUser)
	}

	// --- Step 12: Daemon setup (if token provided) ---
	if tokenFlag != "" && !noDaemon {
		// Write daemon config
		configDir := "/etc/quint"
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			fatal("create config dir: %v", err)
		}
		configContent := fmt.Sprintf("token: %q\napi_url: %q\nlog_level: \"info\"\n", tokenFlag, apiURLFlag)
		if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0o600); err != nil {
			fatal("write config: %v", err)
		}
		step("Wrote /etc/quint/config.yaml")

		// Install and start system service
		if err := installDaemon(port, apiPort); err != nil {
			fatal("install daemon: %v", err)
		}
		step("Installed and started daemon")

		// Wait for daemon to be ready
		fmt.Print("  Waiting for daemon... ")
		if waitForDaemon(apiPort, 10*time.Second) {
			fmt.Println("ready!")
		} else {
			fmt.Println("timeout (daemon may still be starting)")
		}
	}

	// --- Summary ---
	fmt.Println()
	fmt.Println("  Setup complete!")
	fmt.Println()
	fmt.Printf("  Binary:      /usr/local/bin/quint (%s)\n", version)
	fmt.Printf("  Data:        %s\n", daemonDataDir)
	fmt.Printf("  User config: %s\n", userQuintDir)
	fmt.Printf("  CA cert:     %s\n", userCertPath)
	fmt.Printf("  Env:         %s\n", envPath)
	fmt.Println()

	if tokenFlag != "" && !noDaemon {
		fmt.Printf("  Proxy:       http://localhost:%d\n", port)
		fmt.Printf("  Dashboard:   http://localhost:%d\n", apiPort)
		fmt.Println()
		fmt.Println("  AI agent traffic is routed via the system PAC file.")
		fmt.Println("  For CLI agents, run: eval $(quint env --proxy)")
	} else {
		fmt.Println("  To start the proxy:")
		fmt.Println("    quint watch")
		fmt.Println()
		fmt.Println("  AI agent traffic is routed via the system PAC file.")
		fmt.Println("  For CLI agents, run: eval $(quint env --proxy)")
	}
	fmt.Println()
}

// runEnvOnly regenerates ~/.quint/env.sh without redoing the full setup.
func runEnvOnly(realHome string, port int) {
	userQuintDir := filepath.Join(realHome, ".quint")
	userCADir := filepath.Join(userQuintDir, "ca")
	bundlePath := filepath.Join(userCADir, "quint-ca-bundle.pem")
	certPath := filepath.Join(userCADir, "quint-ca.crt")

	// Verify CA exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		fatal("CA cert not found at %s — run full 'quint setup' first", certPath)
	}

	fmt.Println()
	fmt.Println("  Scanning for AI agent CLIs...")
	fmt.Println()

	agents := detectAgents()
	for _, a := range knownAgents {
		found := false
		for _, f := range agents {
			if f.Binary == a.Binary {
				found = true
				break
			}
		}
		if found {
			fmt.Printf("    found  %s (%s)\n", a.Binary, a.Name)
		}
	}

	envPath := filepath.Join(userQuintDir, "env.sh")
	envContent := generateEnvSh(bundlePath, certPath, port, agents)
	if err := os.WriteFile(envPath, []byte(envContent), 0o644); err != nil {
		fatal("write env.sh: %v", err)
	}

	// Generate fish config if fish shell is installed
	if hasFishConfig(realHome) {
		fishPath := filepath.Join(userQuintDir, "env.fish")
		fishContent := generateEnvFish(bundlePath, certPath, port, agents)
		if err := os.WriteFile(fishPath, []byte(fishContent), 0o644); err != nil {
			warn("write env.fish: %v", err)
		} else {
			fmt.Printf("  Wrote %s\n", fishPath)
			// Add source line to fish config if not already present
			fishConfigPath := filepath.Join(realHome, ".config", "fish", "config.fish")
			fishSourceLine := fmt.Sprintf("source %s", fishPath)
			if addLineToFile(fishConfigPath, fishSourceLine, ".quint/env.fish") {
				fmt.Printf("  Added source line to %s\n", fishConfigPath)
			}
		}
	}

	// Fix ownership
	realUser := os.Getenv("SUDO_USER")
	if realUser != "" && realUser != "root" {
		chownRecursive(envPath, realUser)
	}

	fmt.Println()
	fmt.Printf("  Wrote %s with %d agent wrappers.\n", envPath, len(agents))
	fmt.Println("  Open a new terminal to activate.")
	fmt.Println()
}

// detectRealUser finds the actual user behind sudo.
func detectRealUser() (user, home string) {
	user = os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" || user == "root" {
		// Best effort: check common paths
		home = os.Getenv("HOME")
		if home == "" || home == "/var/root" || home == "/root" {
			fatal("cannot determine user home directory (run with sudo, not as root directly)")
		}
		return user, home
	}

	if runtime.GOOS == "darwin" {
		home = filepath.Join("/Users", user)
	} else {
		home = filepath.Join("/home", user)
	}
	if _, err := os.Stat(home); err != nil {
		home = os.Getenv("HOME")
	}
	return user, home
}

// trustCA adds the CA certificate to the system trust store.
func trustCA(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("security", "add-trusted-cert",
			"-d",                       // add to admin trust settings
			"-r", "trustRoot",          // trust as root CA
			"-k", "/Library/Keychains/System.keychain",
			certPath,
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil

	case "linux":
		// Copy cert to ca-certificates directory
		dst := "/usr/local/share/ca-certificates/quint-ca.crt"
		data, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
		out, err := exec.Command("update-ca-certificates").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// installDaemon installs and starts the system daemon.
func installDaemon(port, apiPort int) error {
	binaryPath := "/usr/local/bin/quint"

	switch runtime.GOOS {
	case "darwin":
		plistPath := "/Library/LaunchDaemons/dev.quintai.agent.plist"
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.quintai.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>daemon</string>
    <string>--port</string>
    <string>%d</string>
    <string>--api-port</string>
    <string>%d</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/quint/agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/quint/agent.err</string>
</dict>
</plist>
`, binaryPath, port, apiPort)

		_ = os.MkdirAll("/var/log/quint", 0o755)

		if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
			return fmt.Errorf("write plist: %w", err)
		}

		// Unload first (ignore error if not loaded)
		exec.Command("launchctl", "unload", plistPath).Run()

		out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("launchctl load: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil

	case "linux":
		unitPath := "/etc/systemd/system/quint-agent.service"
		unit := fmt.Sprintf(`[Unit]
Description=Quint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s daemon --port %d --api-port %d
Restart=always
RestartSec=5
User=root
StandardOutput=append:/var/log/quint/agent.log
StandardError=append:/var/log/quint/agent.err

[Install]
WantedBy=multi-user.target
`, binaryPath, port, apiPort)

		_ = os.MkdirAll("/var/log/quint", 0o755)

		if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
			return fmt.Errorf("write unit: %w", err)
		}
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", "quint-agent").Run()
		out, err := exec.Command("systemctl", "start", "quint-agent").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl start: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// waitForDaemon polls the API port until it responds or times out.
func waitForDaemon(apiPort int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://localhost:%d/api/status", apiPort)

	for time.Now().Before(deadline) {
		resp, err := httpGetQuick(url)
		if err == nil && resp != nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// addLineToFile appends line to file if no line containing marker exists.
// Creates the file if it doesn't exist. Returns true if modified.
func addLineToFile(path, line, marker string) bool {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false
	}

	content := string(data)
	if strings.Contains(content, marker) {
		return false // already present
	}

	// Ensure file ends with newline before appending
	if len(content) > 0 && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += line + "\n"

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		qlog.Warn("failed to update %s: %v", path, err)
		return false
	}
	return true
}

// setupLinuxSystemEnv writes system-wide proxy env for non-interactive shells.
func setupLinuxSystemEnv(bundlePath, certPath string, port int) {
	// /etc/profile.d/ for login shells
	profileContent := fmt.Sprintf(`# Quint proxy environment — auto-generated
export SSL_CERT_FILE=%s
export NODE_EXTRA_CA_CERTS=%s
export HTTP_PROXY=http://localhost:%d
export HTTPS_PROXY=http://localhost:%d
`, bundlePath, certPath, port, port)

	_ = os.MkdirAll("/etc/profile.d", 0o755)
	if err := os.WriteFile("/etc/profile.d/quint-proxy.sh", []byte(profileContent), 0o644); err != nil {
		qlog.Warn("failed to write /etc/profile.d/quint-proxy.sh: %v", err)
	}
}

// installEnvAgent creates a user LaunchAgent that injects CA trust env vars
// into the GUI session at login. This is the only reliable way to get
// GUI-launched apps (Cursor, VS Code, Claude Desktop) to inherit
// NODE_EXTRA_CA_CERTS on modern macOS where SIP blocks `sudo launchctl setenv`.
//
// IMPORTANT: We do NOT set HTTP_PROXY/HTTPS_PROXY here. GUI app proxy routing
// is handled by the PAC file (which only routes tool API domains). AI provider
// domains go direct. CLI agents use per-agent wrappers in env.sh that health-
// check the proxy before routing. This prevents the proxy from breaking
// connectivity if it's down or overloaded.
func installEnvAgent(realHome, certPath, bundlePath string, port int, realUser string) {
	agentDir := filepath.Join(realHome, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		warn("create LaunchAgents dir: %v", err)
		return
	}

	// Only set CA trust vars — NO proxy vars. Proxy routing is handled by
	// the PAC file (GUI apps) and env.sh wrappers (CLI agents).
	script := fmt.Sprintf(
		"launchctl setenv NODE_EXTRA_CA_CERTS %s; "+
			"launchctl setenv SSL_CERT_FILE %s; "+
			"launchctl setenv NODE_USE_SYSTEM_CA 1",
		certPath, bundlePath,
	)

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.quintai.env</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
`, script)

	plistPath := filepath.Join(agentDir, "dev.quintai.env.plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		warn("write LaunchAgent plist: %v", err)
		return
	}

	// Fix ownership (we're running as root via sudo)
	chownRecursive(plistPath, realUser)

	// Load the agent immediately so env vars are available without re-login.
	// Use `su` to run launchctl in the real user's context (not root's).
	out, err := exec.Command("su", "-", realUser, "-c",
		fmt.Sprintf("launchctl load %s", plistPath),
	).CombinedOutput()
	if err != nil {
		// Load failed — might already be loaded, try unload+load
		exec.Command("su", "-", realUser, "-c",
			fmt.Sprintf("launchctl unload %s 2>/dev/null; launchctl load %s", plistPath, plistPath),
		).Run()
	}
	_ = out

	step("Installed LaunchAgent for GUI app env vars (%s)", plistPath)
}

// setSystemProxy configures macOS auto-proxy (PAC) on all active network
// interfaces. This routes traffic through Quint at the OS level, catching
// apps that ignore HTTP_PROXY env vars.
func setSystemProxy(pacPath string) {
	pacURL := "file://" + pacPath

	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		warn("could not list network services: %v", err)
		return
	}

	allOk := true
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		iface := strings.TrimSpace(line)
		// Skip header and disabled interfaces
		if iface == "" || strings.HasPrefix(iface, "An asterisk") || strings.HasPrefix(iface, "*") {
			continue
		}

		// Set PAC URL
		if out, err := exec.Command("networksetup", "-setautoproxyurl", iface, pacURL).CombinedOutput(); err != nil {
			// Some interfaces (like iPhone USB) don't support proxy — skip silently
			_ = out
			allOk = false
			continue
		}

		// Enable auto-proxy
		exec.Command("networksetup", "-setautoproxystate", iface, "on").Run()
	}

	if allOk {
		step("Set system proxy (PAC) on all network interfaces")
	} else {
		step("Set system proxy (PAC) on primary network interfaces")
	}
}

// chownRecursive changes ownership of a directory tree to the given user.
func chownRecursive(path, user string) {
	out, err := exec.Command("chown", "-R", user, path).CombinedOutput()
	if err != nil {
		qlog.Warn("chown %s %s: %v (%s)", user, path, err, strings.TrimSpace(string(out)))
	}
}

func step(format string, args ...any) {
	fmt.Printf("  [ok] "+format+"\n", args...)
}

func warn(format string, args ...any) {
	fmt.Printf("  [warn] "+format+"\n", args...)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  [error] "+format+"\n", args...)
	os.Exit(1)
}
