package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// runUninstall handles: quint uninstall [--force]
// Removes the Quint daemon, proxy binary, CA certs, system proxy settings,
// and user configuration. Requires root.
func runUninstall(args []string) {
	var force bool
	for _, a := range args {
		if a == "--force" {
			force = true
		}
	}

	// Require root
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "quint uninstall: must be run as root (sudo quint uninstall)\n")
		os.Exit(1)
	}

	// Detect real user home via SUDO_USER
	realUser := os.Getenv("SUDO_USER")
	realHome := ""
	if realUser != "" {
		if runtime.GOOS == "darwin" {
			realHome = filepath.Join("/Users", realUser)
		} else {
			realHome = filepath.Join("/home", realUser)
		}
		// Verify it exists; fall back to HOME
		if _, err := os.Stat(realHome); err != nil {
			realHome = os.Getenv("HOME")
		}
	} else {
		realHome = os.Getenv("HOME")
	}

	if !force {
		fmt.Println("Quint Uninstall — the following will be removed:")
		fmt.Println()
		fmt.Println("  - Quint daemon (launchd / systemd)")
		fmt.Println("  - Binary: /usr/local/bin/quint, /opt/homebrew/bin/quint")
		fmt.Println("  - CA certificate from system trust store")
		fmt.Println("  - System proxy (PAC) settings")
		fmt.Println("  - Daemon config: /etc/quint/")
		fmt.Println("  - Daemon data: /var/lib/quint/")
		if realHome != "" {
			fmt.Printf("  - User config: %s/.quint/\n", realHome)
		}
		fmt.Println("  - Shell profile entries (~/.zshrc, ~/.bashrc)")
		fmt.Println()
		fmt.Print("Continue? [y/N] ")

		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
	}

	fmt.Println("Uninstalling Quint...")

	// Step 1: Stop daemon
	stopDaemon()

	// Step 2: Remove binaries
	removeBinaries()

	// Step 3: Remove CA from trust store
	removeCA()

	// Step 4: Clear launchd env vars (macOS)
	if runtime.GOOS == "darwin" {
		clearLaunchdEnv()
	}

	// Step 5: Reset system proxy (macOS only)
	if runtime.GOOS == "darwin" {
		resetSystemProxy()
	}

	// Step 5: Remove /etc/profile.d/quint-proxy.sh (Linux)
	if runtime.GOOS == "linux" {
		removeFileWarn("/etc/profile.d/quint-proxy.sh")
	}

	// Step 6: Clean /etc/environment (Linux)
	if runtime.GOOS == "linux" {
		cleanEtcEnvironment()
	}

	// Step 7: Remove daemon config
	removeDirWarn("/etc/quint")

	// Step 8: Remove daemon data
	removeDirWarn("/var/lib/quint")

	// Step 9: Remove LaunchDaemon plist / systemd unit
	removeDaemonConfig()

	// Step 10-12: User-level cleanup
	if realHome != "" {
		// Step 11: Remove ~/.quint/
		removeDirWarn(filepath.Join(realHome, ".quint"))

		// Step 12: Remove source line from shell profiles
		cleanShellProfile(filepath.Join(realHome, ".zshrc"))
		cleanShellProfile(filepath.Join(realHome, ".bashrc"))
	}

	fmt.Println()
	fmt.Println("Quint uninstalled successfully. Restart your shell.")
}

// stopDaemon stops the Quint daemon via launchctl (macOS) or systemctl (Linux).
func stopDaemon() {
	switch runtime.GOOS {
	case "darwin":
		plistPath := "/Library/LaunchDaemons/dev.quintai.agent.plist"
		if _, err := os.Stat(plistPath); err == nil {
			out, err := exec.Command("launchctl", "unload", plistPath).CombinedOutput()
			if err != nil {
				qlog.Warn("failed to unload LaunchDaemon: %v (%s)", err, strings.TrimSpace(string(out)))
			} else {
				fmt.Println("  [ok] Stopped daemon (launchctl)")
			}
		} else {
			fmt.Println("  [skip] No LaunchDaemon plist found")
		}
	case "linux":
		// Stop and disable systemd service
		if out, err := exec.Command("systemctl", "stop", "quint-agent").CombinedOutput(); err != nil {
			qlog.Warn("failed to stop systemd service: %v (%s)", err, strings.TrimSpace(string(out)))
		} else {
			fmt.Println("  [ok] Stopped daemon (systemctl)")
		}
		if out, err := exec.Command("systemctl", "disable", "quint-agent").CombinedOutput(); err != nil {
			qlog.Warn("failed to disable systemd service: %v (%s)", err, strings.TrimSpace(string(out)))
		} else {
			fmt.Println("  [ok] Disabled daemon (systemctl)")
		}
	}
}

// removeBinaries removes the quint binary from known install locations.
func removeBinaries() {
	paths := []string{"/usr/local/bin/quint", "/opt/homebrew/bin/quint"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			if err := os.Remove(p); err != nil {
				qlog.Warn("failed to remove %s: %v", p, err)
			} else {
				fmt.Printf("  [ok] Removed %s\n", p)
			}
		}
	}
}

// removeCA removes the Quint CA certificate from the system trust store.
func removeCA() {
	switch runtime.GOOS {
	case "darwin":
		// Try known CA cert paths
		caPaths := []string{
			"/var/lib/quint/ca/quint-ca.crt",
			filepath.Join(os.Getenv("HOME"), ".quint", "ca", "quint-ca.crt"),
		}
		for _, caPath := range caPaths {
			if _, err := os.Stat(caPath); err == nil {
				out, err := exec.Command("security", "remove-trusted-cert", "-d", caPath).CombinedOutput()
				if err != nil {
					qlog.Warn("failed to remove CA from keychain (%s): %v (%s)", caPath, err, strings.TrimSpace(string(out)))
				} else {
					fmt.Printf("  [ok] Removed CA from keychain (%s)\n", caPath)
				}
			}
		}
	case "linux":
		caPath := "/usr/local/share/ca-certificates/quint-ca.crt"
		if _, err := os.Stat(caPath); err == nil {
			if err := os.Remove(caPath); err != nil {
				qlog.Warn("failed to remove %s: %v", caPath, err)
			} else {
				fmt.Printf("  [ok] Removed %s\n", caPath)
			}
			out, err := exec.Command("update-ca-certificates").CombinedOutput()
			if err != nil {
				qlog.Warn("update-ca-certificates failed: %v (%s)", err, strings.TrimSpace(string(out)))
			} else {
				fmt.Println("  [ok] Updated CA certificates")
			}
		}
	}
}

// clearLaunchdEnv removes the Quint env LaunchAgent and clears env vars.
func clearLaunchdEnv() {
	// Find and unload the user LaunchAgent
	realUser := os.Getenv("SUDO_USER")
	if realUser == "" {
		realUser = os.Getenv("USER")
	}

	var realHome string
	if runtime.GOOS == "darwin" && realUser != "" && realUser != "root" {
		realHome = filepath.Join("/Users", realUser)
	}

	if realHome != "" {
		plistPath := filepath.Join(realHome, "Library", "LaunchAgents", "dev.quintai.env.plist")
		if _, err := os.Stat(plistPath); err == nil {
			// Unload in user context
			exec.Command("su", "-", realUser, "-c",
				fmt.Sprintf("launchctl unload %s 2>/dev/null", plistPath),
			).Run()
			os.Remove(plistPath)
			fmt.Println("  [ok] Removed LaunchAgent (dev.quintai.env)")
		}
	}

	// Clear env vars (best-effort, may fail with SIP)
	vars := []string{"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "HTTP_PROXY", "HTTPS_PROXY", "NODE_USE_SYSTEM_CA"}
	if realUser != "" && realUser != "root" {
		for _, v := range vars {
			exec.Command("su", "-", realUser, "-c",
				fmt.Sprintf("launchctl unsetenv %s 2>/dev/null", v),
			).Run()
		}
	}
	fmt.Println("  [ok] Cleared launchd env vars")
}

// resetSystemProxy clears auto-proxy (PAC) URLs on all macOS network interfaces.
func resetSystemProxy() {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		qlog.Warn("failed to list network services: %v", err)
		return
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		iface := strings.TrimSpace(line)
		// Skip the header line (starts with "An asterisk")
		if iface == "" || strings.HasPrefix(iface, "An asterisk") || strings.HasPrefix(iface, "*") {
			continue
		}

		// Clear auto-proxy URL
		if out, err := exec.Command("networksetup", "-setautoproxyurl", iface, "").CombinedOutput(); err != nil {
			qlog.Warn("failed to clear auto-proxy for %s: %v (%s)", iface, err, strings.TrimSpace(string(out)))
		}

		// Disable auto-proxy
		if out, err := exec.Command("networksetup", "-setautoproxystate", iface, "off").CombinedOutput(); err != nil {
			qlog.Warn("failed to disable auto-proxy for %s: %v (%s)", iface, err, strings.TrimSpace(string(out)))
		}
	}
	fmt.Println("  [ok] Reset system proxy settings")
}

// cleanEtcEnvironment removes Quint proxy lines from /etc/environment (Linux).
func cleanEtcEnvironment() {
	path := "/etc/environment"
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		qlog.Warn("failed to read %s: %v", path, err)
		return
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	changed := false

	for _, line := range lines {
		lower := strings.ToLower(line)
		// Remove lines that set HTTP_PROXY/HTTPS_PROXY/SSL_CERT_FILE/NODE_EXTRA_CA_CERTS
		// pointing to quint
		if isQuintProxyLine(lower) {
			changed = true
			continue
		}
		filtered = append(filtered, line)
	}

	if changed {
		if err := os.WriteFile(path, []byte(strings.Join(filtered, "\n")), 0o644); err != nil {
			qlog.Warn("failed to write %s: %v", path, err)
		} else {
			fmt.Println("  [ok] Cleaned /etc/environment")
		}
	}
}

// isQuintProxyLine returns true if the line is a proxy env var set by Quint.
func isQuintProxyLine(lower string) bool {
	// Match lines like: HTTP_PROXY=..., http_proxy=..., HTTPS_PROXY=..., etc.
	prefixes := []string{"http_proxy=", "https_proxy=", "ssl_cert_file=", "node_extra_ca_certs="}
	for _, pfx := range prefixes {
		if strings.HasPrefix(lower, pfx) && strings.Contains(lower, "quint") {
			return true
		}
	}
	return false
}

// removeDaemonConfig removes the LaunchDaemon plist or systemd unit file.
func removeDaemonConfig() {
	switch runtime.GOOS {
	case "darwin":
		removeFileWarn("/Library/LaunchDaemons/dev.quintai.agent.plist")
	case "linux":
		removeFileWarn("/etc/systemd/system/quint-agent.service")
		// Reload systemd after removing unit
		if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			qlog.Warn("systemctl daemon-reload failed: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
}

// cleanShellProfile removes the Quint source line from a shell profile file.
// The line pattern: [ -f ~/.quint/env.sh ] && source ~/.quint/env.sh
func cleanShellProfile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // file doesn't exist or not readable — skip silently
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	changed := false

	for _, line := range lines {
		if strings.Contains(line, ".quint/env.sh") {
			changed = true
			continue
		}
		filtered = append(filtered, line)
	}

	if changed {
		if err := os.WriteFile(path, []byte(strings.Join(filtered, "\n")), 0o644); err != nil {
			qlog.Warn("failed to update %s: %v", path, err)
		} else {
			fmt.Printf("  [ok] Cleaned %s\n", path)
		}
	}
}

// removeFileWarn removes a single file, logging a warning on failure.
func removeFileWarn(path string) {
	if _, err := os.Stat(path); err != nil {
		return // doesn't exist — nothing to do
	}
	if err := os.Remove(path); err != nil {
		qlog.Warn("failed to remove %s: %v", path, err)
	} else {
		fmt.Printf("  [ok] Removed %s\n", path)
	}
}

// removeDirWarn removes a directory tree, logging a warning on failure.
func removeDirWarn(path string) {
	if _, err := os.Stat(path); err != nil {
		return // doesn't exist — nothing to do
	}
	if err := os.RemoveAll(path); err != nil {
		qlog.Warn("failed to remove %s: %v", path, err)
	} else {
		fmt.Printf("  [ok] Removed %s\n", path)
	}
}
