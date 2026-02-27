package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// stealthAction indicates what to do with a command.
type stealthAction string

const (
	stealthAllow stealthAction = "allow"  // Command is safe, allow it
	stealthDeny  stealthAction = "deny"   // Command would tamper with Quint, deny it
	stealthFake  stealthAction = "fake"   // Command would reveal Quint, fake the response
)

// stealthResult holds the result of stealth analysis.
type stealthResult struct {
	Action    stealthAction
	Reason    string
	RiskScore int
}

// stealthCheck analyzes a shell command and returns a stealth action.
// Returns: action ("allow", "deny", "fake"), reason string, riskScore int
func stealthCheck(command, dataDir string) stealthResult {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return stealthResult{Action: stealthAllow, Reason: "", RiskScore: 0}
	}

	paths := protectedPaths(dataDir)

	// Check for Quint path references in the command
	var matchedPath string
	for _, p := range paths {
		if strings.Contains(cmd, p) {
			matchedPath = p
			break
		}
	}

	if matchedPath == "" {
		// No Quint references, allow
		return stealthResult{Action: stealthAllow, Reason: "", RiskScore: 0}
	}

	// Check for process kill commands
	killPatterns := []string{
		`\bkill\s+.*quint`,
		`\bkillall\s+.*quint`,
		`\bpkill\s+.*quint`,
	}
	for _, pat := range killPatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pat, cmd); matched {
			return stealthResult{
				Action:    stealthDeny,
				Reason:    "attempted to kill quint process",
				RiskScore: 100,
			}
		}
	}

	// Check for destructive operations on Quint files/dirs
	destructivePatterns := []string{
		`\brm\b`,
		`\bmv\b`,
		`\bcp\b.*>`,
		`\bchmod\b`,
		`\bchown\b`,
		`\btruncate\b`,
		`>`,  // redirect that would overwrite
		`>>`, // redirect that would append
	}
	for _, pat := range destructivePatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pat, cmd); matched {
			return stealthResult{
				Action:    stealthDeny,
				Reason:    "attempted to modify/delete quint files",
				RiskScore: 100,
			}
		}
	}

	// Check for read operations on Quint files
	readPatterns := []string{
		`\bcat\b`,
		`\bless\b`,
		`\bmore\b`,
		`\bhead\b`,
		`\btail\b`,
		`\bvim\b`,
		`\bnano\b`,
		`\bvi\b`,
		`\bemacs\b`,
		`\bcode\b`,
		`\bopen\b`,
		`\bfile\b`,
		`\bstat\b`,
		`\bls\b.*` + regexp.QuoteMeta(filepath.Dir(matchedPath)),
	}
	for _, pat := range readPatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pat, cmd); matched {
			return stealthResult{
				Action:    stealthFake,
				Reason:    "attempted to read quint files",
				RiskScore: 90,
			}
		}
	}

	// Check for process listing commands that would reveal Quint
	processListPatterns := []string{
		`\bps\b`,
		`\bpgrep\b`,
		`\btop\b`,
		`\bhtop\b`,
		`\bpstree\b`,
	}
	for _, pat := range processListPatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pat, cmd); matched {
			return stealthResult{
				Action:    stealthFake,
				Reason:    "attempted to list processes (may reveal quint)",
				RiskScore: 60,
			}
		}
	}

	// Default: if Quint path is mentioned but no specific dangerous pattern matched,
	// still flag as high risk read attempt
	return stealthResult{
		Action:    stealthFake,
		Reason:    "referenced quint configuration path",
		RiskScore: 70,
	}
}

// protectedPaths returns the list of paths that should be hidden from agents.
func protectedPaths(dataDir string) []string {
	// Expand ~ to home directory
	home, _ := os.UserHomeDir()

	// Common variations of the data directory path
	paths := []string{
		dataDir,
		strings.ReplaceAll(dataDir, "~", home),
		filepath.Join(home, ".quint"),
		"~/.quint",
		"$HOME/.quint",
	}

	// Specific files
	files := []string{
		"policy.json",
		"quint.db",
		"servers.json",
		"original_servers.json",
		"original_shell.json",
		"audit.db",
		".quint",
	}

	// Add full paths for files
	for _, f := range files {
		paths = append(paths, filepath.Join(dataDir, f))
		paths = append(paths, filepath.Join(home, ".quint", f))
	}

	// Add the quint binary path (from os.Args[0])
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, exe)
		paths = append(paths, filepath.Base(exe))
	}

	return paths
}

// filterProcessList removes quint-related entries from ps/pgrep output.
func filterProcessList(output string) string {
	var filtered []string
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		// Filter out lines containing "quint" (case-insensitive)
		if !strings.Contains(strings.ToLower(line), "quint") {
			filtered = append(filtered, line)
		}
	}

	return strings.Join(filtered, "\n")
}

// fakeFileNotFound returns a plausible "file not found" error message.
func fakeFileNotFound(path string) string {
	return path + ": No such file or directory"
}

// fakePermissionDenied returns a plausible "permission denied" error message.
func fakePermissionDenied(operation string) string {
	return operation + ": Permission denied"
}
