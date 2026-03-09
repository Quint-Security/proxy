//go:build darwin

package pidlookup

import (
	"os/exec"
	"strconv"
	"strings"
)

// genericProcessNames are process names that don't identify the actual tool.
// When we see these, walk up the process tree to find the real parent.
var genericProcessNames = map[string]bool{
	"node": true, "npm": true, "npx": true, "python": true, "python3": true,
	"ruby": true, "java": true, "deno": true, "bun": true, "ts-node": true,
}

// knownAgentNames maps parent process names to canonical agent identifiers.
var knownAgentNames = map[string]string{
	"claude":    "claude-code",
	"cursor":    "cursor",
	"code":      "vscode",
	"windsurf":  "windsurf",
	"zed":       "zed",
	"aider":     "aider",
	"cline":     "cline",
	"devin":     "devin",
	"kiro":      "kiro",
}

func lookupPort(port int) *ProcessInfo {
	out, err := exec.Command("lsof", "-i", ":"+strconv.Itoa(port), "-P", "-n", "-F", "pcn", "-sTCP:ESTABLISHED").Output()
	if err != nil {
		return nil
	}

	var pid int
	var name string

	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'c':
			name = line[1:]
		}
	}

	if pid == 0 {
		return nil
	}

	// Get full command path
	cmdPath := ""
	if pathOut, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output(); err == nil {
		cmdPath = strings.TrimSpace(string(pathOut))
	}

	// If the process is generic (node, python, etc.), walk up to find the real agent
	resolvedName := name
	resolvedPID := pid
	if genericProcessNames[strings.ToLower(name)] {
		if parentName, parentPID := walkParentTree(pid, 5); parentName != "" {
			resolvedName = parentName
			resolvedPID = parentPID
		}
	}

	return &ProcessInfo{
		PID:         resolvedPID,
		ProcessName: resolvedName,
		ProcessPath: cmdPath,
	}
}

// walkParentTree walks up the process tree (up to maxDepth levels) looking
// for a known agent process name. Returns the agent name and PID if found.
func walkParentTree(pid int, maxDepth int) (string, int) {
	currentPID := pid
	for i := 0; i < maxDepth; i++ {
		// Get parent PID
		ppidOut, err := exec.Command("ps", "-p", strconv.Itoa(currentPID), "-o", "ppid=").Output()
		if err != nil {
			return "", 0
		}
		ppid, err := strconv.Atoi(strings.TrimSpace(string(ppidOut)))
		if err != nil || ppid <= 1 {
			return "", 0
		}

		// Get parent process name
		nameOut, err := exec.Command("ps", "-p", strconv.Itoa(ppid), "-o", "comm=").Output()
		if err != nil {
			return "", 0
		}
		parentName := strings.TrimSpace(string(nameOut))
		// Extract just the binary name from the path
		if idx := strings.LastIndex(parentName, "/"); idx >= 0 {
			parentName = parentName[idx+1:]
		}

		// Check if this is a known agent
		lower := strings.ToLower(parentName)
		if agentName, ok := knownAgentNames[lower]; ok {
			return agentName, ppid
		}

		// If parent is also generic, keep walking
		if !genericProcessNames[lower] {
			// Found a non-generic, non-known parent — use it as-is
			return parentName, ppid
		}

		currentPID = ppid
	}
	return "", 0
}
