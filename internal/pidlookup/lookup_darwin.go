//go:build darwin

package pidlookup

import (
	"os/exec"
	"strconv"
	"strings"
)

var genericProcessNames = map[string]bool{
	"node": true, "npm": true, "npx": true, "python": true, "python3": true,
	"ruby": true, "java": true, "deno": true, "bun": true, "ts-node": true,
}

var knownAgentNames = map[string]string{
	"claude":   "claude-code",
	"cursor":   "cursor",
	"code":     "vscode",
	"windsurf": "windsurf",
	"zed":      "zed",
	"aider":    "aider",
	"cline":    "cline",
	"devin":    "devin",
	"kiro":     "kiro",
}

func lookupPort(port int) *ProcessInfo {
	return lookupPortExcluding(port, 0)
}

// lookupPortExcluding finds the process owning a port, skipping excludePID.
func lookupPortExcluding(port int, excludePID int) *ProcessInfo {
	out, err := exec.Command("lsof", "-i", ":"+strconv.Itoa(port), "-P", "-n", "-F", "p").Output()
	if err != nil {
		return nil
	}

	// Collect all PIDs that match, skip excludePID
	var pid int
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) > 1 && line[0] == 'p' {
			p, _ := strconv.Atoi(line[1:])
			if p != 0 && p != excludePID {
				pid = p
				break
			}
		}
	}
	if pid == 0 {
		return nil
	}

	return resolveProcess(pid)
}

// resolveProcess gets the process name and walks the tree if needed.
func resolveProcess(pid int) *ProcessInfo {
	name := ""
	cmdPath := ""
	if nameOut, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output(); err == nil {
		cmdPath = strings.TrimSpace(string(nameOut))
		name = cmdPath
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
	}
	if name == "" {
		return nil
	}

	// Check if this process itself is a known agent
	lower := strings.ToLower(name)
	if agentName, ok := knownAgentNames[lower]; ok {
		return &ProcessInfo{PID: pid, ProcessName: agentName, ProcessPath: cmdPath}
	}

	// If generic, walk up the tree
	if genericProcessNames[lower] {
		if resolvedName, resolvedPID := walkParentTree(pid, 5); resolvedName != "" {
			return &ProcessInfo{PID: resolvedPID, ProcessName: resolvedName, ProcessPath: cmdPath}
		}
	}

	return &ProcessInfo{PID: pid, ProcessName: name, ProcessPath: cmdPath}
}

func walkParentTree(pid int, maxDepth int) (string, int) {
	currentPID := pid
	for i := 0; i < maxDepth; i++ {
		ppidOut, err := exec.Command("ps", "-p", strconv.Itoa(currentPID), "-o", "ppid=").Output()
		if err != nil {
			return "", 0
		}
		ppid, err := strconv.Atoi(strings.TrimSpace(string(ppidOut)))
		if err != nil || ppid <= 1 {
			return "", 0
		}

		nameOut, err := exec.Command("ps", "-p", strconv.Itoa(ppid), "-o", "comm=").Output()
		if err != nil {
			return "", 0
		}
		parentName := strings.TrimSpace(string(nameOut))
		if idx := strings.LastIndex(parentName, "/"); idx >= 0 {
			parentName = parentName[idx+1:]
		}

		lower := strings.ToLower(parentName)
		if agentName, ok := knownAgentNames[lower]; ok {
			return agentName, ppid
		}
		if !genericProcessNames[lower] {
			return parentName, ppid
		}
		currentPID = ppid
	}
	return "", 0
}
