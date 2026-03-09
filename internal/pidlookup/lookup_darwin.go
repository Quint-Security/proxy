//go:build darwin

package pidlookup

import (
	"os/exec"
	"strconv"
	"strings"
)

func lookupPort(port int) *ProcessInfo {
	// Run: lsof -i :<port> -P -n -F pcn -sTCP:ESTABLISHED
	out, err := exec.Command("lsof", "-i", ":"+strconv.Itoa(port), "-P", "-n", "-F", "pcn", "-sTCP:ESTABLISHED").Output()
	if err != nil {
		return nil
	}

	var pid int
	var name, cmdPath string

	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'c':
			name = line[1:]
		case 'n':
			// network address — skip
		}
	}

	if pid == 0 {
		return nil
	}

	// Get full path from ps
	if pathOut, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output(); err == nil {
		cmdPath = strings.TrimSpace(string(pathOut))
	}

	return &ProcessInfo{
		PID:         pid,
		ProcessName: name,
		ProcessPath: cmdPath,
	}
}
