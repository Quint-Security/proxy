//go:build linux

package pidlookup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func lookupPort(port int) *ProcessInfo {
	// Read /proc/net/tcp to find the socket inode for this port
	inode := findInodeByPort(port)
	if inode == "" {
		return nil
	}

	// Scan /proc/*/fd/ to find which process owns this inode
	pid := findPIDByInode(inode)
	if pid == 0 {
		return nil
	}

	name := ""
	cmdPath := ""

	// Read process name
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		name = strings.TrimSpace(string(data))
	}

	// Read process path
	if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		cmdPath = link
	}

	return &ProcessInfo{
		PID:         pid,
		ProcessName: name,
		ProcessPath: cmdPath,
	}
}

func findInodeByPort(port int) string {
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return ""
	}

	portHex := fmt.Sprintf("%04X", port)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// local_address is field 1, format: IP:PORT in hex
		parts := strings.Split(fields[1], ":")
		if len(parts) == 2 && strings.ToUpper(parts[1]) == portHex {
			return fields[9] // inode
		}
	}
	return ""
}

func findPIDByInode(inode string) int {
	target := "socket:[" + inode + "]"
	procs, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fdPath := range procs {
		link, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}
		if link == target {
			// Extract PID from path: /proc/<pid>/fd/<fd>
			parts := strings.Split(fdPath, "/")
			if len(parts) >= 4 {
				pid, _ := strconv.Atoi(parts[2])
				return pid
			}
		}
	}
	return 0
}
