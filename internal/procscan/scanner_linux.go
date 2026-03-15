//go:build linux

package procscan

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func scanProcesses(selfPID int, sigs []AgentSignature) []AgentProcess {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	var results []AgentProcess
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == selfPID {
			continue
		}

		procDir := filepath.Join("/proc", entry.Name())

		// Read process name from /proc/<pid>/comm
		name := readFileFirstLine(filepath.Join(procDir, "comm"))
		if name == "" {
			continue
		}

		// Read binary path from /proc/<pid>/exe (symlink)
		exePath, _ := os.Readlink(filepath.Join(procDir, "exe"))

		platform, matched := MatchProcess(name, exePath)
		if !matched {
			continue
		}

		// Parse PPID from /proc/<pid>/stat — field 4 (1-indexed)
		ppid := parsePPID(filepath.Join(procDir, "stat"))

		// Parse VmRSS from /proc/<pid>/status
		rssKB := parseVmRSS(filepath.Join(procDir, "status"))

		results = append(results, AgentProcess{
			Platform:   platform,
			PID:        pid,
			PPID:       ppid,
			BinaryPath: exePath,
			State:      "running",
			MemoryMB:   rssKB / 1024,
		})
	}

	return results
}

// readFileFirstLine reads a file and returns its first line, trimmed.
func readFileFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	return s
}

// parsePPID reads /proc/<pid>/stat and extracts the PPID (field 4).
// The stat line format is: pid (comm) state ppid ...
// We find the closing ')' of comm first to handle names with spaces or parens.
func parsePPID(statPath string) int {
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	s := string(data)

	// Find the last ')' — everything after is space-separated fields starting with state.
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0
	}

	// After ') ' the fields are: state ppid pgrp session ...
	rest := strings.TrimSpace(s[idx+1:])
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

// parseVmRSS reads /proc/<pid>/status and returns VmRSS in KB.
func parseVmRSS(statusPath string) int {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.Atoi(fields[1])
				return kb
			}
		}
	}
	return 0
}
