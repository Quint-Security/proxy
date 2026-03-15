//go:build darwin

package procscan

import (
	"os/exec"
	"strconv"
	"strings"
)

func scanProcesses(selfPID int, sigs []AgentSignature) []AgentProcess {
	cmd := exec.Command("ps", "-axo", "pid=,ppid=,pcpu=,rss=,comm=")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var results []AgentProcess
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Fields: PID PPID %CPU RSS COMM
		// The first 4 fields are numeric and whitespace-separated.
		// COMM is everything remaining (the full executable path).
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid == selfPID {
			continue
		}

		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		cpuPercent, _ := strconv.ParseFloat(fields[2], 64)

		rssKB, _ := strconv.Atoi(fields[3])

		// COMM may contain spaces; rejoin everything from field 4 onward.
		comm := strings.Join(fields[4:], " ")

		// Extract base name from comm (after last /).
		baseName := comm
		if idx := strings.LastIndex(comm, "/"); idx >= 0 {
			baseName = comm[idx+1:]
		}

		platform, matched := MatchProcess(baseName, comm)
		if !matched {
			continue
		}

		results = append(results, AgentProcess{
			Platform:   platform,
			PID:        pid,
			PPID:       ppid,
			BinaryPath: comm,
			State:      "running",
			CPUPercent: cpuPercent,
			MemoryMB:   rssKB / 1024,
		})
	}

	return results
}
