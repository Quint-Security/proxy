package procscan

import (
	"context"
	"os"
	"sync"
	"time"
)

const defaultInterval = 5 * time.Second

// AgentProcess represents a detected AI agent running on the host.
type AgentProcess struct {
	Platform   string    `json:"platform"`
	PID        int       `json:"pid"`
	PPID       int       `json:"ppid"`
	BinaryPath string    `json:"binary_path"`
	State      string    `json:"state"`
	CPUPercent float64   `json:"cpu_percent"`
	MemoryMB   int       `json:"memory_mb"`
	StartedAt  time.Time `json:"started_at"`
}

// Scanner periodically scans running processes for known AI agents
// and invokes a callback when the set of detected agents changes.
type Scanner struct {
	interval   time.Duration
	mu         sync.RWMutex
	lastReport []AgentProcess
	onChange   func(agents []AgentProcess)
	selfPID    int
	stopCh     chan struct{}
	done       chan struct{}
}

// NewScanner creates a scanner that polls at the given interval.
// If interval is zero, a default of 5 seconds is used.
// The onChange callback is invoked whenever the set of detected agents changes.
func NewScanner(interval time.Duration, onChange func([]AgentProcess)) *Scanner {
	if interval <= 0 {
		interval = defaultInterval
	}
	return &Scanner{
		interval: interval,
		onChange: onChange,
		selfPID:  os.Getpid(),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start begins the scanning loop. It blocks until ctx is cancelled or Stop is called.
func (s *Scanner) Start(ctx context.Context) {
	defer close(s.done)

	// Perform an initial scan immediately.
	s.tick()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.tick()
		}
	}
}

// Stop signals the scanner to shut down.
func (s *Scanner) Stop() {
	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}
}

// Current returns a copy of the most recently detected agent processes.
func (s *Scanner) Current() []AgentProcess {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.lastReport == nil {
		return nil
	}
	out := make([]AgentProcess, len(s.lastReport))
	copy(out, s.lastReport)
	return out
}

func (s *Scanner) tick() {
	curr := scanProcesses(s.selfPID, KnownAgents)

	s.mu.Lock()
	prev := s.lastReport
	changed := hasChanged(prev, curr)
	if changed {
		s.lastReport = curr
	}
	s.mu.Unlock()

	if changed && s.onChange != nil {
		s.onChange(curr)
	}
}

// hasChanged returns true if the set of detected agents differs between prev and curr.
// It compares by PID and Platform — resource metrics are not considered a change.
func hasChanged(prev, curr []AgentProcess) bool {
	if len(prev) != len(curr) {
		return true
	}

	prevMap := make(map[int]string, len(prev))
	for _, a := range prev {
		prevMap[a.PID] = a.Platform
	}

	for _, a := range curr {
		if prevMap[a.PID] != a.Platform {
			return true
		}
	}

	// Check for removals: a PID in prev that is absent in curr.
	currMap := make(map[int]struct{}, len(curr))
	for _, a := range curr {
		currMap[a.PID] = struct{}{}
	}
	for _, a := range prev {
		if _, ok := currMap[a.PID]; !ok {
			return true
		}
	}

	return false
}
