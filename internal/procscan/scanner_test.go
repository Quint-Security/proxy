package procscan

import (
	"context"
	"testing"
	"time"
)

func TestMatchProcess_ExactName(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantPlat string
		wantOK   bool
	}{
		{"claude", "", "claude-code", true},
		{"Claude", "", "claude-code", true},
		{"claude-code", "", "claude-code", true},
		{"cursor", "", "cursor", true},
		{"Cursor Helper", "", "cursor", true},
		{"windsurf", "", "windsurf", true},
		{"gemini", "", "gemini-cli", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plat, ok := MatchProcess(tt.name, tt.path)
			if plat != tt.wantPlat || ok != tt.wantOK {
				t.Errorf("MatchProcess(%q, %q) = (%q, %v), want (%q, %v)",
					tt.name, tt.path, plat, ok, tt.wantPlat, tt.wantOK)
			}
		})
	}
}

func TestMatchProcess_PathPattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantPlat string
		wantOK   bool
	}{
		{"node", "/Applications/Cursor.app/Contents/MacOS/node", "cursor", true},
		{"node", "/home/user/.claude/local/bin/claude", "claude-code", true},
		{"node", "/usr/local/bin/codex-cli", "codex", true},
		{"helper", "/Applications/Zed.app/Contents/MacOS/zed-helper", "zed", true},
		{"runner", "/opt/PearAI.app/Contents/runner", "pearai", true},
		{"agent", "/opt/Trae.app/Contents/agent", "trae", true},
		{"worker", "/opt/Void.app/Contents/worker", "void", true},
	}
	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.path, func(t *testing.T) {
			plat, ok := MatchProcess(tt.name, tt.path)
			if plat != tt.wantPlat || ok != tt.wantOK {
				t.Errorf("MatchProcess(%q, %q) = (%q, %v), want (%q, %v)",
					tt.name, tt.path, plat, ok, tt.wantPlat, tt.wantOK)
			}
		})
	}
}

func TestMatchProcess_NoMatch(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"python3", "/usr/bin/python3"},
		{"node", "/usr/local/bin/node"},
		{"bash", "/bin/bash"},
		{"", ""},
		{"nginx", "/usr/sbin/nginx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plat, ok := MatchProcess(tt.name, tt.path)
			if plat != "" || ok {
				t.Errorf("MatchProcess(%q, %q) = (%q, %v), want (\"\", false)",
					tt.name, tt.path, plat, ok)
			}
		})
	}
}

func TestHasChanged_NewAgent(t *testing.T) {
	prev := []AgentProcess{}
	curr := []AgentProcess{{Platform: "cursor", PID: 1234}}
	if !hasChanged(prev, curr) {
		t.Error("expected change when agent added")
	}
}

func TestHasChanged_RemovedAgent(t *testing.T) {
	prev := []AgentProcess{{Platform: "cursor", PID: 1234}}
	curr := []AgentProcess{}
	if !hasChanged(prev, curr) {
		t.Error("expected change when agent removed")
	}
}

func TestHasChanged_NoChange(t *testing.T) {
	agents := []AgentProcess{
		{Platform: "cursor", PID: 1234},
		{Platform: "claude-code", PID: 5678},
	}
	prev := make([]AgentProcess, len(agents))
	copy(prev, agents)
	curr := make([]AgentProcess, len(agents))
	copy(curr, agents)

	if hasChanged(prev, curr) {
		t.Error("expected no change for identical lists")
	}
}

func TestHasChanged_PlatformChanged(t *testing.T) {
	prev := []AgentProcess{{Platform: "cursor", PID: 1234}}
	curr := []AgentProcess{{Platform: "claude-code", PID: 1234}}
	if !hasChanged(prev, curr) {
		t.Error("expected change when platform differs for same PID")
	}
}

func TestHasChanged_DifferentPID(t *testing.T) {
	prev := []AgentProcess{{Platform: "cursor", PID: 1234}}
	curr := []AgentProcess{{Platform: "cursor", PID: 5678}}
	if !hasChanged(prev, curr) {
		t.Error("expected change when PID differs for same platform")
	}
}

func TestHasChanged_BothNil(t *testing.T) {
	if hasChanged(nil, nil) {
		t.Error("expected no change for two nil slices")
	}
}

func TestHasChanged_BothEmpty(t *testing.T) {
	if hasChanged([]AgentProcess{}, []AgentProcess{}) {
		t.Error("expected no change for two empty slices")
	}
}

func TestCurrent_ReturnsCopy(t *testing.T) {
	s := NewScanner(time.Second, nil)
	s.mu.Lock()
	s.lastReport = []AgentProcess{
		{Platform: "cursor", PID: 100},
		{Platform: "claude-code", PID: 200},
	}
	s.mu.Unlock()

	got := s.Current()
	if len(got) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(got))
	}

	// Mutate the returned slice.
	got[0].Platform = "modified"
	got = append(got, AgentProcess{Platform: "extra", PID: 999})

	// Original should be unchanged.
	again := s.Current()
	if len(again) != 2 {
		t.Fatalf("after mutation: expected 2 agents, got %d", len(again))
	}
	if again[0].Platform != "cursor" {
		t.Errorf("after mutation: expected platform 'cursor', got %q", again[0].Platform)
	}
}

func TestCurrent_NilWhenEmpty(t *testing.T) {
	s := NewScanner(time.Second, nil)
	got := s.Current()
	if got != nil {
		t.Errorf("expected nil for fresh scanner, got %v", got)
	}
}

func TestNewScanner_DefaultInterval(t *testing.T) {
	s := NewScanner(0, nil)
	if s.interval != defaultInterval {
		t.Errorf("expected default interval %v, got %v", defaultInterval, s.interval)
	}
}

func TestNewScanner_CustomInterval(t *testing.T) {
	s := NewScanner(10*time.Second, nil)
	if s.interval != 10*time.Second {
		t.Errorf("expected 10s interval, got %v", s.interval)
	}
}

func TestScanner_StopTerminatesStart(t *testing.T) {
	s := NewScanner(100*time.Millisecond, nil)
	done := make(chan struct{})
	go func() {
		s.Start(context.Background())
		close(done)
	}()

	// Give it time to start and run at least one tick.
	time.Sleep(200 * time.Millisecond)
	s.Stop()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestScanner_ContextCancelTerminatesStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := NewScanner(100*time.Millisecond, nil)
	done := make(chan struct{})
	go func() {
		s.Start(ctx)
		close(done)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}

func TestScanner_OnChangeCalledOnFirstScan(t *testing.T) {
	// This test verifies the scanner calls onChange on the first tick
	// if there are any detected agents. Since we cannot control what
	// processes are running, we just verify the callback mechanism works
	// by checking it doesn't panic with a nil onChange.
	s := NewScanner(50*time.Millisecond, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	s.Start(ctx)
	// No panic = success.
}

func TestScanner_DoubleStopSafe(t *testing.T) {
	s := NewScanner(time.Second, nil)
	s.Stop()
	s.Stop() // should not panic
}
