package risk

import (
	"sync"
	"time"
)

// SessionTracker tracks the last N actions per agent/session for behavioral context.
type SessionTracker struct {
	mu             sync.RWMutex
	sessions       map[string]*actionWindow
	maxActions     int
	windowDuration time.Duration
}

type actionWindow struct {
	actions []string
	times   []time.Time
}

// NewSessionTracker creates a session tracker with the given limits.
// Default: 20 actions, 30-minute window.
func NewSessionTracker(maxActions int, windowDuration time.Duration) *SessionTracker {
	if maxActions <= 0 {
		maxActions = 20
	}
	if windowDuration <= 0 {
		windowDuration = 30 * time.Minute
	}
	return &SessionTracker{
		sessions:       make(map[string]*actionWindow),
		maxActions:     maxActions,
		windowDuration: windowDuration,
	}
}

// Record adds an action to the session's history.
func (t *SessionTracker) Record(sessionKey, action string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	w, ok := t.sessions[sessionKey]
	if !ok {
		w = &actionWindow{}
		t.sessions[sessionKey] = w
	}

	now := time.Now()
	w.actions = append(w.actions, action)
	w.times = append(w.times, now)

	// Trim to max size
	if len(w.actions) > t.maxActions {
		excess := len(w.actions) - t.maxActions
		w.actions = w.actions[excess:]
		w.times = w.times[excess:]
	}
}

// Recent returns the last N actions for a session within the time window.
func (t *SessionTracker) Recent(sessionKey string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	w, ok := t.sessions[sessionKey]
	if !ok {
		return nil
	}

	cutoff := time.Now().Add(-t.windowDuration)
	var result []string
	for i, ts := range w.times {
		if ts.After(cutoff) {
			result = append(result, w.actions[i])
		}
	}
	return result
}
