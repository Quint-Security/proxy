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

// --- Temporal Correlation ---

// BurstThreshold is the number of actions within a short window that indicates delegation burst.
const BurstThreshold = 5

// BurstWindow is the time window for detecting delegation bursts.
const BurstWindow = 10 * time.Second

// DetectDelegationBurst checks if a session has a rapid burst of actions
// suggesting automated delegation (child agent pattern).
// Returns the burst count and whether it exceeds the threshold.
func (t *SessionTracker) DetectDelegationBurst(sessionKey string) (int, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	w, ok := t.sessions[sessionKey]
	if !ok || len(w.times) < BurstThreshold {
		return 0, false
	}

	// Count actions in the last BurstWindow
	cutoff := time.Now().Add(-BurstWindow)
	burstCount := 0
	for _, ts := range w.times {
		if ts.After(cutoff) {
			burstCount++
		}
	}

	return burstCount, burstCount >= BurstThreshold
}

// TemporalCorrelation checks if two sessions show correlated timing patterns
// suggesting a parent-child relationship.
// Returns a confidence score (0.0-1.0) based on temporal proximity.
func (t *SessionTracker) TemporalCorrelation(sessionA, sessionB string) float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	wA, okA := t.sessions[sessionA]
	wB, okB := t.sessions[sessionB]
	if !okA || !okB || len(wA.times) == 0 || len(wB.times) == 0 {
		return 0.0
	}

	// Check if sessionB started shortly after sessionA had activity
	firstB := wB.times[0]

	// Find closest action in A before B's first action
	var closestGap time.Duration = -1
	for _, ta := range wA.times {
		if ta.Before(firstB) {
			gap := firstB.Sub(ta)
			if closestGap < 0 || gap < closestGap {
				closestGap = gap
			}
		}
	}

	if closestGap < 0 {
		return 0.0
	}

	// Score based on temporal proximity:
	// < 1s → 0.50, < 5s → 0.40, < 30s → 0.30, < 60s → 0.20
	switch {
	case closestGap < 1*time.Second:
		return 0.50
	case closestGap < 5*time.Second:
		return 0.40
	case closestGap < 30*time.Second:
		return 0.30
	case closestGap < 60*time.Second:
		return 0.20
	default:
		return 0.0
	}
}

// ActionRate returns the average actions per second for a session in the recent window.
func (t *SessionTracker) ActionRate(sessionKey string) float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	w, ok := t.sessions[sessionKey]
	if !ok || len(w.times) < 2 {
		return 0.0
	}

	cutoff := time.Now().Add(-t.windowDuration)
	var recentTimes []time.Time
	for _, ts := range w.times {
		if ts.After(cutoff) {
			recentTimes = append(recentTimes, ts)
		}
	}

	if len(recentTimes) < 2 {
		return 0.0
	}

	span := recentTimes[len(recentTimes)-1].Sub(recentTimes[0])
	if span == 0 {
		return 0.0
	}

	return float64(len(recentTimes)) / span.Seconds()
}
