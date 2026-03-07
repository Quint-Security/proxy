package risk

import (
	"sync"
	"time"
)

// BehaviorTracker tracks repeated high-risk behavior per subject.
// Uses SQLite when a BehaviorDB is provided, falls back to in-memory.
type BehaviorTracker struct {
	mu       sync.Mutex
	history  map[string][]int64 // in-memory fallback
	windowMs int64
	db       *BehaviorDB
}

// NewBehaviorTracker creates a new tracker.
func NewBehaviorTracker(windowMs int64, db *BehaviorDB) *BehaviorTracker {
	return &BehaviorTracker{
		history:  make(map[string][]int64),
		windowMs: windowMs,
		db:       db,
	}
}

func (t *BehaviorTracker) Record(subjectID string) {
	now := time.Now().UnixMilli()
	if t.db != nil {
		t.db.Record(subjectID, now)
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneInMemory(subjectID)
	t.history[subjectID] = append(t.history[subjectID], now)
}

func (t *BehaviorTracker) Count(subjectID string) int {
	if t.db != nil {
		cutoff := time.Now().UnixMilli() - t.windowMs
		return t.db.Count(subjectID, cutoff)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pruneInMemory(subjectID))
}

func (t *BehaviorTracker) pruneInMemory(subjectID string) []int64 {
	cutoff := time.Now().UnixMilli() - t.windowMs
	entries := t.history[subjectID]

	// Find first entry within window (entries are ordered by time)
	start := 0
	for start < len(entries) && entries[start] <= cutoff {
		start++
	}

	if start == len(entries) {
		delete(t.history, subjectID)
		return nil
	}

	if start == 0 {
		return entries // nothing to prune
	}

	// Shift in place to avoid allocating a new slice
	kept := entries[:copy(entries, entries[start:])]
	t.history[subjectID] = kept
	return kept
}
