package risk

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	_ "modernc.org/sqlite"
)

const behaviorSchema = `
CREATE TABLE IF NOT EXISTS behavior_tracker (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_id  TEXT NOT NULL,
  timestamp   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_behavior_subject ON behavior_tracker(subject_id);
CREATE INDEX IF NOT EXISTS idx_behavior_ts      ON behavior_tracker(timestamp);
`

// BehaviorDB is a SQLite-backed behavior tracker.
type BehaviorDB struct {
	db *sql.DB
}

// OpenBehaviorDB opens (or creates) the behavior tracker database.
func OpenBehaviorDB(dataDir string) (*BehaviorDB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "behavior.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout%3d5000")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(behaviorSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &BehaviorDB{db: db}, nil
}

func (b *BehaviorDB) Record(subjectID string, ts int64) {
	_, err := b.db.Exec("INSERT INTO behavior_tracker (subject_id, timestamp) VALUES (?, ?)", subjectID, ts)
	if err != nil {
		qlog.Error("behavior record error: %v", err)
	}
}

// Count returns the number of entries for the subject after cutoff, and prunes older entries.
func (b *BehaviorDB) Count(subjectID string, cutoff int64) int {
	b.db.Exec("DELETE FROM behavior_tracker WHERE subject_id = ? AND timestamp <= ?", subjectID, cutoff)
	var cnt int
	b.db.QueryRow("SELECT COUNT(*) FROM behavior_tracker WHERE subject_id = ?", subjectID).Scan(&cnt)
	return cnt
}

func (b *BehaviorDB) Close() error {
	return b.db.Close()
}

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
	var kept []int64
	for _, ts := range entries {
		if ts > cutoff {
			kept = append(kept, ts)
		}
	}
	if len(kept) == 0 {
		delete(t.history, subjectID)
	} else {
		t.history[subjectID] = kept
	}
	return kept
}
