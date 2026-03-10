package risk

import (
	"database/sql"
	"os"
	"path/filepath"

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
