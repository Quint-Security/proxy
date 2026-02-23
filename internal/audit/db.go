package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Exact same DDL as TypeScript db.ts lines 7-31
const schema = `
CREATE TABLE IF NOT EXISTS audit_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp       TEXT NOT NULL,
  server_name     TEXT NOT NULL,
  direction       TEXT NOT NULL,
  method          TEXT NOT NULL,
  message_id      TEXT,
  tool_name       TEXT,
  arguments_json  TEXT,
  response_json   TEXT,
  verdict         TEXT NOT NULL,
  risk_score      INTEGER,
  risk_level      TEXT,
  policy_hash     TEXT NOT NULL DEFAULT '',
  prev_hash       TEXT NOT NULL DEFAULT '',
  nonce           TEXT NOT NULL DEFAULT '',
  signature       TEXT NOT NULL,
  public_key      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp   ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_server_name ON audit_log(server_name);
CREATE INDEX IF NOT EXISTS idx_tool_name   ON audit_log(tool_name);
CREATE INDEX IF NOT EXISTS idx_verdict     ON audit_log(verdict);
`

// Migrations for DBs created before risk/chain fields were added.
var migrations = []string{
	`ALTER TABLE audit_log ADD COLUMN policy_hash TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_log ADD COLUMN nonce TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_log ADD COLUMN risk_score INTEGER`,
	`ALTER TABLE audit_log ADD COLUMN risk_level TEXT`,
	`ALTER TABLE audit_log ADD COLUMN agent_id TEXT`,
	`ALTER TABLE audit_log ADD COLUMN agent_name TEXT`,
}

const (
	busyRetries  = 5
	busyBaseWait = 50 * time.Millisecond
)

// Entry represents a single audit log row.
type Entry struct {
	ID            int64
	Timestamp     string
	ServerName    string
	Direction     string
	Method        string
	MessageID     *string
	ToolName      *string
	ArgumentsJSON *string
	ResponseJSON  *string
	Verdict       string
	RiskScore     *int
	RiskLevel     *string
	PolicyHash    string
	PrevHash      string
	Nonce         string
	Signature     string
	PublicKey     string
	AgentID       *string
	AgentName     *string
}

// DB wraps the SQLite audit database.
type DB struct {
	db *sql.DB
}

// OpenDB opens (or creates) the audit database at the standard location.
func OpenDB(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "quint.db")
	return Open(dbPath)
}

// Open opens the audit database at the given path.
func Open(dbPath string) (*DB, error) {
	// Set busy_timeout via pragma to handle concurrent access from
	// multiple proxy instances sharing the same DB file.
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout%3d5000")
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

	// WAL mode for concurrent readers
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	// Create schema
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	// Apply migrations (ignore errors for already-existing columns)
	for _, m := range migrations {
		db.Exec(m)
	}

	return &DB{db: db}, nil
}

// InsertAtomic reads the last signature and inserts a new entry in one transaction.
// The builder function receives the previous signature (or "") and returns the entry to insert.
// Retries on SQLITE_BUSY with exponential backoff.
func (d *DB) InsertAtomic(buildEntry func(prevSignature string) Entry) (int64, error) {
	for attempt := 0; attempt <= busyRetries; attempt++ {
		id, err := d.tryInsertAtomic(buildEntry)
		if err == nil {
			return id, nil
		}
		if !isBusyError(err) || attempt == busyRetries {
			return 0, err
		}
		wait := busyBaseWait * time.Duration(1<<uint(attempt))
		time.Sleep(wait)
	}
	return 0, fmt.Errorf("insert failed after %d retries", busyRetries)
}

func (d *DB) tryInsertAtomic(buildEntry func(prevSignature string) Entry) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Read last signature
	var prevSig string
	row := tx.QueryRow("SELECT signature FROM audit_log ORDER BY id DESC LIMIT 1")
	if err := row.Scan(&prevSig); err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("read last signature: %w", err)
	}

	entry := buildEntry(prevSig)

	result, err := tx.Exec(`
		INSERT INTO audit_log
			(timestamp, server_name, direction, method, message_id, tool_name,
			 arguments_json, response_json, verdict, risk_score, risk_level,
			 policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp, entry.ServerName, entry.Direction, entry.Method,
		entry.MessageID, entry.ToolName, entry.ArgumentsJSON, entry.ResponseJSON,
		entry.Verdict, entry.RiskScore, entry.RiskLevel,
		entry.PolicyHash, entry.PrevHash, entry.Nonce, entry.Signature, entry.PublicKey,
		entry.AgentID, entry.AgentName,
	)
	if err != nil {
		return 0, fmt.Errorf("insert audit entry: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}

	id, _ := result.LastInsertId()
	return id, nil
}

// GetLastSignature returns the signature of the most recent entry, or "".
func (d *DB) GetLastSignature() string {
	var sig string
	d.db.QueryRow("SELECT signature FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&sig)
	return sig
}

// Close closes the database.
func (d *DB) Close() error {
	return d.db.Close()
}

func isBusyError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SQLITE_BUSY")
}
