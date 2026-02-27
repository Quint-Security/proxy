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
	`ALTER TABLE audit_log ADD COLUMN scoring_source TEXT`,
	`ALTER TABLE audit_log ADD COLUMN local_score INTEGER`,
	`ALTER TABLE audit_log ADD COLUMN remote_score INTEGER`,
	`ALTER TABLE audit_log ADD COLUMN gnn_score REAL`,
	`ALTER TABLE audit_log ADD COLUMN confidence REAL`,
	`ALTER TABLE audit_log ADD COLUMN compliance_refs TEXT`,
	`ALTER TABLE audit_log ADD COLUMN behavioral_flags TEXT`,
	`ALTER TABLE audit_log ADD COLUMN score_decomposition TEXT`,
	`ALTER TABLE audit_log ADD COLUMN mitigations TEXT`,
}

const (
	busyRetries  = 5
	busyBaseWait = 50 * time.Millisecond
)

// Entry represents a single audit log row.
type Entry struct {
	ID                 int64
	Timestamp          string
	ServerName         string
	Direction          string
	Method             string
	MessageID          *string
	ToolName           *string
	ArgumentsJSON      *string
	ResponseJSON       *string
	Verdict            string
	RiskScore          *int
	RiskLevel          *string
	PolicyHash         string
	PrevHash           string
	Nonce              string
	Signature          string
	PublicKey          string
	AgentID            *string
	AgentName          *string
	ScoringSource      *string
	LocalScore         *int
	RemoteScore        *int
	GNNScore           *float64
	Confidence         *float64
	ComplianceRefs     *string
	BehavioralFlags    *string
	ScoreDecomposition *string
	Mitigations        *string
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
			 policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name,
			 scoring_source, local_score, remote_score, gnn_score, confidence,
			 compliance_refs, behavioral_flags, score_decomposition, mitigations)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp, entry.ServerName, entry.Direction, entry.Method,
		entry.MessageID, entry.ToolName, entry.ArgumentsJSON, entry.ResponseJSON,
		entry.Verdict, entry.RiskScore, entry.RiskLevel,
		entry.PolicyHash, entry.PrevHash, entry.Nonce, entry.Signature, entry.PublicKey,
		entry.AgentID, entry.AgentName,
		entry.ScoringSource, entry.LocalScore, entry.RemoteScore, entry.GNNScore, entry.Confidence,
		entry.ComplianceRefs, entry.BehavioralFlags, entry.ScoreDecomposition, entry.Mitigations,
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

// QueryOpts controls audit log queries.
type QueryOpts struct {
	Limit      int
	Offset     int
	Verdict    string
	ToolName   string
	ServerName string
	AgentName  string
}

// Query returns audit log entries matching the given filters.
func (d *DB) Query(opts QueryOpts) ([]Entry, int, error) {
	where := "1=1"
	args := []any{}

	if opts.Verdict != "" {
		where += " AND verdict = ?"
		args = append(args, opts.Verdict)
	}
	if opts.ToolName != "" {
		where += " AND tool_name LIKE ?"
		args = append(args, "%"+opts.ToolName+"%")
	}
	if opts.ServerName != "" {
		where += " AND server_name = ?"
		args = append(args, opts.ServerName)
	}
	if opts.AgentName != "" {
		where += " AND agent_name = ?"
		args = append(args, opts.AgentName)
	}

	// Count
	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE "+where, args...).Scan(&total)

	// Fetch
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(
		"SELECT id, timestamp, server_name, direction, method, message_id, tool_name, arguments_json, response_json, verdict, risk_score, risk_level, policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name, scoring_source, local_score, remote_score, gnn_score, confidence, compliance_refs, behavioral_flags, score_decomposition, mitigations FROM audit_log WHERE %s ORDER BY id DESC LIMIT ? OFFSET ?",
		where,
	)
	args = append(args, limit, opts.Offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ServerName, &e.Direction, &e.Method, &e.MessageID, &e.ToolName, &e.ArgumentsJSON, &e.ResponseJSON, &e.Verdict, &e.RiskScore, &e.RiskLevel, &e.PolicyHash, &e.PrevHash, &e.Nonce, &e.Signature, &e.PublicKey, &e.AgentID, &e.AgentName, &e.ScoringSource, &e.LocalScore, &e.RemoteScore, &e.GNNScore, &e.Confidence, &e.ComplianceRefs, &e.BehavioralFlags, &e.ScoreDecomposition, &e.Mitigations); err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}
	return entries, total, nil
}

// Stats returns summary statistics for the audit log.
func (d *DB) Stats() map[string]any {
	stats := map[string]any{}

	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&total)
	stats["total_entries"] = total

	var denied int
	d.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE verdict IN ('deny', 'scope_denied', 'flag_denied')").Scan(&denied)
	stats["denied"] = denied

	var flagged int
	d.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE risk_level = 'high' OR risk_level = 'critical'").Scan(&flagged)
	stats["high_risk"] = flagged

	var lastTimestamp string
	d.db.QueryRow("SELECT timestamp FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&lastTimestamp)
	stats["last_entry"] = lastTimestamp

	return stats
}

// RangeOpts controls time-range queries with optional filters.
type RangeOpts struct {
	Since      string // RFC3339 timestamp (inclusive)
	Until      string // RFC3339 timestamp (inclusive)
	ServerName string
	ToolName   string
	Verdict    string
}

// GetRange returns entries within a time range in ascending order.
func (d *DB) GetRange(opts RangeOpts) ([]Entry, error) {
	where := "1=1"
	args := []any{}

	if opts.Since != "" {
		where += " AND timestamp >= ?"
		args = append(args, opts.Since)
	}
	if opts.Until != "" {
		where += " AND timestamp <= ?"
		args = append(args, opts.Until)
	}
	if opts.ServerName != "" {
		where += " AND server_name = ?"
		args = append(args, opts.ServerName)
	}
	if opts.ToolName != "" {
		where += " AND tool_name LIKE ?"
		args = append(args, "%"+opts.ToolName+"%")
	}
	if opts.Verdict != "" {
		where += " AND verdict = ?"
		args = append(args, opts.Verdict)
	}

	query := fmt.Sprintf(
		`SELECT id, timestamp, server_name, direction, method, message_id, tool_name,
		        arguments_json, response_json, verdict, risk_score, risk_level,
		        policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name,
		        scoring_source, local_score, remote_score, gnn_score, confidence,
		        compliance_refs, behavioral_flags, score_decomposition, mitigations
		 FROM audit_log WHERE %s ORDER BY id ASC`, where,
	)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ServerName, &e.Direction, &e.Method,
			&e.MessageID, &e.ToolName, &e.ArgumentsJSON, &e.ResponseJSON, &e.Verdict,
			&e.RiskScore, &e.RiskLevel, &e.PolicyHash, &e.PrevHash, &e.Nonce,
			&e.Signature, &e.PublicKey, &e.AgentID, &e.AgentName,
			&e.ScoringSource, &e.LocalScore, &e.RemoteScore, &e.GNNScore, &e.Confidence,
			&e.ComplianceRefs, &e.BehavioralFlags, &e.ScoreDecomposition, &e.Mitigations); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Close closes the database.
func (d *DB) Close() error {
	return d.db.Close()
}

func isBusyError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SQLITE_BUSY")
}
