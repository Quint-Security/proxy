package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/crypto"
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

CREATE TABLE IF NOT EXISTS agent_relationships (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_agent    TEXT NOT NULL,
  child_agent     TEXT NOT NULL,
  confidence      REAL NOT NULL DEFAULT 0.0,
  depth           INTEGER NOT NULL DEFAULT 0,
  spawn_type      TEXT,
  signal_type     TEXT,
  first_seen      TEXT NOT NULL,
  last_seen       TEXT NOT NULL,
  signal_count    INTEGER NOT NULL DEFAULT 1,
  trace_id        TEXT,
  UNIQUE(parent_agent, child_agent)
);

CREATE TABLE IF NOT EXISTS spawn_events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp       TEXT NOT NULL,
  pattern_id      TEXT NOT NULL,
  parent_agent    TEXT NOT NULL,
  child_hint      TEXT,
  spawn_type      TEXT NOT NULL,
  confidence      REAL NOT NULL,
  tool_name       TEXT NOT NULL,
  server_name     TEXT NOT NULL,
  arguments_ref   TEXT
);

CREATE INDEX IF NOT EXISTS idx_timestamp   ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_server_name ON audit_log(server_name);
CREATE INDEX IF NOT EXISTS idx_tool_name   ON audit_log(tool_name);
CREATE INDEX IF NOT EXISTS idx_verdict     ON audit_log(verdict);
CREATE INDEX IF NOT EXISTS idx_rel_parent  ON agent_relationships(parent_agent);
CREATE INDEX IF NOT EXISTS idx_rel_child   ON agent_relationships(child_agent);
CREATE INDEX IF NOT EXISTS idx_spawn_ts    ON spawn_events(timestamp);
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
	`ALTER TABLE audit_log ADD COLUMN cloud_event_id TEXT`,
	`ALTER TABLE audit_log ADD COLUMN trace_id TEXT`,
	`ALTER TABLE audit_log ADD COLUMN agent_depth INTEGER`,
	`ALTER TABLE audit_log ADD COLUMN parent_agent_id TEXT`,
	`ALTER TABLE audit_log ADD COLUMN spawn_detected TEXT`,
	`CREATE TABLE IF NOT EXISTS agent_relationships (
		id INTEGER PRIMARY KEY AUTOINCREMENT, parent_agent TEXT NOT NULL, child_agent TEXT NOT NULL,
		confidence REAL NOT NULL DEFAULT 0.0, depth INTEGER NOT NULL DEFAULT 0, spawn_type TEXT,
		signal_type TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
		signal_count INTEGER NOT NULL DEFAULT 1, trace_id TEXT, UNIQUE(parent_agent, child_agent))`,
	`CREATE TABLE IF NOT EXISTS spawn_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, pattern_id TEXT NOT NULL,
		parent_agent TEXT NOT NULL, child_hint TEXT, spawn_type TEXT NOT NULL,
		confidence REAL NOT NULL, tool_name TEXT NOT NULL, server_name TEXT NOT NULL, arguments_ref TEXT)`,
	`CREATE INDEX IF NOT EXISTS idx_rel_parent ON agent_relationships(parent_agent)`,
	`CREATE INDEX IF NOT EXISTS idx_rel_child ON agent_relationships(child_agent)`,
	`CREATE INDEX IF NOT EXISTS idx_spawn_ts ON spawn_events(timestamp)`,
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
	CloudEventID       *string
	TraceID            *string
	AgentDepth         *int
	ParentAgentID      *string
	SpawnDetected      *string
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
			 compliance_refs, behavioral_flags, score_decomposition, mitigations, cloud_event_id,
			 trace_id, agent_depth, parent_agent_id, spawn_detected)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp, entry.ServerName, entry.Direction, entry.Method,
		entry.MessageID, entry.ToolName, entry.ArgumentsJSON, entry.ResponseJSON,
		entry.Verdict, entry.RiskScore, entry.RiskLevel,
		entry.PolicyHash, entry.PrevHash, entry.Nonce, entry.Signature, entry.PublicKey,
		entry.AgentID, entry.AgentName,
		entry.ScoringSource, entry.LocalScore, entry.RemoteScore, entry.GNNScore, entry.Confidence,
		entry.ComplianceRefs, entry.BehavioralFlags, entry.ScoreDecomposition, entry.Mitigations,
		entry.CloudEventID, entry.TraceID, entry.AgentDepth, entry.ParentAgentID, entry.SpawnDetected,
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
		"SELECT id, timestamp, server_name, direction, method, message_id, tool_name, arguments_json, response_json, verdict, risk_score, risk_level, policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name, scoring_source, local_score, remote_score, gnn_score, confidence, compliance_refs, behavioral_flags, score_decomposition, mitigations, cloud_event_id, trace_id, agent_depth, parent_agent_id, spawn_detected FROM audit_log WHERE %s ORDER BY id DESC LIMIT ? OFFSET ?",
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
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ServerName, &e.Direction, &e.Method, &e.MessageID, &e.ToolName, &e.ArgumentsJSON, &e.ResponseJSON, &e.Verdict, &e.RiskScore, &e.RiskLevel, &e.PolicyHash, &e.PrevHash, &e.Nonce, &e.Signature, &e.PublicKey, &e.AgentID, &e.AgentName, &e.ScoringSource, &e.LocalScore, &e.RemoteScore, &e.GNNScore, &e.Confidence, &e.ComplianceRefs, &e.BehavioralFlags, &e.ScoreDecomposition, &e.Mitigations, &e.CloudEventID, &e.TraceID, &e.AgentDepth, &e.ParentAgentID, &e.SpawnDetected); err != nil {
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
		        compliance_refs, behavioral_flags, score_decomposition, mitigations, cloud_event_id,
		        trace_id, agent_depth, parent_agent_id, spawn_detected
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
			&e.ComplianceRefs, &e.BehavioralFlags, &e.ScoreDecomposition, &e.Mitigations,
			&e.CloudEventID, &e.TraceID, &e.AgentDepth, &e.ParentAgentID, &e.SpawnDetected); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// VerifyChain checks the integrity of the audit chain.
// Returns the number of verified entries and the first broken link (if any).
// A broken link is indicated by brokenAt != 0.
func (d *DB) VerifyChain() (verified int, brokenAt int64, err error) {
	entries, err := d.GetAll()
	if err != nil {
		return 0, 0, fmt.Errorf("get all entries: %w", err)
	}

	if len(entries) == 0 {
		return 0, 0, nil
	}

	// First entry should have empty prev_hash
	if entries[0].PrevHash != "" {
		return 0, entries[0].ID, nil
	}

	verified = 1

	// Verify chain links
	for i := 1; i < len(entries); i++ {
		prev := entries[i-1]
		curr := entries[i]

		// Legacy entries (before chain was added) have empty prev_hash
		if curr.PrevHash == "" && prev.PrevHash == "" {
			verified++
			continue
		}

		// Compute expected hash from previous signature
		expectedHash := crypto.SHA256Hex(prev.Signature)
		if curr.PrevHash != expectedHash {
			return verified, curr.ID, nil
		}

		verified++
	}

	return verified, 0, nil
}

// InsertSpawnEvent records a spawn detection event.
func (d *DB) InsertSpawnEvent(timestamp, patternID, parentAgent, childHint, spawnType, toolName, serverName, argsRef string, confidence float64) error {
	_, err := d.db.Exec(`
		INSERT INTO spawn_events (timestamp, pattern_id, parent_agent, child_hint, spawn_type, confidence, tool_name, server_name, arguments_ref)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		timestamp, patternID, parentAgent, childHint, spawnType, confidence, toolName, serverName, argsRef,
	)
	return err
}

// UpsertRelationship creates or updates an agent relationship.
func (d *DB) UpsertRelationship(parentAgent, childAgent string, confidence float64, depth int, spawnType, signalType, traceID string) error {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	_, err := d.db.Exec(`
		INSERT INTO agent_relationships (parent_agent, child_agent, confidence, depth, spawn_type, signal_type, first_seen, last_seen, signal_count, trace_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT(parent_agent, child_agent) DO UPDATE SET
			confidence = MAX(confidence, excluded.confidence),
			last_seen = excluded.last_seen,
			signal_count = signal_count + 1,
			trace_id = COALESCE(excluded.trace_id, trace_id)`,
		parentAgent, childAgent, confidence, depth, spawnType, signalType, now, now, traceID,
	)
	return err
}

// GetAgentRelationships returns all relationships for an agent (as parent or child).
func (d *DB) GetAgentRelationships(agentID string) ([]AgentRelationshipRow, error) {
	rows, err := d.db.Query(`
		SELECT id, parent_agent, child_agent, confidence, depth, spawn_type, signal_type, first_seen, last_seen, signal_count, trace_id
		FROM agent_relationships WHERE parent_agent = ? OR child_agent = ? ORDER BY last_seen DESC`, agentID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AgentRelationshipRow
	for rows.Next() {
		var r AgentRelationshipRow
		if err := rows.Scan(&r.ID, &r.ParentAgent, &r.ChildAgent, &r.Confidence, &r.Depth, &r.SpawnType, &r.SignalType, &r.FirstSeen, &r.LastSeen, &r.SignalCount, &r.TraceID); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// AgentRelationshipRow represents a row from the agent_relationships table.
type AgentRelationshipRow struct {
	ID          int64
	ParentAgent string
	ChildAgent  string
	Confidence  float64
	Depth       int
	SpawnType   *string
	SignalType  *string
	FirstSeen   string
	LastSeen    string
	SignalCount int
	TraceID     *string
}

// GetAllRelationships returns all agent relationships.
func (d *DB) GetAllRelationships() ([]AgentRelationshipRow, error) {
	rows, err := d.db.Query(`
		SELECT id, parent_agent, child_agent, confidence, depth, spawn_type, signal_type, first_seen, last_seen, signal_count, trace_id
		FROM agent_relationships ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AgentRelationshipRow
	for rows.Next() {
		var r AgentRelationshipRow
		if err := rows.Scan(&r.ID, &r.ParentAgent, &r.ChildAgent, &r.Confidence, &r.Depth, &r.SpawnType, &r.SignalType, &r.FirstSeen, &r.LastSeen, &r.SignalCount, &r.TraceID); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// SpawnEventRow represents a row from the spawn_events table.
type SpawnEventRow struct {
	ID           int64
	Timestamp    string
	PatternID    string
	ParentAgent  string
	ChildHint    *string
	SpawnType    string
	Confidence   float64
	ToolName     string
	ServerName   string
	ArgumentsRef *string
}

// GetAllSpawnEvents returns all spawn detection events.
func (d *DB) GetAllSpawnEvents() ([]SpawnEventRow, error) {
	rows, err := d.db.Query(`
		SELECT id, timestamp, pattern_id, parent_agent, child_hint, spawn_type, confidence, tool_name, server_name, arguments_ref
		FROM spawn_events ORDER BY timestamp ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SpawnEventRow
	for rows.Next() {
		var r SpawnEventRow
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.PatternID, &r.ParentAgent, &r.ChildHint, &r.SpawnType, &r.Confidence, &r.ToolName, &r.ServerName, &r.ArgumentsRef); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// Close closes the database.
func (d *DB) Close() error {
	return d.db.Close()
}

func isBusyError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SQLITE_BUSY")
}
