package approval

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const approvalSchema = `
CREATE TABLE IF NOT EXISTS approval_requests (
  id              TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  agent_name      TEXT NOT NULL,
  tool_name       TEXT NOT NULL,
  arguments_json  TEXT NOT NULL DEFAULT '',
  server_name     TEXT NOT NULL,
  risk_score      INTEGER,
  risk_level      TEXT,
  status          TEXT NOT NULL DEFAULT 'pending',
  decision_by     TEXT,
  decision_sig    TEXT,
  created_at      TEXT NOT NULL,
  decided_at      TEXT,
  expires_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_agent  ON approval_requests(agent_id);
`

// Status constants for approval requests.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
)

// Request represents a pending approval request.
type Request struct {
	ID            string
	AgentID       string
	AgentName     string
	ToolName      string
	ArgumentsJSON string
	ServerName    string
	RiskScore     *int
	RiskLevel     *string
	Status        string
	DecisionBy    *string
	DecisionSig   *string
	CreatedAt     string
	DecidedAt     *string
	ExpiresAt     string
}

// DB wraps the SQLite approval database.
type DB struct {
	db *sql.DB
}

// OpenDB opens (or creates) the approval database.
func OpenDB(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "approvals.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout%3d5000")
	if err != nil {
		return nil, err
	}
	db.Exec("PRAGMA journal_mode = WAL")
	if _, err := db.Exec(approvalSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db: db}, nil
}

// Create creates a new approval request and returns it.
func (d *DB) Create(agentID, agentName, toolName, argsJSON, serverName string, riskScore *int, riskLevel *string, timeoutSeconds int) (*Request, error) {
	id := uuid.New().String()
	now := time.Now().UTC()
	createdAt := now.Format(time.RFC3339)
	expiresAt := now.Add(time.Duration(timeoutSeconds) * time.Second).Format(time.RFC3339)

	_, err := d.db.Exec(`
		INSERT INTO approval_requests (id, agent_id, agent_name, tool_name, arguments_json, server_name, risk_score, risk_level, status, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, agentID, agentName, toolName, argsJSON, serverName, riskScore, riskLevel, StatusPending, createdAt, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert approval request: %w", err)
	}

	return &Request{
		ID: id, AgentID: agentID, AgentName: agentName,
		ToolName: toolName, ArgumentsJSON: argsJSON, ServerName: serverName,
		RiskScore: riskScore, RiskLevel: riskLevel,
		Status: StatusPending, CreatedAt: createdAt, ExpiresAt: expiresAt,
	}, nil
}

// Get retrieves an approval request by ID.
func (d *DB) Get(id string) (*Request, error) {
	r := &Request{}
	err := d.db.QueryRow(`
		SELECT id, agent_id, agent_name, tool_name, arguments_json, server_name,
		       risk_score, risk_level, status, decision_by, decision_sig,
		       created_at, decided_at, expires_at
		FROM approval_requests WHERE id = ?`, id,
	).Scan(
		&r.ID, &r.AgentID, &r.AgentName, &r.ToolName, &r.ArgumentsJSON, &r.ServerName,
		&r.RiskScore, &r.RiskLevel, &r.Status, &r.DecisionBy, &r.DecisionSig,
		&r.CreatedAt, &r.DecidedAt, &r.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get approval request: %w", err)
	}
	return r, nil
}

// ListPending returns all pending (non-expired) approval requests.
func (d *DB) ListPending() ([]*Request, error) {
	// Expire old requests first
	d.expireOld()

	rows, err := d.db.Query(`
		SELECT id, agent_id, agent_name, tool_name, arguments_json, server_name,
		       risk_score, risk_level, status, decision_by, decision_sig,
		       created_at, decided_at, expires_at
		FROM approval_requests WHERE status = ? ORDER BY created_at DESC`, StatusPending,
	)
	if err != nil {
		return nil, fmt.Errorf("list pending approvals: %w", err)
	}
	defer rows.Close()

	var out []*Request
	for rows.Next() {
		r := &Request{}
		if err := rows.Scan(
			&r.ID, &r.AgentID, &r.AgentName, &r.ToolName, &r.ArgumentsJSON, &r.ServerName,
			&r.RiskScore, &r.RiskLevel, &r.Status, &r.DecisionBy, &r.DecisionSig,
			&r.CreatedAt, &r.DecidedAt, &r.ExpiresAt,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Decide approves or denies an approval request.
func (d *DB) Decide(id string, approved bool, decidedBy string, signature string) error {
	status := StatusDenied
	if approved {
		status = StatusApproved
	}
	now := time.Now().UTC().Format(time.RFC3339)

	result, err := d.db.Exec(`
		UPDATE approval_requests
		SET status = ?, decision_by = ?, decision_sig = ?, decided_at = ?
		WHERE id = ? AND status = ?`,
		status, decidedBy, signature, now, id, StatusPending,
	)
	if err != nil {
		return fmt.Errorf("decide approval: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("approval %s is not pending (already decided or expired)", id)
	}
	return nil
}

// IsApproved checks if a given approval ID has been approved and is not expired.
func (d *DB) IsApproved(id string) bool {
	r, err := d.Get(id)
	if err != nil || r == nil {
		return false
	}
	if r.Status != StatusApproved {
		return false
	}
	expires, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().Before(expires)
}

func (d *DB) expireOld() {
	now := time.Now().UTC().Format(time.RFC3339)
	d.db.Exec(`UPDATE approval_requests SET status = ? WHERE status = ? AND expires_at < ?`,
		StatusExpired, StatusPending, now)
}

// Close closes the database.
func (d *DB) Close() error {
	return d.db.Close()
}
