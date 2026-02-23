package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const authSchema = `
CREATE TABLE IF NOT EXISTS api_keys (
  id              TEXT PRIMARY KEY,
  key_hash        TEXT NOT NULL UNIQUE,
  owner_id        TEXT NOT NULL,
  label           TEXT NOT NULL,
  scopes          TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL,
  expires_at      TEXT,
  revoked         INTEGER NOT NULL DEFAULT 0,
  rate_limit_rpm  INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  subject_id  TEXT NOT NULL,
  auth_method TEXT NOT NULL,
  scopes      TEXT NOT NULL DEFAULT '',
  issued_at   TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agents (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  type         TEXT NOT NULL DEFAULT 'generic',
  description  TEXT NOT NULL DEFAULT '',
  scopes       TEXT NOT NULL DEFAULT '',
  api_key_id   TEXT NOT NULL,
  creator_id   TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash    ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner   ON api_keys(owner_id);
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject_id);
CREATE INDEX IF NOT EXISTS idx_agents_name      ON agents(name);
CREATE INDEX IF NOT EXISTS idx_agents_api_key   ON agents(api_key_id);
`

const apiKeyPrefix = "qk_"

type ApiKey struct {
	ID           string
	KeyHash      string
	OwnerID      string
	Label        string
	Scopes       string
	CreatedAt    string
	ExpiresAt    *string
	Revoked      bool
	RateLimitRpm *int
}

// Agent represents a registered agent identity.
type Agent struct {
	ID          string
	Name        string
	Type        string
	Description string
	Scopes      string
	ApiKeyID    string
	CreatorID   string
	Status      string
	CreatedAt   string
	UpdatedAt   string
}

type AuthResult struct {
	Type         string // "api_key" or "session"
	SubjectID    string
	Scopes       string
	RateLimitRpm *int
}

type DB struct {
	db *sql.DB
}

func OpenDB(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "auth.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout%3d5000")
	if err != nil {
		return nil, err
	}
	db.Exec("PRAGMA journal_mode = WAL")
	if _, err := db.Exec(authSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db: db}, nil
}

func hashKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// AuthenticateBearer checks a bearer token as either a session or API key.
func (d *DB) AuthenticateBearer(token string) *AuthResult {
	// Try as session first
	var subjectID, scopes, expiresAt string
	var revoked int
	err := d.db.QueryRow("SELECT subject_id, scopes, expires_at, revoked FROM sessions WHERE id = ?", token).
		Scan(&subjectID, &scopes, &expiresAt, &revoked)
	if err == nil && revoked == 0 {
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil && t.After(time.Now()) {
			// Look up originating API key for rate limit
			var rpm *int
			d.db.QueryRow("SELECT rate_limit_rpm FROM api_keys WHERE id = ?", subjectID).Scan(&rpm)
			return &AuthResult{Type: "session", SubjectID: subjectID, Scopes: scopes, RateLimitRpm: rpm}
		}
	}

	// Try as raw API key
	keyHash := hashKey(token)
	var key ApiKey
	var revokedInt int
	err = d.db.QueryRow(
		"SELECT id, scopes, expires_at, revoked, rate_limit_rpm FROM api_keys WHERE key_hash = ?", keyHash,
	).Scan(&key.ID, &key.Scopes, &key.ExpiresAt, &revokedInt, &key.RateLimitRpm)
	if err != nil || revokedInt != 0 {
		return nil
	}
	if key.ExpiresAt != nil {
		if t, err := time.Parse(time.RFC3339, *key.ExpiresAt); err == nil && t.Before(time.Now()) {
			return nil
		}
	}
	return &AuthResult{Type: "api_key", SubjectID: key.ID, Scopes: key.Scopes, RateLimitRpm: key.RateLimitRpm}
}

// GenerateApiKey creates a new API key and returns the raw key (shown once).
func (d *DB) GenerateApiKey(label, ownerID string, scopes string) (string, error) {
	rawBytes := make([]byte, 32)
	rand.Read(rawBytes)
	rawKey := apiKeyPrefix + hex.EncodeToString(rawBytes)
	id := apiKeyPrefix + uuid.New().String()[:16]
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := d.db.Exec(
		"INSERT INTO api_keys (id, key_hash, owner_id, label, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, hashKey(rawKey), ownerID, label, scopes, now,
	)
	if err != nil {
		return "", fmt.Errorf("insert api key: %w", err)
	}
	return rawKey, nil
}

// CreateAgent creates a new agent with its own API key. Returns the agent and raw API key (shown once).
func (d *DB) CreateAgent(name, agentType, description, scopes, creatorID string) (*Agent, string, error) {
	// Generate an API key for this agent
	rawBytes := make([]byte, 32)
	rand.Read(rawBytes)
	rawKey := apiKeyPrefix + hex.EncodeToString(rawBytes)
	keyID := apiKeyPrefix + uuid.New().String()[:16]
	now := time.Now().UTC().Format(time.RFC3339)

	agentID := "agent_" + uuid.New().String()[:12]

	tx, err := d.db.Begin()
	if err != nil {
		return nil, "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Insert API key
	_, err = tx.Exec(
		"INSERT INTO api_keys (id, key_hash, owner_id, label, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		keyID, hashKey(rawKey), agentID, "agent:"+name, scopes, now,
	)
	if err != nil {
		return nil, "", fmt.Errorf("insert agent api key: %w", err)
	}

	// Insert agent
	_, err = tx.Exec(
		`INSERT INTO agents (id, name, type, description, scopes, api_key_id, creator_id, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
		agentID, name, agentType, description, scopes, keyID, creatorID, now, now,
	)
	if err != nil {
		return nil, "", fmt.Errorf("insert agent: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("commit: %w", err)
	}

	return &Agent{
		ID: agentID, Name: name, Type: agentType, Description: description,
		Scopes: scopes, ApiKeyID: keyID, CreatorID: creatorID,
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}, rawKey, nil
}

// GetAgentByName retrieves an agent by name.
func (d *DB) GetAgentByName(name string) (*Agent, error) {
	a := &Agent{}
	err := d.db.QueryRow(
		`SELECT id, name, type, description, scopes, api_key_id, creator_id, status, created_at, updated_at
		 FROM agents WHERE name = ?`, name,
	).Scan(&a.ID, &a.Name, &a.Type, &a.Description, &a.Scopes, &a.ApiKeyID, &a.CreatorID, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// GetAgentByApiKeyID retrieves an agent by its API key ID.
func (d *DB) GetAgentByApiKeyID(keyID string) (*Agent, error) {
	a := &Agent{}
	err := d.db.QueryRow(
		`SELECT id, name, type, description, scopes, api_key_id, creator_id, status, created_at, updated_at
		 FROM agents WHERE api_key_id = ? AND status = 'active'`, keyID,
	).Scan(&a.ID, &a.Name, &a.Type, &a.Description, &a.Scopes, &a.ApiKeyID, &a.CreatorID, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// ListAgents returns all agents.
func (d *DB) ListAgents() ([]*Agent, error) {
	rows, err := d.db.Query(
		`SELECT id, name, type, description, scopes, api_key_id, creator_id, status, created_at, updated_at
		 FROM agents ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		a := &Agent{}
		if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.Description, &a.Scopes, &a.ApiKeyID, &a.CreatorID, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// UpdateAgentStatus sets the agent status (active, suspended, revoked).
func (d *DB) UpdateAgentStatus(name, status string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := d.db.Exec(
		"UPDATE agents SET status = ?, updated_at = ? WHERE name = ?",
		status, now, name,
	)
	if err != nil {
		return fmt.Errorf("update agent status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("agent %q not found", name)
	}

	// If revoking, also revoke the API key
	if status == "revoked" {
		d.db.Exec("UPDATE api_keys SET revoked = 1 WHERE owner_id = (SELECT id FROM agents WHERE name = ?)", name)
	}
	return nil
}

// ResolveIdentity resolves a bearer token to an Identity.
// If the token belongs to an agent's API key, the agent identity is returned.
// Otherwise, a non-agent identity is returned.
func (d *DB) ResolveIdentity(token string) (*Identity, *AuthResult) {
	result := d.AuthenticateBearer(token)
	if result == nil {
		return nil, nil
	}

	identity := &Identity{
		SubjectID: result.SubjectID,
	}

	// Check if this API key belongs to an agent
	if result.Type == "api_key" {
		agent, err := d.GetAgentByApiKeyID(result.SubjectID)
		if err == nil && agent != nil && agent.Status == "active" {
			identity.AgentID = agent.ID
			identity.AgentName = agent.Name
			identity.Scopes = ParseScopes(agent.Scopes)
			identity.IsAgent = true
		}
	}

	return identity, result
}

// ResolveAgentByName resolves an agent name to an Identity (for stdio --agent mode).
func (d *DB) ResolveAgentByName(name string) (*Identity, error) {
	agent, err := d.GetAgentByName(name)
	if err != nil {
		return nil, fmt.Errorf("agent %q not found", name)
	}
	if agent.Status != "active" {
		return nil, fmt.Errorf("agent %q is %s", name, agent.Status)
	}
	return &Identity{
		SubjectID: agent.ID,
		AgentID:   agent.ID,
		AgentName: agent.Name,
		Scopes:    ParseScopes(agent.Scopes),
		IsAgent:   true,
	}, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}
