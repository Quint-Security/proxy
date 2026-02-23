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

CREATE INDEX IF NOT EXISTS idx_api_keys_hash    ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner   ON api_keys(owner_id);
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject_id);
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

func (d *DB) Close() error {
	return d.db.Close()
}
