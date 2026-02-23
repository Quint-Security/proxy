package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/scrypt"
)

const credSchema = `
CREATE TABLE IF NOT EXISTS credentials (
  id              TEXT PRIMARY KEY,
  provider        TEXT NOT NULL,
  access_token    TEXT NOT NULL,
  refresh_token   TEXT,
  token_type      TEXT NOT NULL DEFAULT 'bearer',
  scopes          TEXT NOT NULL DEFAULT '',
  expires_at      TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  metadata        TEXT
);
`

const credMagic = "QUINT-CRED-V1"

// Credential represents a stored credential.
type Credential struct {
	ID           string  `json:"id"`
	Provider     string  `json:"provider"`
	TokenType    string  `json:"token_type"`
	Scopes       string  `json:"scopes"`
	ExpiresAt    *string `json:"expires_at"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
	Metadata     *string `json:"metadata,omitempty"`
}

// StoreOpts are the fields for storing a credential.
type StoreOpts struct {
	Provider     string
	AccessToken  string
	RefreshToken string
	TokenType    string
	Scopes       string
	ExpiresAt    string
	Metadata     string
}

// Store is the encrypted credential store.
type Store struct {
	db         *sql.DB
	passphrase string
}

// OpenStore opens (or creates) the credential store.
func OpenStore(dataDir string, encryptionKey string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "credentials.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout%3d5000")
	if err != nil {
		return nil, err
	}
	db.Exec("PRAGMA journal_mode = WAL")
	if _, err := db.Exec(credSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, passphrase: encryptionKey}, nil
}

// Put stores or replaces a credential.
func (s *Store) Put(id string, opts StoreOpts) error {
	now := time.Now().UTC().Format(time.RFC3339)
	encAccess := encryptToken(opts.AccessToken, s.passphrase)

	var encRefresh *string
	if opts.RefreshToken != "" {
		r := encryptToken(opts.RefreshToken, s.passphrase)
		encRefresh = &r
	}

	var expiresAt *string
	if opts.ExpiresAt != "" {
		expiresAt = &opts.ExpiresAt
	}
	var metadata *string
	if opts.Metadata != "" {
		metadata = &opts.Metadata
	}
	tokenType := opts.TokenType
	if tokenType == "" {
		tokenType = "bearer"
	}

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO credentials
			(id, provider, access_token, refresh_token, token_type, scopes, expires_at, created_at, updated_at, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, opts.Provider, encAccess, encRefresh, tokenType, opts.Scopes, expiresAt, now, now, metadata,
	)
	return err
}

// GetAccessToken retrieves and decrypts the access token for a credential.
func (s *Store) GetAccessToken(id string) (string, error) {
	var enc string
	err := s.db.QueryRow("SELECT access_token FROM credentials WHERE id = ?", id).Scan(&enc)
	if err != nil {
		return "", err
	}
	plain := decryptToken(enc, s.passphrase)
	if plain == "" {
		return "", fmt.Errorf("failed to decrypt access token")
	}
	return plain, nil
}

// List returns all stored credentials (without tokens).
func (s *Store) List() ([]Credential, error) {
	rows, err := s.db.Query(
		"SELECT id, provider, token_type, scopes, expires_at, created_at, updated_at FROM credentials ORDER BY id ASC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.Provider, &c.TokenType, &c.Scopes, &c.ExpiresAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Remove deletes a credential.
func (s *Store) Remove(id string) bool {
	result, err := s.db.Exec("DELETE FROM credentials WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

// IsExpired checks if a credential's access token has expired.
func (s *Store) IsExpired(id string) bool {
	var expiresAt *string
	err := s.db.QueryRow("SELECT expires_at FROM credentials WHERE id = ?", id).Scan(&expiresAt)
	if err != nil {
		return true
	}
	if expiresAt == nil {
		return false
	}
	t, err := time.Parse(time.RFC3339, *expiresAt)
	if err != nil {
		return true
	}
	return time.Now().After(t)
}

// Close closes the store.
func (s *Store) Close() error {
	return s.db.Close()
}

// DeriveEncryptionKey derives an encryption key from passphrase or private key.
func DeriveEncryptionKey(passphrase, privateKeyPEM string) string {
	if passphrase != "" {
		return passphrase
	}
	if privateKeyPEM != "" {
		h := sha256.Sum256([]byte(privateKeyPEM))
		return hex.EncodeToString(h[:])
	}
	return ""
}

// --- Encryption (AES-256-GCM with scrypt, compatible with TS implementation) ---

func deriveKey(passphrase string, salt []byte) []byte {
	key, _ := scrypt.Key([]byte(passphrase), salt, 1<<14, 8, 1, 32)
	return key
}

func encryptToken(plaintext string, passphrase string) string {
	salt := make([]byte, 32)
	rand.Read(salt)
	key := deriveKey(passphrase, salt)
	iv := make([]byte, 12)
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	ciphertext := aead.Seal(nil, iv, []byte(plaintext), nil)

	// AES-GCM appends the auth tag to the ciphertext
	tagSize := aead.Overhead()
	authTag := ciphertext[len(ciphertext)-tagSize:]
	encrypted := ciphertext[:len(ciphertext)-tagSize]

	return strings.Join([]string{
		credMagic,
		hex.EncodeToString(salt),
		hex.EncodeToString(iv),
		hex.EncodeToString(authTag),
		hex.EncodeToString(encrypted),
	}, ":")
}

func decryptToken(encrypted string, passphrase string) string {
	parts := strings.SplitN(encrypted, ":", 5)
	if len(parts) != 5 || parts[0] != credMagic {
		return ""
	}

	salt, _ := hex.DecodeString(parts[1])
	iv, _ := hex.DecodeString(parts[2])
	authTag, _ := hex.DecodeString(parts[3])
	ciphertext, _ := hex.DecodeString(parts[4])

	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}

	// Reconstruct ciphertext+tag for Go's GCM
	combined := append(ciphertext, authTag...)
	plain, err := aead.Open(nil, iv, combined, nil)
	if err != nil {
		return ""
	}
	return string(plain)
}
