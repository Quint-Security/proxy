package intercept

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SpawnTicketClaims encodes the parent-child relationship in a spawn ticket.
type SpawnTicketClaims struct {
	ParentAgentID   string   `json:"pid"`
	ParentAgentName string   `json:"pname,omitempty"`
	ChildHint       string   `json:"child,omitempty"`
	Depth           int      `json:"d"`
	Scopes          string   `json:"sc,omitempty"`
	TraceID         string   `json:"tid,omitempty"`
	SpawnType       string   `json:"st,omitempty"`
	ExpiresAt       int64    `json:"exp"`
	Nonce           string   `json:"n"`
	_               struct{} // prevent unkeyed literals
}

// SpawnTicketSigner issues and validates HMAC-SHA256 signed spawn tickets.
type SpawnTicketSigner struct {
	secret []byte
	ttl    time.Duration
}

var (
	ErrTicketExpired  = errors.New("spawn ticket expired")
	ErrTicketInvalid  = errors.New("spawn ticket invalid")
	ErrTicketMalformed = errors.New("spawn ticket malformed")
)

// NewSpawnTicketSigner creates a signer with a random 32-byte secret.
// TTL defaults to 5 minutes if zero.
func NewSpawnTicketSigner(ttl time.Duration) (*SpawnTicketSigner, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	return &SpawnTicketSigner{secret: secret, ttl: ttl}, nil
}

// Issue creates a signed spawn ticket from the given claims.
// Format: base64url(json).base64url(hmac-sha256)
func (s *SpawnTicketSigner) Issue(claims SpawnTicketClaims) (string, error) {
	claims.ExpiresAt = time.Now().Add(s.ttl).Unix()

	// Generate 16-byte nonce
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	claims.Nonce = base64.RawURLEncoding.EncodeToString(nonce)

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payloadB64))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return payloadB64 + "." + sigB64, nil
}

// Validate verifies the HMAC signature and checks expiry.
// Returns the decoded claims on success.
func (s *SpawnTicketSigner) Validate(ticket string) (*SpawnTicketClaims, error) {
	// Split into payload.signature
	dotIdx := -1
	for i := len(ticket) - 1; i >= 0; i-- {
		if ticket[i] == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx < 1 || dotIdx >= len(ticket)-1 {
		return nil, ErrTicketMalformed
	}

	payloadB64 := ticket[:dotIdx]
	sigB64 := ticket[dotIdx+1:]

	// Verify HMAC (constant-time comparison)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payloadB64))
	expectedSig := mac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrTicketMalformed
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return nil, ErrTicketInvalid
	}

	// Decode claims
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrTicketMalformed
	}

	var claims SpawnTicketClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrTicketMalformed
	}

	// Check expiry (token valid before ExpiresAt, not at or after)
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, ErrTicketExpired
	}

	return &claims, nil
}
