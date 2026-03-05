package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// Token type prefixes for O(1) detection.
const (
	PrefixApp      = "qt_app_"
	PrefixBearer   = "qt_bearer_"
	PrefixAgent    = "qt_agent_"
	PrefixSubagent = "qt_subagent_"
	PrefixSession  = "qt_session_"
	PrefixOverride = "qt_override_"
)

// IsCloudToken checks if a token string is a cloud JWT via prefix.
func IsCloudToken(token string) bool {
	return strings.HasPrefix(token, "qt_")
}

// TokenType returns the type string from the token prefix.
func TokenType(token string) string {
	switch {
	case strings.HasPrefix(token, PrefixApp):
		return "app"
	case strings.HasPrefix(token, PrefixBearer):
		return "bearer"
	case strings.HasPrefix(token, PrefixAgent):
		return "agent"
	case strings.HasPrefix(token, PrefixSubagent):
		return "subagent"
	case strings.HasPrefix(token, PrefixSession):
		return "session"
	case strings.HasPrefix(token, PrefixOverride):
		return "override"
	default:
		return ""
	}
}

// stripPrefix removes the qt_*_ prefix from a token to get the raw JWT.
func stripPrefix(token string) string {
	switch {
	case strings.HasPrefix(token, PrefixSubagent):
		return token[len(PrefixSubagent):]
	case strings.HasPrefix(token, PrefixOverride):
		return token[len(PrefixOverride):]
	case strings.HasPrefix(token, PrefixSession):
		return token[len(PrefixSession):]
	case strings.HasPrefix(token, PrefixBearer):
		return token[len(PrefixBearer):]
	case strings.HasPrefix(token, PrefixAgent):
		return token[len(PrefixAgent):]
	case strings.HasPrefix(token, PrefixApp):
		return token[len(PrefixApp):]
	default:
		return token
	}
}

// CloudClaims represents the JWT claims from a cloud token.
type CloudClaims struct {
	JTI       string      `json:"jti"`
	Sub       string      `json:"sub"`                          // customer_id
	Typ       string      `json:"typ"`                          // token type
	Iat       int64       `json:"iat"`
	Exp       int64       `json:"exp"`
	ParentJTI string      `json:"parent_jti,omitempty"`
	Env       string      `json:"env,omitempty"`                // bearer
	AgentID   string      `json:"agent_id,omitempty"`           // agent, subagent
	RBAC      *RBACPolicy `json:"rbac,omitempty"`               // agent, subagent
	Depth     int         `json:"depth,omitempty"`              // subagent
	SessionID string      `json:"session_id,omitempty"`         // session
	MaxEvents int         `json:"max_events,omitempty"`         // session
	EventID   string      `json:"event_id,omitempty"`           // override
	AllowedDecisions []string `json:"allowed_decisions,omitempty"` // override
}

// jwtHeader is the JWT header we expect.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// PublicKeyEntry is a public key from the auth service.
type PublicKeyEntry struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// CloudValidatorConfig configures the cloud token validator.
type CloudValidatorConfig struct {
	BaseURL       string
	CustomerID    string
	TimeoutMs     int
	KeyRefreshTTL time.Duration
}

// CloudValidator validates cloud JWT tokens using ES256 public keys.
type CloudValidator struct {
	config     CloudValidatorConfig
	client     *http.Client
	keyCache   map[string]*ecdsa.PublicKey // kid -> key
	keyCacheMu sync.RWMutex
	lastFetch  time.Time
}

// NewCloudValidator creates a cloud validator. Returns nil if config is nil or has no BaseURL.
func NewCloudValidator(cfg *CloudValidatorConfig) *CloudValidator {
	if cfg == nil || cfg.BaseURL == "" {
		return nil
	}
	timeout := cfg.TimeoutMs
	if timeout <= 0 {
		timeout = 5000
	}
	refreshTTL := cfg.KeyRefreshTTL
	if refreshTTL == 0 {
		refreshTTL = 5 * time.Minute
	}
	return &CloudValidator{
		config: CloudValidatorConfig{
			BaseURL:       strings.TrimRight(cfg.BaseURL, "/"),
			CustomerID:    cfg.CustomerID,
			TimeoutMs:     timeout,
			KeyRefreshTTL: refreshTTL,
		},
		client:   &http.Client{Timeout: time.Duration(timeout) * time.Millisecond},
		keyCache: make(map[string]*ecdsa.PublicKey),
	}
}

// ValidateToken parses and validates a JWT token string.
// Returns claims on success. The token must have a qt_* prefix.
func (v *CloudValidator) ValidateToken(tokenStr string) (*CloudClaims, error) {
	if v == nil {
		return nil, fmt.Errorf("cloud validator not configured")
	}

	tokType := TokenType(tokenStr)
	if tokType == "" {
		return nil, fmt.Errorf("unrecognized token prefix")
	}

	// Strip the qt_*_ prefix to get the raw JWT
	rawJWT := stripPrefix(tokenStr)

	// Split into header.payload.signature
	parts := strings.SplitN(rawJWT, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid JWT header JSON: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported algorithm: %s (expected ES256)", header.Alg)
	}

	// Decode payload
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}
	var claims CloudClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWT claims: %w", err)
	}

	// Verify token type matches prefix
	if claims.Typ != "" && claims.Typ != tokType {
		return nil, fmt.Errorf("token type mismatch: prefix=%s claims=%s", tokType, claims.Typ)
	}

	// Check expiry
	now := time.Now().Unix()
	if claims.Exp > 0 && now > claims.Exp {
		return nil, fmt.Errorf("token expired at %d (now=%d)", claims.Exp, now)
	}

	// Check customer_id if configured
	if v.config.CustomerID != "" && claims.Sub != "" && claims.Sub != v.config.CustomerID {
		return nil, fmt.Errorf("customer_id mismatch: expected=%s got=%s", v.config.CustomerID, claims.Sub)
	}

	// Verify ES256 signature
	if err := v.verifySignature(parts[0]+"."+parts[1], parts[2], header.Kid); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return &claims, nil
}

// verifySignature verifies the ES256 signature of the signed content.
func (v *CloudValidator) verifySignature(signedContent, signatureB64, kid string) error {
	// Ensure we have keys
	v.keyCacheMu.RLock()
	hasKeys := len(v.keyCache) > 0
	needsRefresh := time.Since(v.lastFetch) > v.config.KeyRefreshTTL
	v.keyCacheMu.RUnlock()

	if !hasKeys || needsRefresh {
		if err := v.refreshKeys(); err != nil {
			if !hasKeys {
				return fmt.Errorf("no cached keys and refresh failed: %w", err)
			}
			qlog.Warn("key refresh failed, using stale cache: %v", err)
		}
	}

	// Decode signature
	sigBytes, err := base64URLDecode(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// ES256 signature is r || s, each 32 bytes
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid ES256 signature length: %d (expected 64)", len(sigBytes))
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	// Hash the signed content
	hash := sha256.Sum256([]byte(signedContent))

	// Try to verify with the specified kid, or try all keys
	v.keyCacheMu.RLock()
	defer v.keyCacheMu.RUnlock()

	if kid != "" {
		if key, ok := v.keyCache[kid]; ok {
			if ecdsa.Verify(key, hash[:], r, s) {
				return nil
			}
			return fmt.Errorf("signature invalid for kid=%s", kid)
		}
	}

	// Try all cached keys
	for _, key := range v.keyCache {
		if ecdsa.Verify(key, hash[:], r, s) {
			return nil
		}
	}

	return fmt.Errorf("no matching key found for signature verification")
}

// refreshKeys fetches public keys from the auth service.
func (v *CloudValidator) refreshKeys() error {
	url := fmt.Sprintf("%s/keys/public/%s", v.config.BaseURL, v.config.CustomerID)
	resp, err := v.client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch public keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("fetch public keys: status %d", resp.StatusCode)
	}

	var result struct {
		Keys []PublicKeyEntry `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode public keys: %w", err)
	}

	newCache := make(map[string]*ecdsa.PublicKey)
	for _, entry := range result.Keys {
		if entry.Kty != "EC" || entry.Crv != "P-256" {
			continue
		}
		xBytes, err := base64URLDecode(entry.X)
		if err != nil {
			continue
		}
		yBytes, err := base64URLDecode(entry.Y)
		if err != nil {
			continue
		}
		key := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		newCache[entry.Kid] = key
	}

	if len(newCache) > 0 {
		v.keyCacheMu.Lock()
		v.keyCache = newCache
		v.lastFetch = time.Now()
		v.keyCacheMu.Unlock()
		qlog.Info("refreshed %d public key(s) from auth service", len(newCache))
	}

	return nil
}

// SetKeys directly sets public keys in the cache (for testing).
func (v *CloudValidator) SetKeys(keys map[string]*ecdsa.PublicKey) {
	v.keyCacheMu.Lock()
	v.keyCache = keys
	v.lastFetch = time.Now()
	v.keyCacheMu.Unlock()
}

// ExtractIdentity converts CloudClaims into the existing Identity struct.
func (v *CloudValidator) ExtractIdentity(claims *CloudClaims) *Identity {
	identity := &Identity{
		SubjectID:    claims.Sub,
		IsCloudToken: true,
		TokenType:    claims.Typ,
		CustomerID:   claims.Sub,
		JTI:          claims.JTI,
		ParentJTI:    claims.ParentJTI,
		Depth:        claims.Depth,
	}

	// Agent/subagent tokens carry agent identity
	if claims.AgentID != "" {
		identity.AgentID = claims.AgentID
		identity.AgentName = claims.AgentID // Use agent_id as name fallback
		identity.IsAgent = true
	}

	// Extract RBAC policy
	if claims.RBAC != nil {
		identity.RBAC = claims.RBAC
		identity.MaxRiskScore = claims.RBAC.MaxRiskScore
		// Generate scopes from RBAC for backward compatibility
		identity.Scopes = rbacToScopes(claims.RBAC)
	}

	// Session tokens use session_id as subject
	if claims.SessionID != "" {
		identity.SubjectID = claims.SessionID
	}

	return identity
}

// rbacToScopes converts a cloud RBAC policy to the local scope list for backward compat.
func rbacToScopes(rbac *RBACPolicy) []string {
	if rbac == nil {
		return nil
	}
	scopes := make(map[string]bool)
	for _, action := range rbac.AllowedActions {
		upper := strings.ToUpper(action)
		if strings.Contains(upper, "DELETE") || strings.Contains(upper, "DESTROY") || strings.Contains(upper, "DROP") {
			scopes[ScopeToolsAdmin] = true
		}
		if strings.Contains(upper, "EXECUTE") || strings.Contains(upper, "SHELL") || strings.Contains(upper, "RUN") {
			scopes[ScopeToolsExecute] = true
		}
		if strings.Contains(upper, "WRITE") || strings.Contains(upper, "CREATE") || strings.Contains(upper, "UPDATE") {
			scopes[ScopeToolsWrite] = true
		}
		if strings.Contains(upper, "READ") || strings.Contains(upper, "GET") || strings.Contains(upper, "LIST") {
			scopes[ScopeToolsRead] = true
		}
		if action == "*" || strings.HasSuffix(action, ":*") || strings.Contains(action, ":**") {
			scopes[ScopeToolsAdmin] = true
			scopes[ScopeToolsExecute] = true
		}
	}
	var result []string
	for s := range scopes {
		result = append(result, s)
	}
	return result
}

// base64URLDecode decodes a base64url-encoded string (no padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
