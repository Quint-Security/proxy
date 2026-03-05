package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func TestIsCloudToken(t *testing.T) {
	tests := []struct {
		token    string
		expected bool
	}{
		{"qt_app_abc123", true},
		{"qt_bearer_xyz", true},
		{"qt_agent_foo", true},
		{"qt_subagent_bar", true},
		{"qt_session_baz", true},
		{"qt_override_qux", true},
		{"qk_abcdef123456", false},
		{"some_random_token", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsCloudToken(tt.token); got != tt.expected {
			t.Errorf("IsCloudToken(%q) = %v, want %v", tt.token, got, tt.expected)
		}
	}
}

func TestTokenType(t *testing.T) {
	tests := []struct {
		token    string
		expected string
	}{
		{"qt_app_abc", "app"},
		{"qt_bearer_abc", "bearer"},
		{"qt_agent_abc", "agent"},
		{"qt_subagent_abc", "subagent"},
		{"qt_session_abc", "session"},
		{"qt_override_abc", "override"},
		{"qk_abc", ""},
		{"random", ""},
	}
	for _, tt := range tests {
		if got := TokenType(tt.token); got != tt.expected {
			t.Errorf("TokenType(%q) = %q, want %q", tt.token, got, tt.expected)
		}
	}
}

func TestStripPrefix(t *testing.T) {
	tests := []struct {
		token    string
		expected string
	}{
		{"qt_app_jwt.parts.here", "jwt.parts.here"},
		{"qt_agent_jwt.parts.here", "jwt.parts.here"},
		{"qt_subagent_jwt.parts.here", "jwt.parts.here"},
		{"no_prefix", "no_prefix"},
	}
	for _, tt := range tests {
		if got := stripPrefix(tt.token); got != tt.expected {
			t.Errorf("stripPrefix(%q) = %q, want %q", tt.token, got, tt.expected)
		}
	}
}

// generateTestJWT creates a signed JWT for testing.
func generateTestJWT(t *testing.T, key *ecdsa.PrivateKey, claims CloudClaims) string {
	t.Helper()

	header := map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": "test-key-1",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signedContent := headerB64 + "." + claimsB64

	hash := sha256.Sum256([]byte(signedContent))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Pad r and s to 32 bytes each
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signedContent + "." + sigB64
}

func TestCloudValidator_ValidateToken(t *testing.T) {
	// Generate test ES256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	validator := NewCloudValidator(&CloudValidatorConfig{
		BaseURL:    "http://localhost:9999",
		CustomerID: "test-customer",
	})

	// Set test key directly
	validator.SetKeys(map[string]*ecdsa.PublicKey{
		"test-key-1": &privateKey.PublicKey,
	})

	claims := CloudClaims{
		JTI:     "test-jti-123",
		Sub:     "test-customer",
		Typ:     "agent",
		Iat:     time.Now().Unix(),
		Exp:     time.Now().Add(24 * time.Hour).Unix(),
		AgentID: "agent-001",
		RBAC: &RBACPolicy{
			AllowedActions:   []string{"mcp:filesystem:*"},
			DeniedActions:    []string{"mcp:*:*.delete"},
			SensitivityLevel: 3,
			MaxRiskScore:     75,
		},
	}

	jwt := generateTestJWT(t, privateKey, claims)
	token := PrefixAgent + jwt

	result, err := validator.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if result.JTI != "test-jti-123" {
		t.Errorf("JTI = %q, want test-jti-123", result.JTI)
	}
	if result.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want agent-001", result.AgentID)
	}
	if result.RBAC == nil {
		t.Fatal("RBAC is nil")
	}
	if result.RBAC.MaxRiskScore != 75 {
		t.Errorf("MaxRiskScore = %d, want 75", result.RBAC.MaxRiskScore)
	}
}

func TestCloudValidator_ExpiredToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	validator := NewCloudValidator(&CloudValidatorConfig{
		BaseURL:    "http://localhost:9999",
		CustomerID: "test-customer",
	})
	validator.SetKeys(map[string]*ecdsa.PublicKey{
		"test-key-1": &privateKey.PublicKey,
	})

	claims := CloudClaims{
		JTI: "expired-jti",
		Sub: "test-customer",
		Typ: "agent",
		Iat: time.Now().Add(-48 * time.Hour).Unix(),
		Exp: time.Now().Add(-24 * time.Hour).Unix(), // expired
	}

	jwt := generateTestJWT(t, privateKey, claims)
	token := PrefixAgent + jwt

	_, err := validator.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestCloudValidator_CustomerMismatch(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	validator := NewCloudValidator(&CloudValidatorConfig{
		BaseURL:    "http://localhost:9999",
		CustomerID: "customer-A",
	})
	validator.SetKeys(map[string]*ecdsa.PublicKey{
		"test-key-1": &privateKey.PublicKey,
	})

	claims := CloudClaims{
		JTI: "wrong-customer-jti",
		Sub: "customer-B", // mismatch
		Typ: "agent",
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(1 * time.Hour).Unix(),
	}

	jwt := generateTestJWT(t, privateKey, claims)
	token := PrefixAgent + jwt

	_, err := validator.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for customer mismatch")
	}
}

func TestCloudValidator_InvalidSignature(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	validator := NewCloudValidator(&CloudValidatorConfig{
		BaseURL:    "http://localhost:9999",
		CustomerID: "test-customer",
	})
	// Set a DIFFERENT key than what was used to sign
	validator.SetKeys(map[string]*ecdsa.PublicKey{
		"test-key-1": &wrongKey.PublicKey,
	})

	claims := CloudClaims{
		JTI: "bad-sig-jti",
		Sub: "test-customer",
		Typ: "agent",
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(1 * time.Hour).Unix(),
	}

	jwt := generateTestJWT(t, privateKey, claims)
	token := PrefixAgent + jwt

	_, err := validator.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestCloudValidator_ExtractIdentity(t *testing.T) {
	validator := NewCloudValidator(&CloudValidatorConfig{
		BaseURL: "http://localhost:9999",
	})

	claims := &CloudClaims{
		JTI:       "jti-123",
		Sub:       "cust-456",
		Typ:       "agent",
		AgentID:   "agent-789",
		ParentJTI: "parent-jti-000",
		RBAC: &RBACPolicy{
			AllowedActions: []string{"mcp:filesystem:*"},
			MaxRiskScore:   75,
		},
	}

	identity := validator.ExtractIdentity(claims)
	if !identity.IsCloudToken {
		t.Fatal("expected IsCloudToken=true")
	}
	if identity.TokenType != "agent" {
		t.Errorf("TokenType = %q, want agent", identity.TokenType)
	}
	if identity.AgentID != "agent-789" {
		t.Errorf("AgentID = %q, want agent-789", identity.AgentID)
	}
	if !identity.IsAgent {
		t.Fatal("expected IsAgent=true for agent token")
	}
	if identity.MaxRiskScore != 75 {
		t.Errorf("MaxRiskScore = %d, want 75", identity.MaxRiskScore)
	}
	if identity.ParentJTI != "parent-jti-000" {
		t.Errorf("ParentJTI = %q, want parent-jti-000", identity.ParentJTI)
	}
}

func TestCloudValidator_ExtractIdentity_Session(t *testing.T) {
	validator := NewCloudValidator(&CloudValidatorConfig{
		BaseURL: "http://localhost:9999",
	})

	claims := &CloudClaims{
		JTI:       "jti-sess",
		Sub:       "cust-456",
		Typ:       "session",
		SessionID: "session-abc",
	}

	identity := validator.ExtractIdentity(claims)
	if identity.SubjectID != "session-abc" {
		t.Errorf("SubjectID = %q, want session-abc (should use session_id)", identity.SubjectID)
	}
}

func TestBase64URLDecode(t *testing.T) {
	// Standard base64url without padding
	encoded := base64.RawURLEncoding.EncodeToString([]byte("hello world"))
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("base64URLDecode failed: %v", err)
	}
	if string(decoded) != "hello world" {
		t.Errorf("got %q, want %q", decoded, "hello world")
	}
}

func TestRBACToScopes(t *testing.T) {
	rbac := &RBACPolicy{
		AllowedActions: []string{"mcp:filesystem:read_file.read", "mcp:git:*"},
	}
	scopes := rbacToScopes(rbac)
	scopeMap := make(map[string]bool)
	for _, s := range scopes {
		scopeMap[s] = true
	}
	if !scopeMap[ScopeToolsRead] {
		t.Error("expected tools:read scope from read action")
	}
}

func TestNewCloudValidator_NilConfig(t *testing.T) {
	v := NewCloudValidator(nil)
	if v != nil {
		t.Fatal("expected nil validator for nil config")
	}
}

func TestNewCloudValidator_EmptyBaseURL(t *testing.T) {
	v := NewCloudValidator(&CloudValidatorConfig{})
	if v != nil {
		t.Fatal("expected nil validator for empty base URL")
	}
}

// Verify that signature verification works with raw big.Int bytes
func TestES256SignatureRoundtrip(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	message := "test message"
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Encode r||s as 64 bytes
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	// Decode and verify
	rDec := new(big.Int).SetBytes(sig[:32])
	sDec := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.Verify(&privateKey.PublicKey, hash[:], rDec, sDec) {
		t.Fatal("ES256 signature roundtrip failed")
	}
}
