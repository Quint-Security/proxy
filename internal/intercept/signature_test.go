package intercept

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSpawnTicketRoundTrip(t *testing.T) {
	signer, err := NewSpawnTicketSigner(5 * time.Minute)
	if err != nil {
		t.Fatalf("NewSpawnTicketSigner: %v", err)
	}

	claims := SpawnTicketClaims{
		ParentAgentID:   "agent-123",
		ParentAgentName: "claude-code",
		ChildHint:       "sub-agent-1",
		Depth:           2,
		Scopes:          "tools:read,tools:write",
		TraceID:         "trace-abc",
		SpawnType:       "delegation",
	}

	ticket, err := signer.Issue(claims)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if ticket == "" {
		t.Fatal("expected non-empty ticket")
	}

	// Validate
	got, err := signer.Validate(ticket)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if got.ParentAgentID != claims.ParentAgentID {
		t.Errorf("ParentAgentID = %q, want %q", got.ParentAgentID, claims.ParentAgentID)
	}
	if got.ParentAgentName != claims.ParentAgentName {
		t.Errorf("ParentAgentName = %q, want %q", got.ParentAgentName, claims.ParentAgentName)
	}
	if got.ChildHint != claims.ChildHint {
		t.Errorf("ChildHint = %q, want %q", got.ChildHint, claims.ChildHint)
	}
	if got.Depth != claims.Depth {
		t.Errorf("Depth = %d, want %d", got.Depth, claims.Depth)
	}
	if got.Scopes != claims.Scopes {
		t.Errorf("Scopes = %q, want %q", got.Scopes, claims.Scopes)
	}
	if got.SpawnType != claims.SpawnType {
		t.Errorf("SpawnType = %q, want %q", got.SpawnType, claims.SpawnType)
	}
	if got.Nonce == "" {
		t.Error("expected non-empty nonce")
	}
	if got.ExpiresAt == 0 {
		t.Error("expected non-zero ExpiresAt")
	}
}

func TestSpawnTicketExpiry(t *testing.T) {
	// Use 1-second TTL; with >= comparison on Unix seconds, sleeping 1.1s guarantees expiry
	signer, err := NewSpawnTicketSigner(1 * time.Second)
	if err != nil {
		t.Fatalf("NewSpawnTicketSigner: %v", err)
	}

	ticket, err := signer.Issue(SpawnTicketClaims{
		ParentAgentID: "agent-123",
		Depth:         1,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Should be valid immediately
	if _, err := signer.Validate(ticket); err != nil {
		t.Fatalf("expected valid ticket immediately after issue, got %v", err)
	}

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	_, err = signer.Validate(ticket)
	if err != ErrTicketExpired {
		t.Errorf("expected ErrTicketExpired, got %v", err)
	}
}

func TestSpawnTicketTampering(t *testing.T) {
	signer, err := NewSpawnTicketSigner(5 * time.Minute)
	if err != nil {
		t.Fatalf("NewSpawnTicketSigner: %v", err)
	}

	ticket, err := signer.Issue(SpawnTicketClaims{
		ParentAgentID: "agent-123",
		Depth:         1,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Tamper with payload
	parts := strings.SplitN(ticket, ".", 2)
	if len(parts) != 2 {
		t.Fatal("expected ticket to have two parts")
	}

	// Decode, modify, re-encode payload without re-signing
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var claims map[string]any
	json.Unmarshal(payloadBytes, &claims)
	claims["d"] = 99 // tamper depth
	tampered, _ := json.Marshal(claims)
	tamperedB64 := base64.RawURLEncoding.EncodeToString(tampered)

	_, err = signer.Validate(tamperedB64 + "." + parts[1])
	if err != ErrTicketInvalid {
		t.Errorf("expected ErrTicketInvalid for tampered payload, got %v", err)
	}
}

func TestSpawnTicketWrongSecret(t *testing.T) {
	signer1, _ := NewSpawnTicketSigner(5 * time.Minute)
	signer2, _ := NewSpawnTicketSigner(5 * time.Minute)

	ticket, err := signer1.Issue(SpawnTicketClaims{
		ParentAgentID: "agent-123",
		Depth:         1,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = signer2.Validate(ticket)
	if err != ErrTicketInvalid {
		t.Errorf("expected ErrTicketInvalid for wrong secret, got %v", err)
	}
}

func TestSpawnTicketMalformed(t *testing.T) {
	signer, _ := NewSpawnTicketSigner(5 * time.Minute)

	cases := []string{
		"",
		"no-dot-here",
		".",
		".sig",
		"payload.",
		"not-base64.not-base64!",
	}

	for _, tc := range cases {
		_, err := signer.Validate(tc)
		if err == nil {
			t.Errorf("expected error for malformed ticket %q, got nil", tc)
		}
	}
}

func TestInjectSpawnTicketNewQuint(t *testing.T) {
	args := json.RawMessage(`{"file":"test.txt"}`)
	result := InjectSpawnTicket(args, "ticket123")

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	quintRaw, ok := parsed["_quint"]
	if !ok {
		t.Fatal("expected _quint field")
	}

	var quint map[string]any
	if err := json.Unmarshal(quintRaw, &quint); err != nil {
		t.Fatalf("unmarshal _quint: %v", err)
	}

	if quint["spawn_ticket"] != "ticket123" {
		t.Errorf("spawn_ticket = %v, want %q", quint["spawn_ticket"], "ticket123")
	}

	// Original field preserved
	var fileField string
	json.Unmarshal(parsed["file"], &fileField)
	if fileField != "test.txt" {
		t.Errorf("file = %q, want %q", fileField, "test.txt")
	}
}

func TestInjectSpawnTicketExistingQuint(t *testing.T) {
	args := json.RawMessage(`{"_quint":{"trace_id":"abc","depth":1},"file":"test.txt"}`)
	result := InjectSpawnTicket(args, "ticket456")

	var parsed map[string]json.RawMessage
	json.Unmarshal(result, &parsed)

	var quint map[string]any
	json.Unmarshal(parsed["_quint"], &quint)

	if quint["spawn_ticket"] != "ticket456" {
		t.Errorf("spawn_ticket = %v, want %q", quint["spawn_ticket"], "ticket456")
	}
	if quint["trace_id"] != "abc" {
		t.Errorf("trace_id = %v, want %q", quint["trace_id"], "abc")
	}
	if quint["depth"] != float64(1) {
		t.Errorf("depth = %v, want 1", quint["depth"])
	}
}

func TestInjectSpawnTicketEmptyTicket(t *testing.T) {
	args := json.RawMessage(`{"file":"test.txt"}`)
	result := InjectSpawnTicket(args, "")

	if string(result) != string(args) {
		t.Errorf("expected unchanged args for empty ticket")
	}
}
