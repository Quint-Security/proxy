package export

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/google/uuid"
)

// makeTestEntries creates signed, chain-linked entries for testing.
func makeTestEntries(t *testing.T, n int) ([]audit.Entry, crypto.KeyPair) {
	t.Helper()

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	policyHash := crypto.SHA256Hex("{}")
	entries := make([]audit.Entry, n)
	var prevSig string

	tools := []string{"read_file", "write_file", "execute_command", "list_directory"}
	servers := []string{"filesystem", "github", "database", "shell"}
	verdicts := []string{"allow", "allow", "allow", "deny", "allow", "allow", "allow", "allow", "allow", "allow"}
	riskLevels := []string{"low", "low", "medium", "high", "low", "low", "critical", "low", "medium", "low"}

	for i := 0; i < n; i++ {
		ts := time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute)
		timestamp := ts.Format("2006-01-02T15:04:05.000Z")
		nonce := uuid.New().String()
		serverName := servers[i%len(servers)]
		toolName := tools[i%len(tools)]
		verdict := verdicts[i%len(verdicts)]
		riskLevel := riskLevels[i%len(riskLevels)]
		riskScore := 10
		if riskLevel == "medium" {
			riskScore = 50
		} else if riskLevel == "high" {
			riskScore = 70
		} else if riskLevel == "critical" {
			riskScore = 90
		}

		var prevHash string
		if prevSig != "" {
			prevHash = crypto.SHA256Hex(prevSig)
		}

		direction := "request"
		method := "tools/call"
		argsJSON := `{"path":"/test"}`

		obj := crypto.BuildSignableObject(
			timestamp, serverName, direction, method,
			nil, &toolName, &argsJSON, nil,
			verdict, policyHash, prevHash, nonce, kp.PublicKey,
			&riskScore, &riskLevel,
			nil, nil,
		)
		canonical, err := crypto.Canonicalize(obj)
		if err != nil {
			t.Fatalf("canonicalize entry %d: %v", i, err)
		}
		sig, err := crypto.SignData(canonical, kp.PrivateKey)
		if err != nil {
			t.Fatalf("sign entry %d: %v", i, err)
		}

		entries[i] = audit.Entry{
			ID:            int64(i + 1),
			Timestamp:     timestamp,
			ServerName:    serverName,
			Direction:     direction,
			Method:        method,
			ToolName:      &toolName,
			ArgumentsJSON: &argsJSON,
			Verdict:       verdict,
			RiskScore:     &riskScore,
			RiskLevel:     &riskLevel,
			PolicyHash:    policyHash,
			PrevHash:      prevHash,
			Nonce:         nonce,
			Signature:     sig,
			PublicKey:     kp.PublicKey,
		}
		prevSig = sig
	}

	return entries, kp
}

func TestBuildBundle_Summary(t *testing.T) {
	entries, kp := makeTestEntries(t, 20)

	bundle, err := BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	if bundle.Version != 1 {
		t.Errorf("version = %d, want 1", bundle.Version)
	}
	if bundle.Format != "quint-audit-bundle" {
		t.Errorf("format = %q, want %q", bundle.Format, "quint-audit-bundle")
	}
	if bundle.Summary.TotalEntries != 20 {
		t.Errorf("total_entries = %d, want 20", bundle.Summary.TotalEntries)
	}
	if bundle.Summary.UniqueServers != 4 {
		t.Errorf("unique_servers = %d, want 4", bundle.Summary.UniqueServers)
	}
	if bundle.Summary.UniqueTools != 4 {
		t.Errorf("unique_tools = %d, want 4", bundle.Summary.UniqueTools)
	}
	// 20 entries, all are requests with tool names
	if bundle.Summary.ToolCalls != 20 {
		t.Errorf("tool_calls = %d, want 20", bundle.Summary.ToolCalls)
	}
	// verdicts cycle: indices 3, 13 are deny (2 denies out of 20)
	if bundle.Summary.Denied != 2 {
		t.Errorf("denied = %d, want 2", bundle.Summary.Denied)
	}

	// Risk distribution
	if bundle.Summary.RiskDistribution["low"] == 0 {
		t.Error("expected some low-risk entries")
	}
	if bundle.Summary.RiskDistribution["medium"] == 0 {
		t.Error("expected some medium-risk entries")
	}

	// Range
	if bundle.Range.From != entries[0].Timestamp {
		t.Errorf("range.from = %q, want %q", bundle.Range.From, entries[0].Timestamp)
	}
	if bundle.Range.To != entries[19].Timestamp {
		t.Errorf("range.to = %q, want %q", bundle.Range.To, entries[19].Timestamp)
	}

	// Chain verification should be valid
	if !bundle.ChainVerification.Valid {
		t.Error("chain_verification.valid = false, want true")
	}
	if len(bundle.ChainVerification.Breaks) != 0 {
		t.Errorf("chain breaks = %v, want empty", bundle.ChainVerification.Breaks)
	}
}

func TestBuildBundle_SignAndVerify(t *testing.T) {
	entries, kp := makeTestEntries(t, 10)

	bundle, err := BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	if bundle.BundleSignature == "" {
		t.Fatal("bundle_signature is empty")
	}

	// Verify the bundle
	result := VerifyBundle(bundle)
	if !result.BundleSignatureValid {
		t.Error("bundle signature should be valid")
	}
	if result.SignaturesInvalid != 0 {
		t.Errorf("signatures invalid = %d, want 0", result.SignaturesInvalid)
	}
	if result.SignaturesValid != 10 {
		t.Errorf("signatures valid = %d, want 10", result.SignaturesValid)
	}
	if !result.ChainValid {
		t.Error("chain should be valid")
	}
	if len(result.Errors) != 0 {
		t.Errorf("errors = %v, want empty", result.Errors)
	}
}

func TestVerifyBundle_TamperedBundleSignature(t *testing.T) {
	entries, kp := makeTestEntries(t, 5)

	bundle, err := BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	// Tamper with bundle signature
	bundle.BundleSignature = "0000" + bundle.BundleSignature[4:]

	result := VerifyBundle(bundle)
	if result.BundleSignatureValid {
		t.Error("tampered bundle signature should be invalid")
	}

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "INVALID bundle signature") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error about invalid bundle signature")
	}
}

func TestVerifyBundle_TamperedEntry(t *testing.T) {
	entries, kp := makeTestEntries(t, 5)

	bundle, err := BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	// Tamper with an entry's verdict (changes what the signature covers)
	bundle.Entries[2].Verdict = "deny"

	result := VerifyBundle(bundle)

	// Bundle signature should be invalid (because entries changed)
	if result.BundleSignatureValid {
		t.Error("bundle signature should be invalid after entry tampering")
	}

	// The tampered entry's signature should be invalid
	if result.SignaturesInvalid == 0 {
		t.Error("expected at least one invalid entry signature")
	}
}

func TestVerifyBundle_BrokenChain(t *testing.T) {
	entries, kp := makeTestEntries(t, 5)

	// Tamper with chain: change prev_hash of entry 3
	entries[2].PrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

	// Re-sign entry 2 with the wrong prev_hash (so its signature is valid for its data)
	policyHash := entries[2].PolicyHash
	obj := crypto.BuildSignableObject(
		entries[2].Timestamp, entries[2].ServerName, entries[2].Direction, entries[2].Method,
		entries[2].MessageID, entries[2].ToolName, entries[2].ArgumentsJSON, entries[2].ResponseJSON,
		entries[2].Verdict, policyHash, entries[2].PrevHash, entries[2].Nonce, kp.PublicKey,
		entries[2].RiskScore, entries[2].RiskLevel,
		nil, nil,
	)
	canonical, _ := crypto.Canonicalize(obj)
	sig, _ := crypto.SignData(canonical, kp.PrivateKey)
	entries[2].Signature = sig

	bundle, err := BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	// Chain verification in the bundle should detect the break
	if bundle.ChainVerification.Valid {
		t.Error("chain should be invalid")
	}
	if len(bundle.ChainVerification.Breaks) == 0 {
		t.Error("expected chain breaks")
	}

	// Also verify via VerifyBundle
	result := VerifyBundle(bundle)
	if result.ChainValid {
		t.Error("chain should be invalid in verification")
	}
	if result.ChainBreaks == 0 {
		t.Error("expected chain breaks in verification")
	}
}

func TestCSVOutput(t *testing.T) {
	entries, kp := makeTestEntries(t, 3)

	bundle, err := BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, bundle); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	csv := buf.String()
	lines := strings.Split(strings.TrimSpace(csv), "\n")

	// Header + 3 data rows
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d:\n%s", len(lines), csv)
	}

	// Check header
	if lines[0] != "timestamp,server,tool,verdict,risk_score,risk_level,signature_valid" {
		t.Errorf("unexpected header: %s", lines[0])
	}

	// Check that each data row has 7 fields
	for i := 1; i < len(lines); i++ {
		fields := strings.Split(lines[i], ",")
		if len(fields) != 7 {
			t.Errorf("line %d has %d fields, want 7: %s", i, len(fields), lines[i])
		}
	}

	// signature_valid should be "true" for all (we haven't tampered)
	for i := 1; i < len(lines); i++ {
		if !strings.HasSuffix(lines[i], "true") {
			t.Errorf("line %d should end with 'true': %s", i, lines[i])
		}
	}
}

func TestParseBundle_Roundtrip(t *testing.T) {
	entries, kp := makeTestEntries(t, 5)

	bundle, err := BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	data, err := ToJSON(bundle)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	parsed, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	// Verify the parsed bundle
	result := VerifyBundle(parsed)
	if !result.BundleSignatureValid {
		t.Error("bundle signature should survive roundtrip")
	}
	if result.SignaturesInvalid != 0 {
		t.Errorf("signatures invalid = %d after roundtrip", result.SignaturesInvalid)
	}
	if !result.ChainValid {
		t.Error("chain should be valid after roundtrip")
	}
}

func TestParseBundle_InvalidFormat(t *testing.T) {
	data := []byte(`{"format":"not-a-bundle","version":1}`)
	_, err := ParseBundle(data)
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestParseBundle_InvalidJSON(t *testing.T) {
	_, err := ParseBundle([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBuildBundle_Empty(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	bundle, err := BuildBundle(nil, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	if bundle.Summary.TotalEntries != 0 {
		t.Errorf("total_entries = %d, want 0", bundle.Summary.TotalEntries)
	}
	if !bundle.ChainVerification.Valid {
		t.Error("empty bundle chain should be valid")
	}
}

func TestBundleJSON_Structure(t *testing.T) {
	entries, kp := makeTestEntries(t, 2)

	bundle, err := BuildBundle(entries, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	data, err := ToJSON(bundle)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	// Verify it's valid JSON with expected top-level keys
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	expectedKeys := []string{"version", "format", "exported_at", "range", "summary", "chain_verification", "entries", "public_key", "bundle_signature"}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key %q in bundle JSON", key)
		}
	}
}
