package crypto

import (
	"encoding/json"
	"os"
	"testing"
)

// TestFixture holds the cross-language test fixture format.
type testFixture struct {
	PublicKey  string     `json:"public_key"`
	PrivateKey string     `json:"private_key"`
	TestCases  []testCase `json:"test_cases"`
}

type testCase struct {
	Name      string         `json:"name"`
	Entry     map[string]any `json:"entry"`
	Canonical string         `json:"canonical"`
	Signature string         `json:"signature"`
}

func loadFixture(t *testing.T) testFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/fixture.json")
	if err != nil {
		t.Fatalf("cannot load fixture: %v", err)
	}
	var f testFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func TestCanonicalizeMatchesFixture(t *testing.T) {
	f := loadFixture(t)
	for _, tc := range f.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := Canonicalize(tc.Entry)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if got != tc.Canonical {
				t.Errorf("canonical mismatch\nwant: %s\ngot:  %s", tc.Canonical, got)
			}
		})
	}
}

func TestSignatureMatchesFixture(t *testing.T) {
	f := loadFixture(t)
	for _, tc := range f.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			canonical, err := Canonicalize(tc.Entry)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}

			// Sign with the fixture private key
			sig, err := SignData(canonical, f.PrivateKey)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if sig != tc.Signature {
				t.Errorf("signature mismatch\nwant: %s\ngot:  %s", tc.Signature, sig)
			}

			// Verify with the fixture public key
			ok, err := VerifySignature(canonical, tc.Signature, f.PublicKey)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Error("fixture signature failed verification")
			}
		})
	}
}

func TestSHA256Hex(t *testing.T) {
	// Known value: SHA-256 of "hello"
	got := SHA256Hex("hello")
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("SHA256Hex(\"hello\")\nwant: %s\ngot:  %s", want, got)
	}
}

func TestKeyPairGenerateSignVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	data := `{"test":"data"}`
	sig, err := SignData(data, kp.PrivateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	ok, err := VerifySignature(data, sig, kp.PublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("signature verification failed")
	}
}

func TestEncryptDecryptPrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	encrypted, err := EncryptPrivateKey(kp.PrivateKey, "test-passphrase")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if !IsEncryptedKey(encrypted) {
		t.Error("IsEncryptedKey should return true")
	}

	decrypted, ok := DecryptPrivateKey(encrypted, "test-passphrase")
	if !ok {
		t.Fatal("decrypt failed")
	}
	if decrypted != kp.PrivateKey {
		t.Error("decrypted key does not match original")
	}

	// Wrong passphrase
	_, ok = DecryptPrivateKey(encrypted, "wrong")
	if ok {
		t.Error("wrong passphrase should fail")
	}
}

func TestBuildSignableObjectAlwaysIncludesRiskFields(t *testing.T) {
	obj := BuildSignableObject(
		"2025-01-01T00:00:00.000Z", "srv", "request", "tools/call",
		nil, nil, nil, nil,
		"allow", "hash", "", "nonce", "pubkey",
		nil, nil,
		nil, nil,
	)

	// risk_score and risk_level must be present (as null)
	if _, ok := obj["risk_score"]; !ok {
		t.Error("risk_score missing from signable object")
	}
	if _, ok := obj["risk_level"]; !ok {
		t.Error("risk_level missing from signable object")
	}
	if obj["risk_score"] != nil {
		t.Errorf("risk_score should be nil, got %v", obj["risk_score"])
	}
	if obj["risk_level"] != nil {
		t.Errorf("risk_level should be nil, got %v", obj["risk_level"])
	}

	// agent_id and agent_name must be present (as null)
	if _, ok := obj["agent_id"]; !ok {
		t.Error("agent_id missing from signable object")
	}
	if _, ok := obj["agent_name"]; !ok {
		t.Error("agent_name missing from signable object")
	}
}
