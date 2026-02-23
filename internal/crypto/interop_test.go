package crypto

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const nodeScript = `
const { decryptPrivateKey, encryptPrivateKey, signData, verifySignature } = require('%s/packages/core/dist/crypto.js');

const mode = process.argv[2];

if (mode === 'decrypt') {
  // Read Go-encrypted key from stdin, decrypt with passphrase from argv[3]
  const encrypted = require('fs').readFileSync(0, 'utf-8').trim();
  const passphrase = process.argv[3];
  const result = decryptPrivateKey(encrypted, passphrase);
  if (!result) {
    console.error('decryption failed');
    process.exit(1);
  }
  process.stdout.write(result);
} else if (mode === 'encrypt') {
  // Read PEM key from stdin, encrypt with passphrase from argv[3]
  const pem = require('fs').readFileSync(0, 'utf-8');
  const passphrase = process.argv[3];
  const encrypted = encryptPrivateKey(pem, passphrase);
  process.stdout.write(encrypted);
} else if (mode === 'sign') {
  // Read data from stdin, sign with private key from argv[3]
  const data = require('fs').readFileSync(0, 'utf-8');
  const privKeyPem = require('fs').readFileSync(process.argv[3], 'utf-8');
  const sig = signData(data, privKeyPem);
  process.stdout.write(sig);
} else if (mode === 'verify') {
  // Read data from stdin, verify sig from argv[3] with pubkey from argv[4]
  const data = require('fs').readFileSync(0, 'utf-8');
  const sig = process.argv[3];
  const pubKeyPem = require('fs').readFileSync(process.argv[4], 'utf-8');
  const ok = verifySignature(data, sig, pubKeyPem);
  process.stdout.write(ok ? 'true' : 'false');
}
`

func hasNodeDeps(t *testing.T) string {
	t.Helper()
	cliRoot := os.Getenv("QUINT_CLI_ROOT")
	if cliRoot == "" {
		t.Skip("QUINT_CLI_ROOT not set, skipping interop test")
	}
	distPath := filepath.Join(cliRoot, "packages", "core", "dist", "crypto.js")
	if _, err := os.Stat(distPath); err != nil {
		t.Skipf("TS CLI not built at %s, skipping interop test: %v", cliRoot, err)
	}
	return cliRoot
}

func TestGoEncryptTSDecrypt(t *testing.T) {
	cliRoot := hasNodeDeps(t)

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	passphrase := "test-interop-passphrase-42"
	encrypted, err := EncryptPrivateKey(kp.PrivateKey, passphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Use TS to decrypt
	script := strings.Replace(nodeScript, "%s", cliRoot, 1)
	tmpScript := filepath.Join(t.TempDir(), "interop.js")
	os.WriteFile(tmpScript, []byte(script), 0o644)

	cmd := exec.Command("node", tmpScript, "decrypt", passphrase)
	cmd.Stdin = strings.NewReader(encrypted)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("TS decrypt failed: %v\noutput: %s", err, out)
	}

	decrypted := string(out)
	if strings.TrimSpace(decrypted) != strings.TrimSpace(kp.PrivateKey) {
		t.Errorf("TS-decrypted key does not match Go original\nGo:  %q\nTS:  %q", kp.PrivateKey[:50], decrypted[:50])
	}
}

func TestTSEncryptGoDecrypt(t *testing.T) {
	cliRoot := hasNodeDeps(t)

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	passphrase := "test-interop-passphrase-99"

	// Use TS to encrypt
	script := strings.Replace(nodeScript, "%s", cliRoot, 1)
	tmpScript := filepath.Join(t.TempDir(), "interop.js")
	os.WriteFile(tmpScript, []byte(script), 0o644)

	cmd := exec.Command("node", tmpScript, "encrypt", passphrase)
	cmd.Stdin = strings.NewReader(kp.PrivateKey)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("TS encrypt failed: %v\noutput: %s", err, out)
	}

	tsEncrypted := strings.TrimSpace(string(out))
	if !IsEncryptedKey(tsEncrypted) {
		t.Fatalf("TS output is not encrypted key format: %s", tsEncrypted[:40])
	}

	// Decrypt with Go
	decrypted, ok := DecryptPrivateKey(tsEncrypted, passphrase)
	if !ok {
		t.Fatal("Go decrypt of TS-encrypted key failed")
	}

	if strings.TrimSpace(decrypted) != strings.TrimSpace(kp.PrivateKey) {
		t.Errorf("Go-decrypted key does not match original\norig: %q\ngot:  %q", kp.PrivateKey[:50], decrypted[:50])
	}
}

func TestGoSignTSVerify(t *testing.T) {
	cliRoot := hasNodeDeps(t)

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	data := `{"test":"cross-language signature verification"}`
	sig, err := SignData(data, kp.PrivateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Write keys to temp files for TS
	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "pub.pem")
	os.WriteFile(pubFile, []byte(kp.PublicKey), 0o644)

	script := strings.Replace(nodeScript, "%s", cliRoot, 1)
	tmpScript := filepath.Join(tmpDir, "interop.js")
	os.WriteFile(tmpScript, []byte(script), 0o644)

	cmd := exec.Command("node", tmpScript, "verify", sig, pubFile)
	cmd.Stdin = strings.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("TS verify failed: %v\noutput: %s", err, out)
	}

	if strings.TrimSpace(string(out)) != "true" {
		t.Errorf("TS failed to verify Go signature: %s", out)
	}
}

func TestTSSignGoVerify(t *testing.T) {
	cliRoot := hasNodeDeps(t)

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	data := `{"test":"cross-language signature verification reverse"}`

	// Write keys to temp files for TS
	tmpDir := t.TempDir()
	privFile := filepath.Join(tmpDir, "priv.pem")
	pubFile := filepath.Join(tmpDir, "pub.pem")
	os.WriteFile(privFile, []byte(kp.PrivateKey), 0o600)
	os.WriteFile(pubFile, []byte(kp.PublicKey), 0o644)

	script := strings.Replace(nodeScript, "%s", cliRoot, 1)
	tmpScript := filepath.Join(tmpDir, "interop.js")
	os.WriteFile(tmpScript, []byte(script), 0o644)

	cmd := exec.Command("node", tmpScript, "sign", privFile)
	cmd.Stdin = strings.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("TS sign failed: %v\noutput: %s", err, out)
	}

	tsSig := strings.TrimSpace(string(out))

	// Verify with Go
	ok, err := VerifySignature(data, tsSig, kp.PublicKey)
	if err != nil {
		t.Fatalf("Go verify error: %v", err)
	}
	if !ok {
		t.Error("Go failed to verify TS signature")
	}
}
