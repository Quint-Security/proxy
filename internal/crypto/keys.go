package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const encryptedMagic = "QUINT-ENC-V1"

// KeyPair holds SPKI (public) and PKCS8 (private) PEM-encoded Ed25519 keys.
type KeyPair struct {
	PublicKey  string // SPKI PEM
	PrivateKey string // PKCS8 PEM
}

// GenerateKeyPair creates a new Ed25519 keypair with PEM encoding.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate key: %w", err)
	}

	privPKCS8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return KeyPair{}, fmt.Errorf("marshal private key: %w", err)
	}
	pubSPKI, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return KeyPair{}, fmt.Errorf("marshal public key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privPKCS8})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubSPKI})

	return KeyPair{
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
	}, nil
}

// EncryptPrivateKey encrypts a private key PEM with a passphrase using scrypt + AES-256-GCM.
// Format: QUINT-ENC-V1:<salt_hex>:<iv_hex>:<authTag_hex>:<ciphertext_hex>
func EncryptPrivateKey(privateKeyPEM string, passphrase string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<14, 8, 1, 32)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	sealed := aead.Seal(nil, iv, []byte(privateKeyPEM), nil)
	// GCM appends auth tag (16 bytes) to ciphertext
	tagSize := aead.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]

	return strings.Join([]string{
		encryptedMagic,
		hex.EncodeToString(salt),
		hex.EncodeToString(iv),
		hex.EncodeToString(authTag),
		hex.EncodeToString(ciphertext),
	}, ":"), nil
}

// DecryptPrivateKey decrypts an encrypted private key. Returns "", false if passphrase is wrong.
func DecryptPrivateKey(encrypted string, passphrase string) (string, bool) {
	parts := strings.Split(encrypted, ":")
	if len(parts) != 5 || parts[0] != encryptedMagic {
		return "", false
	}

	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	iv, err := hex.DecodeString(parts[2])
	if err != nil {
		return "", false
	}
	authTag, err := hex.DecodeString(parts[3])
	if err != nil {
		return "", false
	}
	ciphertext, err := hex.DecodeString(parts[4])
	if err != nil {
		return "", false
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<14, 8, 1, 32)
	if err != nil {
		return "", false
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", false
	}

	// GCM expects ciphertext + authTag concatenated
	sealed := append(ciphertext, authTag...)
	plaintext, err := aead.Open(nil, iv, sealed, nil)
	if err != nil {
		return "", false
	}

	return string(plaintext), true
}

// IsEncryptedKey checks if file contents are an encrypted private key.
func IsEncryptedKey(data string) bool {
	return strings.HasPrefix(data, encryptedMagic+":")
}

// SaveKeyPair saves keys to disk. If passphrase is provided, the private key is encrypted.
func SaveKeyPair(dataDir string, kp KeyPair, passphrase string) error {
	keysDir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return err
	}

	privPath := filepath.Join(keysDir, "quint.key")
	pubPath := filepath.Join(keysDir, "quint.pub")

	privData := kp.PrivateKey
	if passphrase != "" {
		enc, err := EncryptPrivateKey(kp.PrivateKey, passphrase)
		if err != nil {
			return fmt.Errorf("encrypt private key: %w", err)
		}
		privData = enc
	}

	if err := os.WriteFile(privPath, []byte(privData), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, []byte(kp.PublicKey), 0o644); err != nil {
		return err
	}
	return nil
}

// LoadKeyPair loads keys from disk. Returns nil, nil if keys don't exist.
// Returns error if encrypted and passphrase is missing or wrong.
func LoadKeyPair(dataDir string, passphrase string) (*KeyPair, error) {
	privPath := filepath.Join(dataDir, "keys", "quint.key")
	pubPath := filepath.Join(dataDir, "keys", "quint.pub")

	privData, err := os.ReadFile(privPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	privStr := string(privData)
	if IsEncryptedKey(privStr) {
		if passphrase == "" {
			return nil, fmt.Errorf("private key is encrypted; provide a passphrase with QUINT_PASSPHRASE")
		}
		decrypted, ok := DecryptPrivateKey(privStr, passphrase)
		if !ok {
			return nil, fmt.Errorf("wrong passphrase — could not decrypt private key")
		}
		return &KeyPair{PublicKey: string(pubData), PrivateKey: decrypted}, nil
	}

	return &KeyPair{PublicKey: string(pubData), PrivateKey: privStr}, nil
}

// EnsureKeyPair loads or generates a keypair.
func EnsureKeyPair(dataDir string, passphrase string) (KeyPair, error) {
	kp, err := LoadKeyPair(dataDir, passphrase)
	if err != nil {
		return KeyPair{}, err
	}
	if kp != nil {
		return *kp, nil
	}

	newKP, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}
	if err := SaveKeyPair(dataDir, newKP, passphrase); err != nil {
		return KeyPair{}, err
	}
	return newKP, nil
}
