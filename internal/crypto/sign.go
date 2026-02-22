package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// SignData signs data with an Ed25519 private key (PKCS8 PEM) and returns a hex-encoded signature.
func SignData(data string, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key is not Ed25519")
	}

	sig := ed25519.Sign(edKey, []byte(data))
	return hex.EncodeToString(sig), nil
}

// VerifySignature verifies an Ed25519 signature against data and a public key (SPKI PEM).
func VerifySignature(data string, signatureHex string, publicKeyPEM string) (bool, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("key is not Ed25519")
	}

	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("decode signature hex: %w", err)
	}

	return ed25519.Verify(edPub, []byte(data), sig), nil
}
