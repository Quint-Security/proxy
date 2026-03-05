package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA holds a certificate authority for MITM TLS interception.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// EnsureCA loads or generates a CA certificate at dataDir/ca/.
// It also creates a combined CA bundle (system CAs + Quint CA).
func EnsureCA(dataDir string) (*CA, error) {
	caDir := filepath.Join(dataDir, "ca")
	certPath := filepath.Join(caDir, "quint-ca.crt")
	keyPath := filepath.Join(caDir, "quint-ca.key")

	// Try to load existing CA
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	var ca *CA
	if certErr == nil && keyErr == nil {
		var err error
		ca, err = parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
	} else {
		// Generate new CA
		if err := os.MkdirAll(caDir, 0o700); err != nil {
			return nil, fmt.Errorf("create ca dir: %w", err)
		}

		var err error
		ca, err = generateCA()
		if err != nil {
			return nil, err
		}

		if err := os.WriteFile(certPath, ca.CertPEM, 0o644); err != nil {
			return nil, fmt.Errorf("write ca cert: %w", err)
		}

		keyBytes, err := x509.MarshalECPrivateKey(ca.Key)
		if err != nil {
			return nil, fmt.Errorf("marshal ca key: %w", err)
		}
		keyPEMData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		if err := os.WriteFile(keyPath, keyPEMData, 0o600); err != nil {
			return nil, fmt.Errorf("write ca key: %w", err)
		}
	}

	// Create combined CA bundle (best-effort — don't fail if system CAs unavailable)
	if err := EnsureBundle(dataDir, ca.CertPEM); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create CA bundle: %v\n", err)
	}

	return ca, nil
}

// BundlePath returns the path to the combined CA bundle file.
func BundlePath(dataDir string) string {
	return filepath.Join(dataDir, "ca", "quint-ca-bundle.pem")
}

// EnsureBundle creates a combined CA bundle (system CAs + Quint CA).
// This allows SSL_CERT_FILE to work without breaking trust for real CAs.
func EnsureBundle(dataDir string, caCertPEM []byte) error {
	bundlePath := BundlePath(dataDir)

	systemBundle := findSystemCABundle()
	if systemBundle == "" {
		return fmt.Errorf("could not find system CA bundle")
	}

	systemCAs, err := os.ReadFile(systemBundle)
	if err != nil {
		return fmt.Errorf("read system CAs: %w", err)
	}

	// Concatenate: system CAs + newline + Quint CA
	combined := append(systemCAs, '\n')
	combined = append(combined, caCertPEM...)

	return os.WriteFile(bundlePath, combined, 0o644)
}

func findSystemCABundle() string {
	candidates := []string{
		"/etc/ssl/cert.pem",                      // macOS
		"/etc/ssl/certs/ca-certificates.crt",     // Debian/Ubuntu
		"/etc/pki/tls/certs/ca-bundle.crt",       // RHEL/CentOS
		"/etc/ssl/ca-bundle.pem",                 // OpenSUSE
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// CertPath returns the path to the CA certificate file.
func CertPath(dataDir string) string {
	return filepath.Join(dataDir, "ca", "quint-ca.crt")
}

// GenerateLeafCert creates a TLS certificate for the given hostname, signed by this CA.
func (ca *CA) GenerateLeafCert(hostname string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add hostname as SAN
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert: %w", err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	leafKeyBytes, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("marshal leaf key: %w", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyBytes})

	// Include CA cert in chain so clients that don't load NODE_EXTRA_CA_CERTS
	// (e.g. Bun standalone binaries) can still build the full chain.
	chainPEM := append(leafCertPEM, ca.CertPEM...)

	tlsCert, err := tls.X509KeyPair(chainPEM, leafKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("create tls cert: %w", err)
	}

	return &tlsCert, nil
}

func generateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Quint Security"},
			CommonName:   "Quint Proxy CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &CA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &CA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}
