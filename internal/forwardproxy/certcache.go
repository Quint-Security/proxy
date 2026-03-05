package forwardproxy

import (
	"crypto/tls"
	"sync"

	"github.com/Quint-Security/quint-proxy/internal/crypto"
)

// CertCache caches generated TLS certificates per hostname.
type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
	ca    *crypto.CA
}

// NewCertCache creates a new cert cache backed by the given CA.
func NewCertCache(ca *crypto.CA) *CertCache {
	return &CertCache{
		certs: make(map[string]*tls.Certificate),
		ca:    ca,
	}
}

// GetOrCreate returns a cached cert for the hostname or generates a new one.
func (c *CertCache) GetOrCreate(hostname string) (*tls.Certificate, error) {
	c.mu.RLock()
	cert, ok := c.certs[hostname]
	c.mu.RUnlock()
	if ok {
		return cert, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if cert, ok := c.certs[hostname]; ok {
		return cert, nil
	}

	cert, err := c.ca.GenerateLeafCert(hostname)
	if err != nil {
		return nil, err
	}

	c.certs[hostname] = cert
	return cert, nil
}
