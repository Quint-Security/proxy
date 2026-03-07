// Package credential provides a stub for the removed credential store.
// The OAuth credential store was removed when the forward proxy (MITM TLS)
// replaced the need for per-provider OAuth connections. HTTP backends
// should use environment variables for authentication instead.
package credential

// Store is a no-op stub. The credential store has been removed.
// This type exists only for backward compatibility with the gateway package.
type Store struct{}

// GetAccessToken always returns empty — credentials are no longer stored.
func (s *Store) GetAccessToken(provider string) (string, error) {
	return "", nil
}

// Close is a no-op.
func (s *Store) Close() error {
	return nil
}
