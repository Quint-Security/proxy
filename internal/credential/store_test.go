package credential

import (
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(dir, "test-encryption-key")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestPutAndGetAccessToken(t *testing.T) {
	store := testStore(t)

	store.Put("github", StoreOpts{
		Provider:    "github",
		AccessToken: "gho_secret_token_12345",
		Scopes:      "repo,read:org",
	})

	token, err := store.GetAccessToken("github")
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if token != "gho_secret_token_12345" {
		t.Errorf("token = %q, want gho_secret_token_12345", token)
	}
}

func TestGetAccessTokenNonexistent(t *testing.T) {
	store := testStore(t)

	token, err := store.GetAccessToken("nonexistent")
	if err == nil && token != "" {
		t.Error("expected empty token for nonexistent credential")
	}
}

func TestList(t *testing.T) {
	store := testStore(t)

	store.Put("github", StoreOpts{Provider: "github", AccessToken: "tok1"})
	store.Put("notion", StoreOpts{Provider: "notion", AccessToken: "tok2"})

	creds, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(creds) != 2 {
		t.Errorf("got %d credentials, want 2", len(creds))
	}
}

func TestRemove(t *testing.T) {
	store := testStore(t)

	store.Put("github", StoreOpts{Provider: "github", AccessToken: "tok1"})

	if !store.Remove("github") {
		t.Error("Remove should return true")
	}

	if store.Remove("github") {
		t.Error("second Remove should return false")
	}

	token, _ := store.GetAccessToken("github")
	if token != "" {
		t.Error("token should be empty after removal")
	}
}

func TestIsExpired(t *testing.T) {
	store := testStore(t)

	// No expiry
	store.Put("github", StoreOpts{Provider: "github", AccessToken: "tok1"})
	if store.IsExpired("github") {
		t.Error("credential without expiry should not be expired")
	}

	// Expired
	store.Put("old", StoreOpts{Provider: "old", AccessToken: "tok2", ExpiresAt: "2020-01-01T00:00:00Z"})
	if !store.IsExpired("old") {
		t.Error("past expiry should be expired")
	}

	// Future expiry
	store.Put("future", StoreOpts{Provider: "future", AccessToken: "tok3", ExpiresAt: "2099-01-01T00:00:00Z"})
	if store.IsExpired("future") {
		t.Error("future expiry should not be expired")
	}

	// Nonexistent
	if !store.IsExpired("nonexistent") {
		t.Error("nonexistent should be treated as expired")
	}
}

func TestOverwrite(t *testing.T) {
	store := testStore(t)

	store.Put("github", StoreOpts{Provider: "github", AccessToken: "old_token"})
	store.Put("github", StoreOpts{Provider: "github", AccessToken: "new_token"})

	token, err := store.GetAccessToken("github")
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if token != "new_token" {
		t.Errorf("token = %q, want new_token", token)
	}

	creds, _ := store.List()
	if len(creds) != 1 {
		t.Errorf("got %d credentials after overwrite, want 1", len(creds))
	}
}

func TestDeriveEncryptionKey(t *testing.T) {
	key := DeriveEncryptionKey("passphrase", "")
	if key != "passphrase" {
		t.Errorf("with passphrase, should return passphrase directly")
	}

	key = DeriveEncryptionKey("", "some-private-key-pem")
	if key == "" || key == "some-private-key-pem" {
		t.Error("with private key, should return derived hash")
	}
}

func TestTokenEncryption(t *testing.T) {
	store := testStore(t)

	// Store a token
	store.Put("test", StoreOpts{Provider: "test", AccessToken: "super_secret_token"})

	// Get it back — should be decrypted
	token, err := store.GetAccessToken("test")
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if token != "super_secret_token" {
		t.Errorf("decrypted token = %q, want super_secret_token", token)
	}
}
