package connect

import (
	"testing"
)

func TestProviderRegistry(t *testing.T) {
	// All expected providers exist
	for _, name := range []string{"github", "notion", "slack", "sentry"} {
		p := GetProvider(name)
		if p == nil {
			t.Errorf("provider %q not found", name)
			continue
		}
		if p.Name == "" {
			t.Errorf("provider %q has empty Name", name)
		}
		if p.AuthURL == "" {
			t.Errorf("provider %q has empty AuthURL", name)
		}
		if p.TokenURL == "" {
			t.Errorf("provider %q has empty TokenURL", name)
		}
	}
}

func TestProviderCaseInsensitive(t *testing.T) {
	if GetProvider("GitHub") == nil {
		t.Error("uppercase should match — GetProvider uses ToLower")
	}
	if GetProvider("github") == nil {
		t.Error("lowercase should match")
	}
	if GetProvider("GITHUB") == nil {
		t.Error("all caps should match")
	}
}

func TestGitHubProviderHasCredentials(t *testing.T) {
	p := GetProvider("github")
	if p == nil {
		t.Fatal("github provider not found")
	}
	if p.ClientID == "" {
		t.Error("github missing ClientID")
	}
	if p.ClientSecret == "" {
		t.Error("github missing ClientSecret")
	}
	if p.CallbackPort == 0 {
		t.Error("github missing CallbackPort")
	}
}

func TestNotionProviderHasCredentials(t *testing.T) {
	p := GetProvider("notion")
	if p == nil {
		t.Fatal("notion provider not found")
	}
	if p.ClientID == "" {
		t.Error("notion missing ClientID")
	}
	if p.ClientSecret == "" {
		t.Error("notion missing ClientSecret")
	}
	if !p.BasicAuth {
		t.Error("notion should use BasicAuth")
	}
	if p.ExtraParams["owner"] != "user" {
		t.Error("notion should have owner=user extra param")
	}
}

func TestSlackProviderHasTLS(t *testing.T) {
	p := GetProvider("slack")
	if p == nil {
		t.Fatal("slack provider not found")
	}
	if !p.TLSCallback {
		t.Error("slack should require TLS callback")
	}
	if p.ClientID == "" {
		t.Error("slack missing ClientID")
	}
}

func TestSentryProviderNoCreds(t *testing.T) {
	p := GetProvider("sentry")
	if p == nil {
		t.Fatal("sentry provider not found")
	}
	// Sentry doesn't have built-in OAuth creds — uses token-based auth
	if p.ClientID != "" {
		t.Error("sentry should not have ClientID (not registered yet)")
	}
}

func TestUnknownProvider(t *testing.T) {
	if GetProvider("does-not-exist") != nil {
		t.Error("unknown provider should return nil")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("no certificate data")
	}
	if cert.PrivateKey == nil {
		t.Error("no private key")
	}
}
