package connect

import (
	"testing"
)

func TestProviderRegistry(t *testing.T) {
	// All expected providers exist
	for _, name := range []string{"github", "notion", "slack", "sentry", "linear"} {
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

func TestGitHubProviderConfig(t *testing.T) {
	p := GetProvider("github")
	if p == nil {
		t.Fatal("github provider not found")
	}
	if p.ClientID == "" {
		t.Error("github missing ClientID (public fallback)")
	}
	if p.ClientSecret != "" {
		t.Error("github should NOT have ClientSecret in binary")
	}
	if p.CallbackPort == 0 {
		t.Error("github missing CallbackPort")
	}
}

func TestNotionProviderConfig(t *testing.T) {
	p := GetProvider("notion")
	if p == nil {
		t.Fatal("notion provider not found")
	}
	if p.ClientID != "" {
		t.Error("notion should NOT have ClientID in binary (fetched from API)")
	}
	if p.ClientSecret != "" {
		t.Error("notion should NOT have ClientSecret in binary")
	}
	if !p.BasicAuth {
		t.Error("notion should use BasicAuth")
	}
	if p.ExtraParams["owner"] != "user" {
		t.Error("notion should have owner=user extra param")
	}
}

func TestSlackProviderConfig(t *testing.T) {
	p := GetProvider("slack")
	if p == nil {
		t.Fatal("slack provider not found")
	}
	if !p.TLSCallback {
		t.Error("slack should require TLS callback")
	}
	if p.ClientID != "" {
		t.Error("slack should NOT have ClientID in binary (fetched from API)")
	}
	if p.ClientSecret != "" {
		t.Error("slack should NOT have ClientSecret in binary")
	}
}

func TestSentryProviderNoCreds(t *testing.T) {
	p := GetProvider("sentry")
	if p == nil {
		t.Fatal("sentry provider not found")
	}
	if p.ClientID != "" {
		t.Error("sentry should not have ClientID")
	}
	if p.ClientSecret != "" {
		t.Error("sentry should not have ClientSecret")
	}
}

func TestLinearProviderConfig(t *testing.T) {
	p := GetProvider("linear")
	if p == nil {
		t.Fatal("linear provider not found")
	}
	if p.ClientID != "" {
		t.Error("linear should not have ClientID")
	}
	if p.ClientSecret != "" {
		t.Error("linear should not have ClientSecret")
	}
}

func TestNoSecretsInProviders(t *testing.T) {
	for name, p := range Providers {
		if p.ClientSecret != "" {
			t.Errorf("provider %q still has ClientSecret in binary — this is a security issue", name)
		}
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
