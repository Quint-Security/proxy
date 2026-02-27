package risk

import (
	"testing"
)

func TestExtractTarget_ServerMapping(t *testing.T) {
	tests := []struct {
		server string
		want   string
	}{
		{"postgres", "database"},
		{"mysql", "database"},
		{"filesystem", "file"},
		{"github", "repository"},
		{"slack", "channel"},
		{"vault", "secret_store"},
		{"fetch", "external_api"},
		{"notion", "document"},
		{"unknown-thing", "service"},
	}
	for _, tt := range tests {
		target := ExtractTarget(tt.server, "test", "{}", nil)
		if target.ResourceType != tt.want {
			t.Errorf("server=%q: got resource_type=%q, want %q", tt.server, target.ResourceType, tt.want)
		}
	}
}

func TestExtractTarget_SensitivityFromFields(t *testing.T) {
	tests := []struct {
		fields []ClassifiedField
		want   int
	}{
		{nil, 1},
		{[]ClassifiedField{{Field: "email", Classification: "pii"}}, 2},
		{[]ClassifiedField{{Field: "ssn", Classification: "pii_sensitive"}}, 3},
		{[]ClassifiedField{{Field: "cc", Classification: "financial"}}, 3},
		{[]ClassifiedField{{Field: "pw", Classification: "auth"}}, 4},
		{[]ClassifiedField{
			{Field: "email", Classification: "pii"},
			{Field: "pw", Classification: "auth"},
		}, 4},
	}
	for _, tt := range tests {
		target := ExtractTarget("test", "test", "{}", tt.fields)
		if target.SensitivityLevel != tt.want {
			t.Errorf("fields=%v: got sensitivity=%d, want %d", tt.fields, target.SensitivityLevel, tt.want)
		}
	}
}

func TestExtractTarget_ResourceID(t *testing.T) {
	target := ExtractTarget("filesystem", "read", `{"path": "/etc/passwd"}`, nil)
	if target.ResourceID != "/etc/passwd" {
		t.Errorf("expected resource_id=/etc/passwd, got %q", target.ResourceID)
	}

	target = ExtractTarget("github", "clone", `{"repository": "org/repo"}`, nil)
	if target.ResourceID != "org/repo" {
		t.Errorf("expected resource_id=org/repo, got %q", target.ResourceID)
	}

	target = ExtractTarget("slack", "send", `{"channel": "#general"}`, nil)
	if target.ResourceID != "#general" {
		t.Errorf("expected resource_id=#general, got %q", target.ResourceID)
	}
}

func TestExtractTarget_NoResourceID(t *testing.T) {
	target := ExtractTarget("test", "test", `{"foo": "bar"}`, nil)
	if target.ResourceID != "" {
		t.Errorf("expected empty resource_id, got %q", target.ResourceID)
	}
}

func TestExtractTarget_PartialServerMatch(t *testing.T) {
	// "my-postgres-server" should still match "postgres"
	target := ExtractTarget("my-postgres-server", "query", "{}", nil)
	if target.ResourceType != "database" {
		t.Errorf("expected database for partial match, got %q", target.ResourceType)
	}
}
