package pac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePAC_BasicOutput(t *testing.T) {
	pac := GeneratePAC(9090, []string{"api.openai.com"})

	if !strings.Contains(pac, "function FindProxyForURL(url, host)") {
		t.Fatal("PAC missing FindProxyForURL function declaration")
	}
	if !strings.Contains(pac, "PROXY") {
		t.Fatal("PAC missing PROXY directive")
	}
	if !strings.Contains(pac, "DIRECT") {
		t.Fatal("PAC missing DIRECT directive")
	}
}

func TestGeneratePAC_ExactDomains(t *testing.T) {
	domains := []string{"api.openai.com", "api.anthropic.com"}
	pac := GeneratePAC(9090, domains)

	for _, d := range domains {
		expected := `host == "` + d + `"`
		if !strings.Contains(pac, expected) {
			t.Errorf("PAC missing exact match for %s; expected %q in output", d, expected)
		}
	}

	// Exact domains should not use shExpMatch.
	if strings.Contains(pac, "shExpMatch") {
		t.Error("PAC should not contain shExpMatch for exact domains only")
	}
}

func TestGeneratePAC_WildcardDomains(t *testing.T) {
	domains := []string{"*.openai.azure.com", "bedrock-runtime.*.amazonaws.com"}
	pac := GeneratePAC(9090, domains)

	for _, d := range domains {
		expected := `shExpMatch(host, "` + d + `")`
		if !strings.Contains(pac, expected) {
			t.Errorf("PAC missing shExpMatch for %s; expected %q in output", d, expected)
		}
	}

	// Wildcard domains should not use host ==.
	if strings.Contains(pac, "host ==") {
		t.Error("PAC should not contain host == for wildcard-only domains")
	}
}

func TestGeneratePAC_CustomPort(t *testing.T) {
	pac := GeneratePAC(8888, []string{"api.openai.com"})

	if !strings.Contains(pac, "PROXY 127.0.0.1:8888") {
		t.Error("PAC does not contain the custom port 8888")
	}
	if strings.Contains(pac, "PROXY 127.0.0.1:9090") {
		t.Error("PAC should not contain default port 9090 when custom port is used")
	}
}

func TestMergeDomains_Dedup(t *testing.T) {
	defaults := []string{"api.openai.com", "api.anthropic.com"}
	custom := []string{"api.openai.com", "custom.example.com"}

	merged := MergeDomains(defaults, custom)

	if len(merged) != 3 {
		t.Fatalf("expected 3 merged domains, got %d: %v", len(merged), merged)
	}

	// Verify order: defaults first, then new customs.
	if merged[0] != "api.openai.com" || merged[1] != "api.anthropic.com" || merged[2] != "custom.example.com" {
		t.Errorf("unexpected merge order: %v", merged)
	}
}

func TestMergeDomains_Empty(t *testing.T) {
	// Both nil.
	merged := MergeDomains(nil, nil)
	if len(merged) != 0 {
		t.Fatalf("expected 0 merged domains from nil inputs, got %d", len(merged))
	}

	// Defaults only.
	merged = MergeDomains([]string{"a.com"}, nil)
	if len(merged) != 1 || merged[0] != "a.com" {
		t.Fatalf("expected [a.com], got %v", merged)
	}

	// Custom only.
	merged = MergeDomains(nil, []string{"b.com"})
	if len(merged) != 1 || merged[0] != "b.com" {
		t.Fatalf("expected [b.com], got %v", merged)
	}

	// Empty slices (not nil).
	merged = MergeDomains([]string{}, []string{})
	if len(merged) != 0 {
		t.Fatalf("expected 0 merged domains from empty slices, got %d", len(merged))
	}
}

func TestLoadCustomDomains_MissingFile(t *testing.T) {
	dir := t.TempDir()

	domains, err := LoadCustomDomains(dir)
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if domains != nil {
		t.Fatalf("expected nil domains for missing file, got: %v", domains)
	}
}

func TestLoadCustomDomains_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai-providers.json")

	content := `{"domains": ["custom1.example.com", "*.custom2.example.com"]}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	domains, err := LoadCustomDomains(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	if domains[0] != "custom1.example.com" {
		t.Errorf("expected custom1.example.com, got %s", domains[0])
	}
	if domains[1] != "*.custom2.example.com" {
		t.Errorf("expected *.custom2.example.com, got %s", domains[1])
	}
}

func TestLoadCustomDomains_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai-providers.json")

	if err := os.WriteFile(path, []byte("{not valid json}"), 0o644); err != nil {
		t.Fatal(err)
	}

	domains, err := LoadCustomDomains(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if domains != nil {
		t.Fatalf("expected nil domains for invalid JSON, got: %v", domains)
	}
}

func TestWritePACFile_WritesToDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.pac")

	domains := []string{"api.openai.com", "*.openai.azure.com"}
	count, err := WritePACFile(path, 9090, domains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected domain count 2, got %d", count)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read PAC file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "FindProxyForURL") {
		t.Error("written PAC file missing FindProxyForURL")
	}
	if !strings.Contains(content, "api.openai.com") {
		t.Error("written PAC file missing api.openai.com")
	}
	if !strings.Contains(content, "shExpMatch") {
		t.Error("written PAC file missing shExpMatch for wildcard domain")
	}
}

func TestSaveThenLoadCustomDomains(t *testing.T) {
	dir := t.TempDir()

	original := []string{"custom1.example.com", "*.custom2.example.com", "api.myai.dev"}

	if err := SaveCustomDomains(dir, original); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := LoadCustomDomains(dir)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if len(loaded) != len(original) {
		t.Fatalf("expected %d domains, got %d", len(original), len(loaded))
	}

	for i, d := range original {
		if loaded[i] != d {
			t.Errorf("domain[%d]: expected %q, got %q", i, d, loaded[i])
		}
	}
}
