package forwardproxy

import (
	"strings"
	"testing"
)

func TestGenerateWordName_Deterministic(t *testing.T) {
	// Same seed + provider → same name
	name1 := GenerateWordName("anthropic", "127.0.0.1:claude-code")
	name2 := GenerateWordName("anthropic", "127.0.0.1:claude-code")

	if name1 != name2 {
		t.Errorf("same seed produced different names: %q vs %q", name1, name2)
	}
}

func TestGenerateWordName_ProviderPrefix(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{"anthropic", "anthropic:"},
		{"openai", "openai:"},
		{"google", "google:"},
		{"", "agent:"},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			name := GenerateWordName(tt.provider, "test-seed")
			if !strings.HasPrefix(name, tt.want) {
				t.Errorf("GenerateWordName(%q, ...) = %q, want prefix %q", tt.provider, name, tt.want)
			}
		})
	}
}

func TestGenerateWordName_Format(t *testing.T) {
	name := GenerateWordName("anthropic", "test-seed")

	// Format: provider:adj-color-animal
	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("expected format provider:adj-color-animal, got %q", name)
	}

	words := strings.Split(parts[1], "-")
	if len(words) != 3 {
		t.Errorf("expected 3 words after colon, got %d in %q", len(words), name)
	}
}

func TestGenerateWordName_DifferentSeeds(t *testing.T) {
	// Different seeds should produce different names (with high probability)
	seen := make(map[string]bool)
	collisions := 0

	for i := 0; i < 1000; i++ {
		seed := strings.Repeat("x", i) + "seed"
		name := GenerateWordName("agent", seed)
		if seen[name] {
			collisions++
		}
		seen[name] = true
	}

	// With ~100*100*95 = 950,000 possible names, 1000 random seeds
	// should have very few collisions (birthday problem: ~0.5 expected)
	if collisions > 10 {
		t.Errorf("too many collisions: %d out of 1000 seeds", collisions)
	}
}

func TestDeriveChildName_Format(t *testing.T) {
	name := DeriveChildName("anthropic:swift-blue-falcon", "agent-123", 1)

	if !strings.HasPrefix(name, "derived_") {
		t.Errorf("expected 'derived_' prefix, got %q", name)
	}
	if !strings.Contains(name, "anthropic:swift-blue-falcon") {
		t.Errorf("expected parent name in derived name, got %q", name)
	}
}

func TestDeriveChildName_Deterministic(t *testing.T) {
	name1 := DeriveChildName("parent", "id-123", 1)
	name2 := DeriveChildName("parent", "id-123", 1)

	if name1 != name2 {
		t.Errorf("same inputs produced different names: %q vs %q", name1, name2)
	}
}

func TestDeriveChildName_DifferentChildren(t *testing.T) {
	name1 := DeriveChildName("parent", "id-123", 1)
	name2 := DeriveChildName("parent", "id-123", 2)

	if name1 == name2 {
		t.Errorf("different child numbers should produce different names, both got %q", name1)
	}
}
