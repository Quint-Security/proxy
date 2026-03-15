package pac

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// customDomainsFile is the JSON config file name for user-specified domains.
const customDomainsFile = "ai-providers.json"

// customDomainsJSON is the on-disk format for the custom domains file.
type customDomainsJSON struct {
	Domains []string `json:"domains"`
}

// GeneratePAC produces a valid JavaScript PAC file string.
// Traffic to listed domains routes through PROXY 127.0.0.1:{port}; DIRECT.
// Everything else goes DIRECT.
func GeneratePAC(proxyPort int, domains []string) string {
	var b strings.Builder

	b.WriteString("function FindProxyForURL(url, host) {\n")

	proxy := fmt.Sprintf("PROXY 127.0.0.1:%d; DIRECT", proxyPort)

	// Separate exact-match and wildcard domains.
	var exact, wildcard []string
	for _, d := range domains {
		if strings.Contains(d, "*") {
			wildcard = append(wildcard, d)
		} else {
			exact = append(exact, d)
		}
	}

	// Exact match domains — use host == for speed.
	if len(exact) > 0 {
		b.WriteString("  // Exact match domains\n")
		for _, d := range exact {
			fmt.Fprintf(&b, "  if (host == %q) return %q;\n", d, proxy)
		}
	}

	// Wildcard match domains — use shExpMatch.
	if len(wildcard) > 0 {
		if len(exact) > 0 {
			b.WriteString("\n")
		}
		b.WriteString("  // Wildcard match domains\n")
		for _, d := range wildcard {
			fmt.Fprintf(&b, "  if (shExpMatch(host, %q)) return %q;\n", d, proxy)
		}
	}

	b.WriteString("\n  return \"DIRECT\";\n")
	b.WriteString("}\n")

	return b.String()
}

// LoadCustomDomains reads {dir}/ai-providers.json and returns custom domains.
// Returns nil, nil if the file does not exist.
func LoadCustomDomains(dir string) ([]string, error) {
	path := filepath.Join(dir, customDomainsFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read custom domains: %w", err)
	}

	var cfg customDomainsJSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse custom domains %s: %w", path, err)
	}

	return cfg.Domains, nil
}

// SaveCustomDomains writes domains to {dir}/ai-providers.json.
func SaveCustomDomains(dir string, domains []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	cfg := customDomainsJSON{Domains: domains}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal custom domains: %w", err)
	}

	path := filepath.Join(dir, customDomainsFile)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write custom domains %s: %w", path, err)
	}

	return nil
}

// MergeDomains combines default and custom domains, deduplicating.
// Order is preserved: defaults first, then custom entries not already present.
func MergeDomains(defaults, custom []string) []string {
	seen := make(map[string]bool, len(defaults)+len(custom))
	var merged []string

	for _, d := range defaults {
		lower := strings.ToLower(d)
		if !seen[lower] {
			seen[lower] = true
			merged = append(merged, d)
		}
	}

	for _, d := range custom {
		lower := strings.ToLower(d)
		if !seen[lower] {
			seen[lower] = true
			merged = append(merged, d)
		}
	}

	return merged
}

// WritePACFile generates and writes the PAC file to disk. Returns the domain count.
func WritePACFile(path string, proxyPort int, domains []string) (int, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("create directory for PAC file: %w", err)
	}

	content := GeneratePAC(proxyPort, domains)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return 0, fmt.Errorf("write PAC file %s: %w", path, err)
	}

	return len(domains), nil
}
