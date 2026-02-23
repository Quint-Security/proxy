package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config defines the gateway's downstream MCP servers.
type Config struct {
	Servers map[string]ServerConfig `json:"servers"`
}

// ServerConfig defines a single downstream MCP server.
type ServerConfig struct {
	// Stdio servers
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// HTTP servers
	URL       string            `json:"url,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Transport string            `json:"transport,omitempty"` // "streamablehttp" or "sse"
}

// IsHTTP returns true if this is an HTTP-based server.
func (s ServerConfig) IsHTTP() bool {
	return s.URL != ""
}

// LoadConfig loads the gateway config from the data directory.
func LoadConfig(dataDir string) (*Config, error) {
	path := filepath.Join(dataDir, "servers.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveConfig writes the gateway config to the data directory.
func SaveConfig(dataDir string, cfg *Config) error {
	path := filepath.Join(dataDir, "servers.json")
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
