package cloud

import (
	"os"

	"gopkg.in/yaml.v3"
)

// DaemonConfig holds the configuration for the daemon mode,
// loaded from /etc/quint/config.yaml or a custom path.
type DaemonConfig struct {
	Token    string `yaml:"token"`
	APIURL   string `yaml:"api_url"`
	LogLevel string `yaml:"log_level"`
	LogFile  string `yaml:"log_file"`
}

// DefaultConfigPath is the standard location for daemon configuration.
const DefaultConfigPath = "/etc/quint/config.yaml"

// DefaultAPIURL is the production cloud API endpoint.
const DefaultAPIURL = "https://api.quintai.dev"

// LoadDaemonConfig reads a YAML config file and returns a DaemonConfig.
// Environment variables QUINT_DEPLOY_TOKEN and QUINT_API_URL override file values.
func LoadDaemonConfig(path string) (*DaemonConfig, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &DaemonConfig{APIURL: DefaultAPIURL}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if t := os.Getenv("QUINT_DEPLOY_TOKEN"); t != "" {
		cfg.Token = t
	}
	if u := os.Getenv("QUINT_API_URL"); u != "" {
		cfg.APIURL = u
	}
	return cfg, nil
}
