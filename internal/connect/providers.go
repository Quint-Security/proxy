package connect

import "strings"

// Provider defines a known OAuth provider.
type Provider struct {
	Name          string            `json:"name"`
	ClientID      string            `json:"client_id,omitempty"`
	ClientSecret  string            `json:"client_secret,omitempty"`
	AuthURL       string            `json:"auth_url"`
	TokenURL      string            `json:"token_url"`
	CallbackPort  int               `json:"callback_port,omitempty"`
	DefaultScopes []string          `json:"default_scopes"`
	Docs          string            `json:"docs"`
	BasicAuth     bool              `json:"basic_auth,omitempty"`
	TLSCallback   bool              `json:"tls_callback,omitempty"`
	ExtraParams   map[string]string `json:"extra_params,omitempty"`
}

// Providers is the map of known OAuth providers.
// Client IDs and secrets are fetched at runtime from the Quint API.
// Only GitHub's public client ID is kept here as a fallback.
var Providers = map[string]Provider{
	"github": {
		Name:          "GitHub",
		ClientID:      "Ov23liVPN35pZFQ7L7Rl",
		AuthURL:       "https://github.com/login/oauth/authorize",
		TokenURL:      "https://github.com/login/oauth/access_token",
		CallbackPort:  7890,
		DefaultScopes: []string{"repo", "read:org"},
		Docs:          "https://github.com/settings/developers",
	},
	"notion": {
		Name:          "Notion",
		AuthURL:       "https://api.notion.com/v1/oauth/authorize",
		TokenURL:      "https://api.notion.com/v1/oauth/token",
		CallbackPort:  7890,
		DefaultScopes: []string{},
		Docs:          "https://www.notion.so/my-integrations",
		BasicAuth:     true,
		ExtraParams:   map[string]string{"owner": "user"},
	},
	"slack": {
		Name:          "Slack",
		AuthURL:       "https://slack.com/oauth/v2/authorize",
		TokenURL:      "https://slack.com/api/oauth.v2.access",
		CallbackPort:  7890,
		DefaultScopes: []string{"app_mentions:read", "bookmarks:read", "calls:read", "calls:write", "users:read", "files:read"},
		Docs:          "https://api.slack.com/apps",
		TLSCallback:   true,
	},
	"sentry": {
		Name:          "Sentry",
		AuthURL:       "https://sentry.io/oauth/authorize/",
		TokenURL:      "https://sentry.io/oauth/token/",
		DefaultScopes: []string{"project:read", "event:read"},
		Docs:          "https://sentry.io/settings/developer-settings/",
	},
	"linear": {
		Name:          "Linear",
		AuthURL:       "https://linear.app/oauth/authorize",
		TokenURL:      "https://api.linear.app/oauth/token",
		DefaultScopes: []string{"read", "write"},
		Docs:          "https://linear.app/settings/api",
	},
}

// GetProvider returns a known provider by name, or nil.
func GetProvider(name string) *Provider {
	if p, ok := Providers[strings.ToLower(name)]; ok {
		return &p
	}
	return nil
}
