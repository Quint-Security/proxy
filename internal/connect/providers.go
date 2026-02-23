package connect

import "strings"

// Provider defines a known OAuth provider.
type Provider struct {
	Name          string   `json:"name"`
	ClientID      string   `json:"client_id,omitempty"`
	ClientSecret  string   `json:"client_secret,omitempty"`
	AuthURL       string   `json:"auth_url"`
	TokenURL      string   `json:"token_url"`
	CallbackPort  int      `json:"callback_port,omitempty"`
	DefaultScopes []string `json:"default_scopes"`
	Docs          string   `json:"docs"`
}

// Providers is the map of known OAuth providers.
var Providers = map[string]Provider{
	"github": {
		Name:          "GitHub",
		ClientID:      "Ov23liVPN35pZFQ7L7Rl",
		ClientSecret:  "681de8ad98acad13193e1fe93f072f67645aa3c9",
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
		DefaultScopes: []string{},
		Docs:          "https://www.notion.so/my-integrations",
	},
	"slack": {
		Name:          "Slack",
		AuthURL:       "https://slack.com/oauth/v2/authorize",
		TokenURL:      "https://slack.com/api/oauth.v2.access",
		DefaultScopes: []string{"chat:write", "channels:read"},
		Docs:          "https://api.slack.com/apps",
	},
	"sentry": {
		Name:          "Sentry",
		AuthURL:       "https://sentry.io/oauth/authorize/",
		TokenURL:      "https://sentry.io/oauth/token/",
		DefaultScopes: []string{"project:read", "event:read"},
		Docs:          "https://sentry.io/settings/developer-settings/",
	},
}

// GetProvider returns a known provider by name, or nil.
func GetProvider(name string) *Provider {
	if p, ok := Providers[strings.ToLower(name)]; ok {
		return &p
	}
	return nil
}
