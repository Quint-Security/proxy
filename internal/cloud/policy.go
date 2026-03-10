package cloud

import (
	"time"
)

// CloudPolicy represents an enforcement policy fetched from the cloud API.
type CloudPolicy struct {
	ID          string       `json:"id"`
	OrgID       string       `json:"org_id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Enabled     bool         `json:"enabled"`
	Rules       []PolicyRule `json:"rules"`
	Priority    int          `json:"priority"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// PolicyRule defines a single enforcement rule within a policy.
type PolicyRule struct {
	Tool       string   `json:"tool"`
	Agent      string   `json:"agent"`
	Action     string   `json:"action"`                // "block", "flag", "require_approval"
	Conditions []string `json:"conditions,omitempty"`
}
