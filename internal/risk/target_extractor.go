package risk

import (
	"encoding/json"
	"strings"
)

// TargetInfo matches the cloud API's target schema.
type TargetInfo struct {
	ResourceType     string `json:"resource_type"`
	ResourceID       string `json:"resource_id,omitempty"`
	SensitivityLevel int    `json:"sensitivity_level"`
}

// server name → resource type mapping
var serverResourceTypes = map[string]string{
	"postgres":   "database",
	"postgresql": "database",
	"mysql":      "database",
	"sqlite":     "database",
	"mongo":      "database",
	"mongodb":    "database",
	"redis":      "database",
	"database":   "database",
	"db":         "database",
	"filesystem": "file",
	"fs":         "file",
	"file":       "file",
	"github":     "repository",
	"gitlab":     "repository",
	"bitbucket":  "repository",
	"git":        "repository",
	"slack":      "channel",
	"discord":    "channel",
	"teams":      "channel",
	"telegram":   "channel",
	"vault":      "secret_store",
	"secrets":    "secret_store",
	"aws":        "cloud_service",
	"gcp":        "cloud_service",
	"azure":      "cloud_service",
	"s3":         "object_store",
	"notion":     "document",
	"confluence": "document",
	"jira":       "issue_tracker",
	"linear":     "issue_tracker",
	"email":      "email",
	"smtp":       "email",
	"fetch":      "external_api",
	"http":       "external_api",
	"network":    "external_api",
	"browser":    "web_page",
}

// keys to look for resource_id in tool arguments
var resourceIDKeys = []string{"path", "url", "uri", "table", "database", "db", "repository", "repo", "channel", "bucket", "file", "filename", "resource", "endpoint", "collection", "queue", "topic"}

// ExtractTarget infers target info from the tool call context.
func ExtractTarget(serverName, toolName, argsJSON string, fields []ClassifiedField) *TargetInfo {
	target := &TargetInfo{
		ResourceType:     inferResourceType(serverName),
		SensitivityLevel: inferSensitivity(fields),
	}

	// Try to extract resource ID from tool arguments
	if argsJSON != "" && argsJSON != "{}" {
		var args map[string]any
		if err := json.Unmarshal([]byte(argsJSON), &args); err == nil {
			target.ResourceID = extractResourceID(args)
		}
	}

	return target
}

// inferResourceType maps server name to a resource type.
func inferResourceType(serverName string) string {
	lower := strings.ToLower(serverName)
	// exact match
	if rt, ok := serverResourceTypes[lower]; ok {
		return rt
	}
	// partial match
	for prefix, rt := range serverResourceTypes {
		if strings.Contains(lower, prefix) {
			return rt
		}
	}
	return "service"
}

// inferSensitivity returns the highest sensitivity level based on classified fields.
// 0=public, 1=internal, 2=pii, 3=pii_sensitive/financial/health, 4=auth
func inferSensitivity(fields []ClassifiedField) int {
	if len(fields) == 0 {
		return 1
	}
	max := 1
	for _, f := range fields {
		level := classificationToLevel(f.Classification)
		if level > max {
			max = level
		}
	}
	return max
}

func classificationToLevel(c string) int {
	switch c {
	case "auth":
		return 4
	case "pii_sensitive", "financial", "health":
		return 3
	case "pii":
		return 2
	case "legal", "internal":
		return 1
	default:
		return 0
	}
}

// extractResourceID looks for common resource identifier keys in tool arguments.
func extractResourceID(args map[string]any) string {
	for _, key := range resourceIDKeys {
		if val, ok := args[key]; ok {
			if s, ok := val.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
