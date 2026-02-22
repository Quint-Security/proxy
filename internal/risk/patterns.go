package risk

import "regexp"

// RiskPattern defines a base risk score for tools matching a glob pattern.
type RiskPattern struct {
	Tool      string
	BaseScore int
}

// DefaultToolRisks are the built-in risk patterns matching the TypeScript implementation.
var DefaultToolRisks = []RiskPattern{
	// Destructive file operations
	{Tool: "Delete*", BaseScore: 80},
	{Tool: "Remove*", BaseScore: 80},
	{Tool: "Rm*", BaseScore: 80},
	// Write operations
	{Tool: "Write*", BaseScore: 50},
	{Tool: "Create*", BaseScore: 40},
	{Tool: "Update*", BaseScore: 45},
	{Tool: "Edit*", BaseScore: 45},
	// Database operations
	{Tool: "*Sql*", BaseScore: 60},
	{Tool: "*Query*", BaseScore: 40},
	{Tool: "*Database*", BaseScore: 55},
	// Execution
	{Tool: "*Execute*", BaseScore: 70},
	{Tool: "*Run*", BaseScore: 65},
	{Tool: "*Shell*", BaseScore: 75},
	{Tool: "*Bash*", BaseScore: 75},
	{Tool: "*Command*", BaseScore: 70},
	// Network
	{Tool: "*Fetch*", BaseScore: 35},
	{Tool: "*Http*", BaseScore: 35},
	{Tool: "*Request*", BaseScore: 35},
	// Read operations (low risk)
	{Tool: "Read*", BaseScore: 10},
	{Tool: "Get*", BaseScore: 10},
	{Tool: "List*", BaseScore: 5},
	{Tool: "Search*", BaseScore: 10},
}

// ArgKeyword defines a pattern that, when found in arguments, boosts the risk score.
type ArgKeyword struct {
	Pattern *regexp.Regexp
	Boost   int
	Label   string // human-readable description of what was matched
}

// DangerousArgKeywords are argument patterns that increase risk scores.
var DangerousArgKeywords = []ArgKeyword{
	{Pattern: regexp.MustCompile(`(?i)\bdrop\b`), Boost: 30, Label: `\bdrop\b`},
	{Pattern: regexp.MustCompile(`(?i)\bdelete\b`), Boost: 25, Label: `\bdelete\b`},
	{Pattern: regexp.MustCompile(`(?i)\btruncate\b`), Boost: 25, Label: `\btruncate\b`},
	{Pattern: regexp.MustCompile(`(?i)\brm\s+-rf\b`), Boost: 30, Label: `\brm\s+-rf\b`},
	{Pattern: regexp.MustCompile(`(?i)\bformat\b`), Boost: 20, Label: `\bformat\b`},
	{Pattern: regexp.MustCompile(`(?i)\b(sudo|chmod|chown)\b`), Boost: 25, Label: `\b(sudo|chmod|chown)\b`},
	{Pattern: regexp.MustCompile(`(?i)\bpassword\b`), Boost: 15, Label: `\bpassword\b`},
	{Pattern: regexp.MustCompile(`(?i)\bsecret\b`), Boost: 15, Label: `\bsecret\b`},
	{Pattern: regexp.MustCompile(`(?i)\btoken\b`), Boost: 10, Label: `\btoken\b`},
	{Pattern: regexp.MustCompile(`(?i)\b(\.env|credentials)\b`), Boost: 20, Label: `\b(\.env|credentials)\b`},
}
