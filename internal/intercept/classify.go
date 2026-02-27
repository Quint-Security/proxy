package intercept

import (
	"fmt"
	"strings"
)

// knownVerbs maps common tool name prefixes to canonical verbs.
var knownVerbs = map[string]string{
	"list":     "list",
	"get":      "read",
	"read":     "read",
	"fetch":    "read",
	"search":   "search",
	"find":     "search",
	"query":    "read",
	"create":   "create",
	"add":      "create",
	"insert":   "create",
	"write":    "write",
	"update":   "update",
	"edit":     "update",
	"modify":   "update",
	"patch":    "update",
	"set":      "update",
	"delete":   "delete",
	"remove":   "delete",
	"destroy":  "delete",
	"drop":     "delete",
	"send":     "send",
	"post":     "send",
	"publish":  "send",
	"execute":  "execute",
	"run":      "execute",
	"exec":     "execute",
	"invoke":   "invoke",
	"call":     "invoke",
	"upload":   "upload",
	"download": "download",
	"export":   "export",
	"import":   "import",
}

// ClassifyAction converts a tool call to canonical action format.
// Format: mcp:{server}:{tool}.{verb}
func ClassifyAction(serverName, toolName, method string) string {
	server := sanitizeSegment(serverName)

	switch method {
	case "tools/call":
		verb := inferVerb(toolName)
		tool := sanitizeSegment(toolName)
		return fmt.Sprintf("mcp:%s:%s.%s", server, tool, verb)
	case "resources/read":
		return fmt.Sprintf("mcp:%s:resource.read", server)
	case "prompts/get":
		return fmt.Sprintf("mcp:%s:prompt.get", server)
	default:
		sanitized := sanitizeSegment(method)
		return fmt.Sprintf("mcp:%s:%s", server, sanitized)
	}
}

// inferVerb extracts a verb from tool name patterns.
// "list_repos" -> "list", "create_file" -> "create", etc.
func inferVerb(toolName string) string {
	lower := strings.ToLower(toolName)

	// Split on _ and - to find verb prefix
	for _, sep := range []string{"_", "-"} {
		parts := strings.SplitN(lower, sep, 2)
		if len(parts) >= 2 {
			if verb, ok := knownVerbs[parts[0]]; ok {
				return verb
			}
		}
	}

	// Check if the whole name is a known verb
	if verb, ok := knownVerbs[lower]; ok {
		return verb
	}

	// Check if the name ends with a known verb pattern
	for prefix, verb := range knownVerbs {
		if strings.HasSuffix(lower, prefix) {
			return verb
		}
	}

	return "invoke"
}

// sanitizeSegment replaces characters that would break the taxonomy format.
func sanitizeSegment(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
