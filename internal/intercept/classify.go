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

// ClassifyHTTPAction converts an HTTP request to canonical action format.
// Format: http:{domain}:{method}.{path_slug}
// Examples:
//
//	GET  api.github.com/repos/foo/bar     -> http:api.github.com:get.repos
//	POST api.openai.com/v1/completions    -> http:api.openai.com:post.completions
//	CONNECT pastebin.com:443              -> http:pastebin.com:connect.tunnel
func ClassifyHTTPAction(method, host, path string) string {
	domain := sanitizeSegment(StripPort(host))
	verb := strings.ToLower(method)
	slug := inferPathSlug(path)
	return fmt.Sprintf("http:%s:%s.%s", domain, verb, slug)
}

// StripPort removes the port suffix from a host string.
// "api.github.com:443" -> "api.github.com"
func StripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i >= 0 {
		// Make sure it's a port, not part of an IPv6 address
		if strings.Contains(host, "]") {
			// IPv6: [::1]:443
			if j := strings.LastIndex(host, "]"); j < i {
				return host[:i]
			}
			return host
		}
		return host[:i]
	}
	return host
}

// inferPathSlug extracts a meaningful slug from a URL path.
// "/v1/chat/completions" -> "completions"
// "/repos/owner/name/pulls" -> "pulls"
// "/" or "" -> "root"
func inferPathSlug(path string) string {
	if path == "" || path == "/" {
		return "root"
	}

	// Strip query string
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}

	// Split and work backwards to find a meaningful segment
	parts := strings.Split(strings.Trim(path, "/"), "/")

	// Filter out version prefixes and UUIDs/numeric IDs
	var meaningful []string
	for _, p := range parts {
		lower := strings.ToLower(p)
		// Skip version prefixes
		if len(lower) >= 2 && lower[0] == 'v' && lower[1] >= '0' && lower[1] <= '9' {
			continue
		}
		// Skip purely numeric segments (IDs)
		allDigits := true
		for _, c := range lower {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(lower) > 0 {
			continue
		}
		if lower != "" {
			meaningful = append(meaningful, lower)
		}
	}

	if len(meaningful) == 0 {
		return "root"
	}

	// Take the last meaningful segment
	return sanitizeSegment(meaningful[len(meaningful)-1])
}

// sanitizeSegment replaces characters that would break the taxonomy format.
// The risk API requires segments to match [a-z0-9_.]+ (no hyphens, colons, etc).
func sanitizeSegment(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
