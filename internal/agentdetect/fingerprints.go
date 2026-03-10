package agentdetect

import (
	"net/http"
	"strings"
)

// platformDef defines the identification fingerprint for an AI coding platform.
type platformDef struct {
	name string

	// processNames — names that pidlookup resolves to for this platform.
	// Matched exactly (case-insensitive) against ProcessInfo.ProcessName.
	processNames []string

	// processPathPatterns — substrings matched against the full executable path.
	processPathPatterns []string

	// headerMarkers — header name → expected value substring.
	// Any single match is a hard identifier.
	headerMarkers map[string]string

	// promptFingerprints — each entry is a set of substrings that must ALL
	// match (AND logic). Multiple entries are OR (any matching set = positive ID).
	// Checked against the lowercased system prompt.
	promptFingerprints [][]string

	// promptHashes — SHA256 hashes of known system prompts (exact version match).
	promptHashes []string

	// uaPatterns — substrings matched against the lowercased User-Agent.
	uaPatterns []string
}

// platforms is the embedded fingerprint registry. Order matters for
// promptFingerprints — more specific patterns should come first to avoid
// false positives from generic terms.
var platforms = []platformDef{
	{
		name:         "claude-code",
		processNames: []string{"claude-code", "claude"},
		processPathPatterns: []string{
			"claude.app", ".claude/local", "/claude-code",
		},
		promptFingerprints: [][]string{
			{"you are claude code"},
			{"claude code, anthropic"},
			{"claude-code"},
			{"software engineering tasks", "working directory"},
		},
		uaPatterns: []string{"claude-code", "claude-ai"},
	},
	{
		name:         "cursor",
		processNames: []string{"cursor"},
		processPathPatterns: []string{
			"cursor.app", "/cursor",
		},
		headerMarkers: map[string]string{
			"x-cursor-checksum":       "",
			"x-cursor-client-version": "",
		},
		promptFingerprints: [][]string{
			{"designed by cursor"},
			{"cursor", "world's best ide"},
			{"cursor", "pair programming", "ai"},
		},
		uaPatterns: []string{"cursor"},
	},
	{
		name:         "copilot",
		processNames: []string{"copilot"},
		processPathPatterns: []string{
			"copilot",
		},
		headerMarkers: map[string]string{
			"copilot-integration-id": "",
			"x-github-api-version":   "",
		},
		promptFingerprints: [][]string{
			{"github copilot"},
			{"copilot", "github"},
		},
		uaPatterns: []string{"copilot"},
	},
	{
		name:         "windsurf",
		processNames: []string{"windsurf"},
		processPathPatterns: []string{
			"windsurf.app", "/windsurf",
		},
		headerMarkers: map[string]string{
			"x-codeium-session-id": "",
		},
		promptFingerprints: [][]string{
			{"windsurf"},
			{"codeium", "cascade"},
		},
		uaPatterns: []string{"windsurf", "codeium"},
	},
	{
		name:         "kiro",
		processNames: []string{"kiro"},
		processPathPatterns: []string{
			"kiro.app", "/kiro",
		},
		promptFingerprints: [][]string{
			{"kiro"},
		},
		uaPatterns: []string{"kiro"},
	},
	{
		name:         "aider",
		processNames: []string{"aider"},
		processPathPatterns: []string{
			"/aider",
		},
		promptFingerprints: [][]string{
			{"aider", "chat"},
			{"aider", "architect"},
		},
		uaPatterns: []string{"aider"},
	},
	{
		name:         "cline",
		processNames: []string{"cline"},
		processPathPatterns: []string{
			"cline",
		},
		promptFingerprints: [][]string{
			{"cline"},
			{"roo-code"},
			{"roo code"},
		},
		uaPatterns: []string{"cline", "roo-code"},
	},
	{
		name:         "continue",
		processNames: []string{"continue"},
		processPathPatterns: []string{
			"continue",
		},
		headerMarkers: map[string]string{
			"x-continue-session": "",
		},
		promptFingerprints: [][]string{
			{"continue.dev"},
			{"continue", "open-source", "ai code assistant"},
		},
		uaPatterns: []string{"continue"},
	},
	{
		name:         "codex",
		processNames: []string{"codex"},
		processPathPatterns: []string{
			"codex-cli", "/codex",
		},
		promptFingerprints: [][]string{
			{"codex", "openai"},
			{"codex-cli"},
		},
		uaPatterns: []string{"codex-cli", "codex/", "openai-codex"},
	},
	{
		name:                "augment",
		processNames:        []string{"augment"},
		processPathPatterns: []string{"augment"},
		promptFingerprints: [][]string{
			{"augment", "code"},
		},
		uaPatterns: []string{"augment"},
	},
	{
		name:                "goose",
		processNames:        []string{"goose"},
		processPathPatterns: []string{"/goose", "gose"},
		promptFingerprints: [][]string{
			{"goose", "agent"},
		},
		uaPatterns: []string{"gose", "goose"},
	},
	{
		name:         "gemini-cli",
		processNames: []string{"gemini"},
		processPathPatterns: []string{
			"gemini-cli", "/gemini",
		},
		promptFingerprints: [][]string{
			{"gemini", "cli"},
			{"google", "code assist"},
		},
		uaPatterns: []string{"gemini-cli"},
	},
	{
		name:                "amp",
		processNames:        []string{"amp"},
		processPathPatterns: []string{"/amp"},
		promptFingerprints: [][]string{
			{"amp", "sourcegraph"},
		},
		uaPatterns: []string{"amp"},
	},
	{
		name:                "zed",
		processNames:        []string{"zed"},
		processPathPatterns: []string{"zed.app", "/zed"},
		uaPatterns:          []string{"zed"},
	},
	{
		name:                "opencode",
		processNames:        []string{"opencode"},
		processPathPatterns: []string{"/opencode"},
		uaPatterns:          []string{"opencode"},
	},
	{
		name:                "pearai",
		processNames:        []string{"pearai"},
		processPathPatterns: []string{"pearai.app"},
		uaPatterns:          []string{"pear"},
	},
	{
		name:                "trae",
		processNames:        []string{"trae"},
		processPathPatterns: []string{"trae.app"},
		uaPatterns:          []string{"trae"},
	},
	{
		name:                "void",
		processNames:        []string{"void"},
		processPathPatterns: []string{"void.app"},
		uaPatterns:          []string{"void"},
	},
	{
		name:                "devin",
		processNames:        []string{"devin"},
		processPathPatterns: []string{"devin"},
		uaPatterns:          []string{"devin"},
	},
}

// identifyFromProcess checks the process name and path against known platforms.
// pidlookup already resolves known agents via knownAgentNames, so processName
// may already be "claude-code", "cursor", etc.
func identifyFromProcess(processName, processPath string) string {
	if processName == "" && processPath == "" {
		return ""
	}
	lowerName := strings.ToLower(processName)
	lowerPath := strings.ToLower(processPath)

	for _, p := range platforms {
		for _, name := range p.processNames {
			if lowerName == name {
				return p.name
			}
		}
		for _, pattern := range p.processPathPatterns {
			if lowerPath != "" && strings.Contains(lowerPath, strings.ToLower(pattern)) {
				return p.name
			}
		}
	}
	return ""
}

// identifyFromHeaders checks HTTP headers for agent-specific markers.
func identifyFromHeaders(h http.Header) (string, float64) {
	if h == nil {
		return "", 0
	}
	for _, p := range platforms {
		for header, expectedVal := range p.headerMarkers {
			actual := h.Get(header)
			if actual == "" {
				continue
			}
			// Empty expectedVal means any non-empty value is a match
			if expectedVal == "" || containsFold(actual, expectedVal) {
				return p.name, 0.9
			}
		}
	}
	return "", 0
}

// identifyFromSystemPrompt checks the system prompt against known fingerprint patterns.
func identifyFromSystemPrompt(systemPrompt string) (string, float64) {
	if systemPrompt == "" {
		return "", 0
	}
	lower := strings.ToLower(systemPrompt)

	for _, p := range platforms {
		for _, fingerprint := range p.promptFingerprints {
			if matchAllSubstrings(lower, fingerprint) {
				return p.name, 0.95
			}
		}
	}
	return "", 0
}

// matchPromptHash checks if a system prompt hash matches any known platform.
func matchPromptHash(hash string) string {
	for _, p := range platforms {
		for _, h := range p.promptHashes {
			if h == hash {
				return p.name
			}
		}
	}
	return ""
}

// identifyFromUA checks the User-Agent against known platform patterns.
// Returns higher confidence (0.85) for specific agent UAs, lower (0.2) for
// generic SDK UAs that might be used by any agent.
func identifyFromUA(ua string) (string, float64) {
	if ua == "" {
		return "", 0
	}
	lower := strings.ToLower(ua)

	for _, p := range platforms {
		for _, pattern := range p.uaPatterns {
			if strings.Contains(lower, pattern) {
				return p.name, 0.85
			}
		}
	}
	return "", 0
}

// matchAllSubstrings returns true if haystack contains ALL of the given substrings.
func matchAllSubstrings(haystack string, substrings []string) bool {
	for _, sub := range substrings {
		if !strings.Contains(haystack, sub) {
			return false
		}
	}
	return len(substrings) > 0
}
