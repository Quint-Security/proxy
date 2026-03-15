package procscan

import "strings"

// AgentSignature defines how to identify an AI agent by its OS process.
type AgentSignature struct {
	Platform     string   // canonical name (e.g., "claude-code")
	ProcessNames []string // exact process name matches (case-insensitive)
	PathPatterns []string // substring matches in binary path
	ParentHints  []string // if parent process matches, child is this agent
}

// KnownAgents is the authoritative list of AI agent process signatures.
// NOTE: Also update internal/agentdetect/fingerprints.go when adding agents here.
var KnownAgents = []AgentSignature{
	{Platform: "claude-code", ProcessNames: []string{"claude", "claude-code"}, PathPatterns: []string{"claude.app", ".claude/local", "/claude-code"}},
	{Platform: "cursor", ProcessNames: []string{"cursor", "Cursor Helper"}, PathPatterns: []string{"Cursor.app", "/cursor"}},
	{Platform: "copilot", ProcessNames: []string{"copilot"}, PathPatterns: []string{"copilot"}},
	{Platform: "windsurf", ProcessNames: []string{"windsurf"}, PathPatterns: []string{"Windsurf.app", "/windsurf"}},
	{Platform: "kiro", ProcessNames: []string{"kiro"}, PathPatterns: []string{"Kiro.app", "/kiro"}},
	{Platform: "codex", ProcessNames: []string{"codex"}, PathPatterns: []string{"codex-cli", "/codex"}},
	{Platform: "aider", ProcessNames: []string{"aider"}, PathPatterns: []string{"/aider"}},
	{Platform: "cline", ProcessNames: []string{"cline"}, PathPatterns: []string{"cline"}},
	{Platform: "continue", ProcessNames: []string{"continue"}, PathPatterns: []string{"continue"}},
	{Platform: "augment", ProcessNames: []string{"augment"}, PathPatterns: []string{"augment"}},
	{Platform: "goose", ProcessNames: []string{"goose"}, PathPatterns: []string{"/goose"}},
	{Platform: "gemini-cli", ProcessNames: []string{"gemini"}, PathPatterns: []string{"gemini-cli", "/gemini"}},
	{Platform: "amp", ProcessNames: []string{"amp"}, PathPatterns: []string{"/amp"}},
	{Platform: "zed", ProcessNames: []string{"zed"}, PathPatterns: []string{"Zed.app", "/zed"}},
	{Platform: "opencode", ProcessNames: []string{"opencode"}, PathPatterns: []string{"/opencode"}},
	{Platform: "pearai", ProcessNames: []string{"pearai"}, PathPatterns: []string{"PearAI.app"}},
	{Platform: "trae", ProcessNames: []string{"trae"}, PathPatterns: []string{"Trae.app"}},
	{Platform: "void", ProcessNames: []string{"void"}, PathPatterns: []string{"Void.app"}},
	{Platform: "devin", ProcessNames: []string{"devin"}, PathPatterns: []string{"devin"}},
}

// MatchProcess checks a process name and binary path against KnownAgents.
// Returns the platform name and true if matched, empty string and false otherwise.
// Name matching is case-insensitive. Path matching is substring-based.
func MatchProcess(name, path string) (string, bool) {
	lowerName := strings.ToLower(name)

	for _, sig := range KnownAgents {
		// Check process names (case-insensitive exact match)
		for _, pn := range sig.ProcessNames {
			if lowerName == strings.ToLower(pn) {
				return sig.Platform, true
			}
		}

		// Check path patterns (substring match)
		if path != "" {
			for _, pattern := range sig.PathPatterns {
				if strings.Contains(path, pattern) {
					return sig.Platform, true
				}
			}
		}
	}

	return "", false
}
