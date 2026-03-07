package forwardproxy

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Quint-Security/quint-proxy/internal/auth"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// knownTools maps User-Agent substrings to canonical tool names.
// Checked in order — first match wins.
var knownTools = []struct {
	substring string
	name      string
}{
	{"claude-code", "claude-code"},
	{"claude", "claude"},
	{"cursor", "cursor"},
	{"aider", "aider"},
	{"continue", "continue"},
	{"cline", "cline"},
	{"copilot", "copilot"},
	{"windsurf", "windsurf"},
	{"zed", "zed"},
	{"python-httpx", "python-httpx"},
	{"python-requests", "python-requests"},
	{"go-http-client", "go-http-client"},
	{"node-fetch", "node-fetch"},
	{"curl", "curl"},
	{"wget", "wget"},
}

// ParseToolFromUA extracts a canonical tool name from a User-Agent string.
// Returns the tool name and true if a known tool was identified, or ("", false)
// for browsers and unrecognizable UAs.
func ParseToolFromUA(ua string) (string, bool) {
	if ua == "" {
		return "", false
	}

	lower := strings.ToLower(ua)

	// Check known tool patterns
	for _, t := range knownTools {
		if strings.Contains(lower, t.substring) {
			return t.name, true
		}
	}

	// Fallback: first token before "/" if short and not a browser
	if strings.HasPrefix(lower, "mozilla") {
		return "", false
	}
	token, _, _ := strings.Cut(ua, "/")
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	// Only accept short, simple tokens (likely CLI tools)
	if len(token) > 30 || strings.ContainsAny(token, " ()") {
		return "", false
	}
	return strings.ToLower(token), true
}

// IdentityResolver auto-resolves agent identity from HTTP headers.
type IdentityResolver struct {
	authDB         *auth.DB
	counter        atomic.Int64
	httpIdentities sync.Map // IP:toolName:provider → *auth.Identity
}

// NewIdentityResolver creates a resolver backed by the given auth DB.
func NewIdentityResolver(authDB *auth.DB) *IdentityResolver {
	return &IdentityResolver{authDB: authDB}
}

// NextSuffix returns the next unique suffix for agent naming.
func (r *IdentityResolver) NextSuffix() int64 {
	return r.counter.Add(1)
}

// ResolveFromHeaders parses the User-Agent and registers an agent identity.
// Uses word-based naming: {provider}:{adjective}-{color}-{animal}
func (r *IdentityResolver) ResolveFromHeaders(ua, provider, seed string) *auth.Identity {
	_, ok := ParseToolFromUA(ua)
	if !ok {
		return nil
	}
	return r.registerWordAgent(provider, seed)
}

// ResolveForHTTP resolves identity for an HTTP request, caching by IP:toolName:provider.
// Different tools AND different providers from the same IP get distinct identities
// (e.g. Claude Code → Anthropic vs Claude Code → OpenAI).
func (r *IdentityResolver) ResolveForHTTP(remoteAddr, ua, provider string) *auth.Identity {
	// Strip port from remote address
	ip := remoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		ip = remoteAddr[:idx]
	}

	toolName, _ := ParseToolFromUA(ua)
	if toolName == "" {
		toolName = "_unknown"
	}

	// Cache key includes provider so same tool talking to different APIs
	// gets distinct identities.
	cacheKey := ip + ":" + toolName
	if provider != "" {
		cacheKey = ip + ":" + toolName + ":" + provider
	}

	if cached, ok := r.httpIdentities.Load(cacheKey); ok {
		return cached.(*auth.Identity)
	}

	identity := r.registerWordAgent(provider, cacheKey)
	if identity != nil {
		identity.Provider = provider
		if toolName != "_unknown" {
			identity.Tool = toolName
		}
	}

	r.httpIdentities.Store(cacheKey, identity)
	return identity
}

// RotateIdentity updates the httpIdentities cache so that subsequent
// ResolveForHTTP calls for this cache key return the new identity.
// Called by the tunnel tracker when a new session is detected after
// all previous tunnels closed.
func (r *IdentityResolver) RotateIdentity(cacheKey string, identity *auth.Identity) {
	if identity != nil {
		r.httpIdentities.Store(cacheKey, identity)
	}
}

// ResolveChild creates a child identity linked to the given parent.
// Uses derived naming: derived_{parentName}_{shortID}
func (r *IdentityResolver) ResolveChild(parent *auth.Identity, childNum int) *auth.Identity {
	if parent == nil {
		return nil
	}
	childName := DeriveChildName(parent.AgentName, parent.AgentID, childNum)
	identity, created, err := r.authDB.FindOrCreateSubagent(
		childName, parent.AgentID, "", parent.Depth+1,
	)
	if err != nil {
		qlog.Error("resolve child %q for parent %q: %v", childName, parent.AgentName, err)
		return nil
	}
	if created {
		qlog.Info("auto-registered child agent %q (id=%s, parent=%s)", childName, identity.AgentID, parent.AgentID)
	}
	identity.Source = "child_detect"
	identity.Provider = parent.Provider
	identity.Tool = parent.Tool
	return identity
}

// registerWordAgent creates or finds an agent with a word-based name.
// Name format: {provider}:{adjective}-{color}-{animal}
// On DB collision (UNIQUE constraint), retries with -2, -3 suffix.
func (r *IdentityResolver) registerWordAgent(provider, seed string) *auth.Identity {
	name := GenerateWordName(provider, seed)

	// Try the base name first, then with suffix on collision
	for attempt := 0; attempt < 5; attempt++ {
		candidateName := name
		if attempt > 0 {
			candidateName = fmt.Sprintf("%s-%d", name, attempt+1)
		}
		identity, created, err := r.authDB.FindOrCreateAgent(candidateName, "http-agent", "")
		if err != nil {
			qlog.Error("auto-resolve identity %q: %v", candidateName, err)
			return nil
		}
		if created {
			qlog.Info("auto-registered agent %q (id=%s)", candidateName, identity.AgentID)
		}
		identity.Source = "auto_resolve"
		return identity
	}
	return nil
}

// ResolveFromAgentID looks up an existing agent by its ID.
// Used to resolve identity from the X-Quint-Agent header.
func (r *IdentityResolver) ResolveFromAgentID(agentID string) *auth.Identity {
	if agentID == "" {
		return nil
	}
	agent, err := r.authDB.GetAgentByID(agentID)
	if err != nil {
		qlog.Debug("X-Quint-Agent lookup for %q: %v", agentID, err)
		return nil
	}
	if agent == nil {
		return nil
	}
	identity := auth.IdentityFromAgent(agent)
	identity.Source = "quint_agent_header"
	return identity
}

// CacheKey builds the IP:toolName cache key used for identity and provider caching.
func CacheKey(remoteAddr, ua string) string {
	ip := remoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		ip = remoteAddr[:idx]
	}
	toolName, _ := ParseToolFromUA(ua)
	if toolName == "" {
		toolName = "_unknown"
	}
	return ip + ":" + toolName
}
