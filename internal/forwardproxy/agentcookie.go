package forwardproxy

import (
	"net/http"
	"sync"

	"github.com/Quint-Security/quint-proxy/internal/auth"
)

const quintCookieName = "_quint_agent"

// agentCookieStore maps agent IDs to their resolved identities.
// Used to recognize returning agents via Set-Cookie / Cookie in MITM tunnels.
type agentCookieStore struct {
	mu      sync.RWMutex
	agents  map[string]*auth.Identity // agentID → identity
}

func newAgentCookieStore() *agentCookieStore {
	return &agentCookieStore{
		agents: make(map[string]*auth.Identity),
	}
}

// Register stores an identity so it can be looked up by agent ID from a cookie.
func (s *agentCookieStore) Register(identity *auth.Identity) {
	if identity == nil || identity.AgentID == "" {
		return
	}
	s.mu.Lock()
	s.agents[identity.AgentID] = identity
	s.mu.Unlock()
}

// Lookup returns the identity for the given agent ID, or nil.
func (s *agentCookieStore) Lookup(agentID string) *auth.Identity {
	if agentID == "" {
		return nil
	}
	s.mu.RLock()
	id := s.agents[agentID]
	s.mu.RUnlock()
	return id
}

// extractAgentCookie reads the _quint_agent cookie value from a request.
func extractAgentCookie(req *http.Request) string {
	c, err := req.Cookie(quintCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

// injectAgentCookie adds a Set-Cookie header to a response so the client
// will send the agent ID back on subsequent requests within the same MITM tunnel.
func injectAgentCookie(resp *http.Response, agentID string) {
	if agentID == "" || resp == nil {
		return
	}
	cookie := &http.Cookie{
		Name:     quintCookieName,
		Value:    agentID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}
	resp.Header.Add("Set-Cookie", cookie.String())
}

// stripQuintCookie removes the _quint_agent cookie from a request before
// forwarding to the upstream server. Other cookies are preserved.
func stripQuintCookie(req *http.Request) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}

	// Remove all cookie headers and re-add only non-quint cookies
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != quintCookieName {
			req.AddCookie(c)
		}
	}
}
