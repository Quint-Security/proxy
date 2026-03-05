package forwardproxy

import (
	"net/http"
	"testing"

	"github.com/Quint-Security/quint-proxy/internal/auth"
)

func TestAgentCookieStore_RegisterAndLookup(t *testing.T) {
	store := newAgentCookieStore()

	identity := &auth.Identity{
		AgentID:   "agent-abc",
		AgentName: "claude-code-1",
		SubjectID: "subject-abc",
	}

	// Lookup before register → nil
	if got := store.Lookup("agent-abc"); got != nil {
		t.Errorf("expected nil before register, got %+v", got)
	}

	store.Register(identity)

	// Lookup after register → found
	got := store.Lookup("agent-abc")
	if got == nil {
		t.Fatal("expected non-nil identity after register")
	}
	if got.AgentID != "agent-abc" {
		t.Errorf("expected AgentID %q, got %q", "agent-abc", got.AgentID)
	}
	if got.AgentName != "claude-code-1" {
		t.Errorf("expected AgentName %q, got %q", "claude-code-1", got.AgentName)
	}

	// Unknown ID → nil
	if got := store.Lookup("unknown"); got != nil {
		t.Errorf("expected nil for unknown, got %+v", got)
	}
}

func TestAgentCookieStore_NilIdentity(t *testing.T) {
	store := newAgentCookieStore()

	// Register nil should not panic
	store.Register(nil)

	// Register identity with empty AgentID should not store
	store.Register(&auth.Identity{AgentID: ""})
	if got := store.Lookup(""); got != nil {
		t.Errorf("expected nil for empty agentID, got %+v", got)
	}
}

func TestExtractAgentCookie(t *testing.T) {
	tests := []struct {
		name    string
		cookies []*http.Cookie
		want    string
	}{
		{
			name:    "no cookies",
			cookies: nil,
			want:    "",
		},
		{
			name:    "quint cookie present",
			cookies: []*http.Cookie{{Name: "_quint_agent", Value: "agent-123"}},
			want:    "agent-123",
		},
		{
			name: "quint cookie among others",
			cookies: []*http.Cookie{
				{Name: "session_id", Value: "sess-xyz"},
				{Name: "_quint_agent", Value: "agent-456"},
				{Name: "theme", Value: "dark"},
			},
			want: "agent-456",
		},
		{
			name:    "empty value",
			cookies: []*http.Cookie{{Name: "_quint_agent", Value: ""}},
			want:    "",
		},
		{
			name:    "different cookie name",
			cookies: []*http.Cookie{{Name: "other_cookie", Value: "agent-789"}},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com", nil)
			for _, c := range tt.cookies {
				req.AddCookie(c)
			}

			got := extractAgentCookie(req)
			if got != tt.want {
				t.Errorf("extractAgentCookie() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInjectAgentCookie(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}

	injectAgentCookie(resp, "agent-test-123")

	setCookieHeaders := resp.Header.Values("Set-Cookie")
	if len(setCookieHeaders) == 0 {
		t.Fatal("expected Set-Cookie header")
	}

	// Parse the cookie to verify format
	found := false
	for _, h := range setCookieHeaders {
		// The header should contain our cookie name and value
		if contains(h, "_quint_agent=agent-test-123") {
			found = true
			// Verify HttpOnly
			if !contains(h, "HttpOnly") {
				t.Error("expected HttpOnly flag in cookie")
			}
			// Verify Secure
			if !contains(h, "Secure") {
				t.Error("expected Secure flag in cookie")
			}
		}
	}
	if !found {
		t.Errorf("expected _quint_agent cookie, got headers: %v", setCookieHeaders)
	}
}

func TestInjectAgentCookie_EmptyID(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}

	injectAgentCookie(resp, "")

	if len(resp.Header.Values("Set-Cookie")) > 0 {
		t.Error("should not inject cookie for empty agent ID")
	}
}

func TestInjectAgentCookie_NilResponse(t *testing.T) {
	// Should not panic
	injectAgentCookie(nil, "agent-123")
}

func TestStripQuintCookie(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "sess-abc"})
	req.AddCookie(&http.Cookie{Name: "_quint_agent", Value: "agent-123"})
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})

	stripQuintCookie(req)

	// _quint_agent should be gone
	if _, err := req.Cookie("_quint_agent"); err == nil {
		t.Error("expected _quint_agent cookie to be stripped")
	}

	// Other cookies should remain
	if c, err := req.Cookie("session_id"); err != nil || c.Value != "sess-abc" {
		t.Errorf("expected session_id cookie to be preserved, got err=%v", err)
	}
	if c, err := req.Cookie("theme"); err != nil || c.Value != "dark" {
		t.Errorf("expected theme cookie to be preserved, got err=%v", err)
	}
}

func TestStripQuintCookie_NoCookies(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	// Should not panic
	stripQuintCookie(req)
}

func TestStripQuintCookie_OnlyQuintCookie(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.AddCookie(&http.Cookie{Name: "_quint_agent", Value: "agent-123"})

	stripQuintCookie(req)

	if _, err := req.Cookie("_quint_agent"); err == nil {
		t.Error("expected _quint_agent cookie to be stripped")
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
