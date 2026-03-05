package forwardproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Quint-Security/quint-proxy/internal/auth"
)

func TestParseToolFromUA(t *testing.T) {
	tests := []struct {
		ua       string
		wantName string
		wantOK   bool
	}{
		// Known agents
		{"claude-code/1.2.3 node/20.11.0", "claude-code", true},
		{"Claude-Code/1.0.0", "claude-code", true},
		{"cursor/0.43.6", "cursor", true},
		{"aider/0.51.0 python/3.12", "aider", true},
		{"python-httpx/0.27.0", "python-httpx", true},
		{"python-requests/2.31.0", "python-requests", true},
		{"Go-http-client/2.0", "go-http-client", true},
		{"node-fetch/1.0", "node-fetch", true},
		{"curl/8.4.0", "curl", true},
		{"wget/1.21", "wget", true},
		{"Windsurf/1.0", "windsurf", true},
		{"cline/0.1.0", "cline", true},
		{"copilot/1.0", "copilot", true},
		{"continue/0.8", "continue", true},
		{"zed/0.1", "zed", true},

		// Browser UAs — should not match
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36", "", false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0", "", false},

		// Empty
		{"", "", false},

		// Unknown short token — fallback extracts first token
		{"my-tool/1.0", "my-tool", true},
		{"httpclient/2.0", "httpclient", true},

		// Token too long or contains spaces
		{"Some Very Long Agent Name That Should Not Match/1.0", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.ua, func(t *testing.T) {
			name, ok := ParseToolFromUA(tt.ua)
			if ok != tt.wantOK {
				t.Errorf("ParseToolFromUA(%q) ok = %v, want %v", tt.ua, ok, tt.wantOK)
			}
			if name != tt.wantName {
				t.Errorf("ParseToolFromUA(%q) name = %q, want %q", tt.ua, name, tt.wantName)
			}
		})
	}
}

func setupTestAuthDB(t *testing.T) *auth.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := auth.OpenDB(filepath.Join(dir, "test-data"))
	if err != nil {
		t.Fatalf("open auth db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestIdentityResolver_NextSuffix(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	s1 := r.NextSuffix()
	s2 := r.NextSuffix()
	s3 := r.NextSuffix()

	if s1 != 1 || s2 != 2 || s3 != 3 {
		t.Errorf("expected suffixes 1,2,3 got %d,%d,%d", s1, s2, s3)
	}
}

func TestIdentityResolver_ResolveFromHeaders(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	// Known UA — word-based name
	id := r.ResolveFromHeaders("claude-code/1.2.3 node/20", "anthropic", "test-seed-1")
	if id == nil {
		t.Fatal("expected non-nil identity for claude-code UA")
	}
	if !strings.HasPrefix(id.AgentName, "anthropic:") {
		t.Errorf("expected name prefix %q, got %q", "anthropic:", id.AgentName)
	}
	if id.Source != "auto_resolve" {
		t.Errorf("expected source %q, got %q", "auto_resolve", id.Source)
	}

	// Unknown UA
	id = r.ResolveFromHeaders("Mozilla/5.0 (Macintosh)", "", "test-seed-2")
	if id != nil {
		t.Errorf("expected nil identity for Mozilla UA, got %+v", id)
	}

	// Empty UA
	id = r.ResolveFromHeaders("", "", "test-seed-3")
	if id != nil {
		t.Errorf("expected nil identity for empty UA, got %+v", id)
	}
}

func TestIdentityResolver_ResolveForHTTP_CachesByIPAndTool(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	// Same IP + same tool (different port) → cached identity
	id1 := r.ResolveForHTTP("192.168.1.1:54321", "claude-code/1.0", "")
	id2 := r.ResolveForHTTP("192.168.1.1:54322", "claude-code/1.0", "")

	if id1 == nil || id2 == nil {
		t.Fatal("expected non-nil identities")
	}
	if id1.AgentName != id2.AgentName {
		t.Errorf("expected same agent for same IP+tool, got %q and %q", id1.AgentName, id2.AgentName)
	}

	// Different IP should get a different identity
	id3 := r.ResolveForHTTP("192.168.1.2:54321", "claude-code/1.0", "")
	if id3 == nil {
		t.Fatal("expected non-nil identity for different IP")
	}
	if id3.AgentName == id1.AgentName {
		t.Errorf("expected different agent for different IP, got same: %q", id3.AgentName)
	}
}

func TestResolveForHTTP_DifferentToolsSameIP(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	// Claude Code and Cursor from same IP → distinct identities
	idClaude := r.ResolveForHTTP("127.0.0.1:50001", "claude-code/1.2.3 node/20", "")
	idCursor := r.ResolveForHTTP("127.0.0.1:50002", "cursor/0.43.6", "")

	if idClaude == nil || idCursor == nil {
		t.Fatal("expected non-nil identities")
	}
	if idClaude.AgentID == idCursor.AgentID {
		t.Error("different tools from same IP should get distinct agent IDs")
	}
	if idClaude.AgentName == idCursor.AgentName {
		t.Errorf("different tools should have different names: claude=%q cursor=%q",
			idClaude.AgentName, idCursor.AgentName)
	}
}

func TestResolveForHTTP_DifferentProvidersSameIPAndTool(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	// Same tool from same IP but different providers → distinct identities
	idAnth := r.ResolveForHTTP("127.0.0.1:50001", "claude-code/1.2.3", "anthropic")
	idOAI := r.ResolveForHTTP("127.0.0.1:50002", "claude-code/1.2.3", "openai")

	if idAnth == nil || idOAI == nil {
		t.Fatal("expected non-nil identities")
	}
	if idAnth.AgentID == idOAI.AgentID {
		t.Error("different providers from same IP+tool should get distinct agent IDs")
	}
	if !strings.HasPrefix(idAnth.AgentName, "anthropic:") {
		t.Errorf("expected anthropic: prefix, got %q", idAnth.AgentName)
	}
	if !strings.HasPrefix(idOAI.AgentName, "openai:") {
		t.Errorf("expected openai: prefix, got %q", idOAI.AgentName)
	}
}

func TestResolveChild_Naming(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	parent := r.ResolveForHTTP("10.0.0.1:50001", "claude-code/1.2.3", "")
	if parent == nil {
		t.Fatal("expected non-nil parent")
	}

	child1 := r.ResolveChild(parent, 1)
	child2 := r.ResolveChild(parent, 2)

	if child1 == nil || child2 == nil {
		t.Fatal("expected non-nil children")
	}

	// Children should use derived naming: derived_{parentName}_{shortID}
	if !strings.HasPrefix(child1.AgentName, "derived_") {
		t.Errorf("child1 name should start with 'derived_', got %q", child1.AgentName)
	}
	if !strings.HasPrefix(child2.AgentName, "derived_") {
		t.Errorf("child2 name should start with 'derived_', got %q", child2.AgentName)
	}
	if !strings.Contains(child1.AgentName, parent.AgentName) {
		t.Errorf("child1 name should contain parent name %q, got %q", parent.AgentName, child1.AgentName)
	}
	if child1.AgentName == child2.AgentName {
		t.Errorf("child1 and child2 should have different names, both got %q", child1.AgentName)
	}
	if child1.Source != "child_detect" {
		t.Errorf("child1 source = %q, want %q", child1.Source, "child_detect")
	}
	if child1.AgentID == parent.AgentID {
		t.Error("child should have a different agent ID than parent")
	}
}

func TestResolveChild_NilParent(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	child := r.ResolveChild(nil, 1)
	if child != nil {
		t.Errorf("expected nil child for nil parent, got %+v", child)
	}
}

func TestIdentityResolver_Fallback(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	// Mozilla UA → no UA match → fallback to word-based agent name
	id := r.ResolveForHTTP("10.0.0.1:1234", "Mozilla/5.0 (X11; Linux)", "")
	if id == nil {
		t.Fatal("expected non-nil fallback identity")
	}
	// With no provider, should get "agent:" prefix
	if !strings.HasPrefix(id.AgentName, "agent:") {
		t.Errorf("expected fallback name with 'agent:' prefix, got %q", id.AgentName)
	}
}

func TestIdentityResolver_UniqueNames(t *testing.T) {
	db := setupTestAuthDB(t)
	r := NewIdentityResolver(db)

	// Each different IP gets a unique suffix
	names := make(map[string]bool)
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("10.0.0.%d:8080", i+1)
		id := r.ResolveForHTTP(ip, "curl/8.0", "")
		if id == nil {
			t.Fatalf("expected non-nil identity for ip %s", ip)
		}
		if names[id.AgentName] {
			t.Errorf("duplicate agent name: %s", id.AgentName)
		}
		names[id.AgentName] = true
	}
}

// Ensure the test data dir doesn't leak.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
