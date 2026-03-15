package main

import (
	"strings"
	"testing"
)

func TestGenerateEnvSh_WithAgents(t *testing.T) {
	agents := []knownAgent{
		{"claude", "Claude Code"},
		{"aider", "Aider"},
	}

	content := generateEnvSh("/home/user/.quint/ca/bundle.pem", "/home/user/.quint/ca/cert.crt", 9090, agents)

	// CA trust vars
	if !strings.Contains(content, "export SSL_CERT_FILE=/home/user/.quint/ca/bundle.pem") {
		t.Error("missing SSL_CERT_FILE export")
	}
	if !strings.Contains(content, "export NODE_EXTRA_CA_CERTS=/home/user/.quint/ca/cert.crt") {
		t.Error("missing NODE_EXTRA_CA_CERTS export")
	}
	if !strings.Contains(content, "export NODE_USE_SYSTEM_CA=1") {
		t.Error("missing NODE_USE_SYSTEM_CA export")
	}

	// _quint_proxy function
	if !strings.Contains(content, "_quint_proxy()") {
		t.Error("missing _quint_proxy function")
	}
	if !strings.Contains(content, "nc -z 127.0.0.1 9090") {
		t.Error("missing nc liveness check for port 9090")
	}

	// Agent wrappers
	if !strings.Contains(content, `claude() { _quint_proxy command claude "$@"; }`) {
		t.Error("missing claude wrapper function")
	}
	if !strings.Contains(content, `aider() { _quint_proxy command aider "$@"; }`) {
		t.Error("missing aider wrapper function")
	}

	// Should NOT contain agents we didn't pass
	if strings.Contains(content, "codex()") {
		t.Error("unexpected codex wrapper (not in agent list)")
	}
}

func TestGenerateEnvSh_NoAgents(t *testing.T) {
	content := generateEnvSh("/bundle.pem", "/cert.crt", 9090, nil)

	// CA trust should still be present
	if !strings.Contains(content, "export SSL_CERT_FILE=/bundle.pem") {
		t.Error("missing SSL_CERT_FILE export")
	}

	// Should NOT contain proxy wrapper
	if strings.Contains(content, "_quint_proxy()") {
		t.Error("unexpected _quint_proxy function with no agents")
	}

	// Should have helpful message
	if !strings.Contains(content, "No AI agent CLIs detected") {
		t.Error("missing no-agents message")
	}
}

func TestGenerateEnvSh_CustomPort(t *testing.T) {
	agents := []knownAgent{{"claude", "Claude Code"}}
	content := generateEnvSh("/b.pem", "/c.crt", 8888, agents)

	if !strings.Contains(content, "nc -z 127.0.0.1 8888") {
		t.Error("wrong port in nc check")
	}
	if !strings.Contains(content, "http://127.0.0.1:8888") {
		t.Error("wrong port in proxy URL")
	}
}

func TestGenerateEnvSh_POSIXCompatible(t *testing.T) {
	agents := []knownAgent{{"claude", "Claude Code"}}
	content := generateEnvSh("/b.pem", "/c.crt", 9090, agents)

	// Must not use bash-only syntax
	bashOnlyPatterns := []string{
		"[[", "]]",       // bash test brackets
		"declare ",       // bash declare
		"local ",         // bash local (not POSIX in all shells)
		"function ",      // bash function keyword
		"$((",            // bash arithmetic
	}
	for _, pat := range bashOnlyPatterns {
		if strings.Contains(content, pat) {
			t.Errorf("contains bash-only syntax: %q", pat)
		}
	}
}
