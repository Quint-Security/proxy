package forwardproxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// passthroughDomains are non-AI domains that should NOT be MITM'd.
// These get a blind TCP tunnel — the proxy can see the domain (from CONNECT)
// but cannot read or modify the encrypted traffic.
// AI provider domains are intentionally NOT listed here — they are MITM'd
// so we can parse LLM tool calls from request bodies.
var passthroughDomains = []string{
	// npm registry (not AI, needed for tooling)
	"registry.npmjs.org",
	// GitHub Copilot binary streaming (not chat API)
	"copilot-proxy.githubusercontent.com",
	// Railway CLI internal traffic (doesn't trust Quint CA)
	"backboard.railway.com",
}

// isPassthroughDomain returns true if the domain should bypass MITM.
func isPassthroughDomain(domain string) bool {
	for _, d := range passthroughDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

// llmProviderDomains are AI provider API endpoints that should be MITM'd
// for LLM conversation parsing (tool call extraction), but should NOT be
// scored/blocked as regular HTTP traffic. Instead, parsed tool calls are
// emitted via the OnToolCall callback.
var llmProviderDomains = []string{
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
	"api.mistral.ai",
}

// isLLMProviderDomain returns true if the domain is an AI provider API
// endpoint that should be parsed for LLM tool calls instead of being
// treated as regular HTTP traffic.
func isLLMProviderDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, d := range llmProviderDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	// Catch all AWS Bedrock runtime regions (bedrock-runtime.*.amazonaws.com)
	if strings.HasPrefix(domain, "bedrock-runtime.") && strings.HasSuffix(domain, ".amazonaws.com") {
		return true
	}
	return false
}

// blindTunnel establishes a raw TCP tunnel without TLS interception.
// The client and server negotiate TLS directly — the proxy just copies bytes.
func (p *Proxy) blindTunnel(w http.ResponseWriter, r *http.Request, host string) {
	upstream, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		qlog.Error("passthrough dial %s: %v", host, err)
		http.Error(w, "upstream connect failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		qlog.Error("passthrough hijack: %v", err)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	qlog.Debug("passthrough tunnel: %s", host)

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, upstream); done <- struct{}{} }()
	<-done
}
