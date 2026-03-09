package forwardproxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// tlsFailedDomains tracks domains where TLS handshake failed (client doesn't
// trust our CA). These auto-fallback to blind tunnel on subsequent connections.
// No hardcoded passthrough list needed — domains are learned at runtime.
var (
	tlsFailedDomains sync.Map // domain (string) → time.Time (first failure)
)

// MarkTLSFailed records that a domain's TLS handshake failed, so future
// connections to this domain will use blind tunnel instead of MITM.
func MarkTLSFailed(domain string) {
	tlsFailedDomains.Store(domain, time.Now())
	qlog.Info("auto-passthrough: %s (TLS handshake failed, will bypass MITM)", domain)
}

// isPassthroughDomain returns true if the domain should bypass MITM.
// Domains are auto-learned from TLS handshake failures — no hardcoded list.
func isPassthroughDomain(domain string) bool {
	_, failed := tlsFailedDomains.Load(domain)
	return failed
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
