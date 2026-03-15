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

const (
	// passthrough TTL — auto-learned domains expire after 1 hour.
	// If the CA gets trusted (e.g. user re-runs install), the domain
	// will be MITM'd again after the TTL expires.
	passthroughTTL = 1 * time.Hour
)

// tlsFailedDomains tracks domains where TLS handshake failed.
// Auto-fallback to blind tunnel on subsequent connections.
var (
	tlsFailedDomains sync.Map // domain (string) → time.Time (first failure)

	// tlsErrorCooldown prevents log spam — only log once per domain per minute
	tlsErrorLogged sync.Map // domain (string) → time.Time (last logged)
)

// MarkTLSFailed records that a domain's TLS handshake failed, so future
// connections to this domain will use blind tunnel instead of MITM.
// Logs the event at most once per minute per domain to prevent spam.
func MarkTLSFailed(domain string) {
	tlsFailedDomains.Store(domain, time.Now())

	// Rate-limit the log message
	if lastLog, ok := tlsErrorLogged.Load(domain); ok {
		if time.Since(lastLog.(time.Time)) < time.Minute {
			return // already logged recently
		}
	}
	tlsErrorLogged.Store(domain, time.Now())
	qlog.Info("auto-passthrough: %s (TLS failed, bypassing MITM for %v)", domain, passthroughTTL)
}

// isPassthroughDomain returns true if the domain should bypass MITM.
// Domains are auto-learned from TLS handshake failures with a TTL.
func isPassthroughDomain(domain string) bool {
	v, ok := tlsFailedDomains.Load(domain)
	if !ok {
		return false
	}
	failedAt := v.(time.Time)
	if time.Since(failedAt) > passthroughTTL {
		// TTL expired — try MITM again
		tlsFailedDomains.Delete(domain)
		tlsErrorLogged.Delete(domain)
		return false
	}
	return true
}

// llmProviderDomains are AI provider API endpoints that should be MITM'd
// for LLM conversation parsing (tool call extraction).
var llmProviderDomains = []string{
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
	"api.mistral.ai",
}

// isLLMProviderDomain returns true if the domain is an AI provider API.
func isLLMProviderDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, d := range llmProviderDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	if strings.HasPrefix(domain, "bedrock-runtime.") && strings.HasSuffix(domain, ".amazonaws.com") {
		return true
	}
	if strings.HasSuffix(domain, ".openai.azure.com") {
		return true
	}
	return false
}

// blindTunnel establishes a raw TCP tunnel without TLS interception.
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

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, upstream); done <- struct{}{} }()
	<-done
	<-done
}
