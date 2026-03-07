package forwardproxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

// passthroughDomains are AI provider APIs that should NOT be MITM'd.
// These get a blind TCP tunnel — the proxy can see the domain (from CONNECT)
// but cannot read or modify the encrypted traffic.
var passthroughDomains = []string{
	// Anthropic
	"api.anthropic.com",
	"anthropic.com",
	// OpenAI
	"api.openai.com",
	"openai.com",
	// Google
	"generativelanguage.googleapis.com",
	// GitHub Copilot
	"api.githubcopilot.com",
	"copilot-proxy.githubusercontent.com",
	// AWS Bedrock (Claude via API Billing)
	"bedrock-runtime.us-east-1.amazonaws.com",
	"bedrock-runtime.us-west-2.amazonaws.com",
	"bedrock-runtime.eu-west-1.amazonaws.com",
	"bedrock.us-east-1.amazonaws.com",
	"bedrock.us-west-2.amazonaws.com",
	// Cursor
	"api.cursor.com",
	"api2.cursor.sh",
	// Amazon CodeWhisperer
	"codewhisperer.amazonaws.com",
	// npm registry (not AI but needed for tooling)
	"registry.npmjs.org",
}

// isPassthroughDomain returns true if the domain should bypass MITM.
func isPassthroughDomain(domain string) bool {
	for _, d := range passthroughDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	// Catch all AWS Bedrock regions
	if strings.Contains(domain, "bedrock") && strings.HasSuffix(domain, ".amazonaws.com") {
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
