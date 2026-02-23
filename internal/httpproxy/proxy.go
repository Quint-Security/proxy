package httpproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/approval"
	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/ratelimit"
	"github.com/Quint-Security/quint-proxy/internal/risk"
)

// Options configures the HTTP proxy.
type Options struct {
	ServerName  string
	Port        int
	TargetURL   string
	Policy      intercept.PolicyConfig
	RequireAuth bool
}

// Proxy is the HTTP MCP proxy server.
type Proxy struct {
	opts         Options
	server       *http.Server
	logger       *audit.Logger
	riskEngine   *risk.Engine
	rateLimiter  *ratelimit.Limiter
	authDB       *auth.DB
	auditDB      *audit.DB
	approvalDB   *approval.DB
	behaviorDB   *risk.BehaviorDB
	reverseProxy *httputil.ReverseProxy
	targetURL    *url.URL
	credHeader   string
	credHeaderMu sync.RWMutex
	counter      atomic.Int64
	pending      sync.Map
}

type pendingRequest struct {
	w         http.ResponseWriter
	body      string
	headers   map[string]string
	subjectID string
	done      chan struct{}
}

// New creates a new HTTP proxy.
func New(opts Options) (*Proxy, error) {
	dataDir := intercept.ResolveDataDir(opts.Policy.DataDir)

	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	auditDB, err := audit.OpenDB(dataDir)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

	policyBytes, _ := json.Marshal(opts.Policy)
	var policyMap map[string]any
	json.Unmarshal(policyBytes, &policyMap)

	logger := audit.NewLogger(auditDB, kp.PrivateKey, kp.PublicKey, policyMap)

	behaviorDB, err := risk.OpenBehaviorDB(dataDir)
	if err != nil {
		qlog.Error("failed to open behavior db: %v", err)
	}

	riskEngine := risk.NewEngine(&risk.EngineOpts{BehaviorDB: behaviorDB})
	rateLimiter := ratelimit.New(opts.Policy.GetRateLimitRpm(), opts.Policy.GetRateLimitBurst())

	var authDB *auth.DB
	if opts.RequireAuth {
		authDB, err = auth.OpenDB(dataDir)
		if err != nil {
			return nil, fmt.Errorf("open auth db: %w", err)
		}
	}

	var approvalDB *approval.DB
	if opts.Policy.ApprovalRequired {
		approvalDB, err = approval.OpenDB(dataDir)
		if err != nil {
			return nil, fmt.Errorf("open approval db: %w", err)
		}
	}

	// Parse target URL
	target, err := url.Parse(opts.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}

	p := &Proxy{
		opts:        opts,
		logger:      logger,
		riskEngine:  riskEngine,
		rateLimiter: rateLimiter,
		authDB:      authDB,
		auditDB:     auditDB,
		approvalDB:  approvalDB,
		behaviorDB:  behaviorDB,
		targetURL:   target,
	}

	// Build reverse proxy
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			// Preserve the original path from the target URL + any extra path
			origPath := req.URL.Path
			req.URL.Path = singleJoiningSlash(target.Path, origPath)
			if target.RawQuery == "" || req.URL.RawQuery == "" {
				req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
			} else {
				req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
			}
			req.Host = target.Host
		},
		FlushInterval: -1, // stream SSE immediately
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			qlog.Error("proxy error for %s %s: %v", r.Method, r.URL.Path, err)
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(fmt.Sprintf(`{"error":"proxy error: %s"}`, err.Error())))
		},
	}
	p.reverseProxy = rp

	return p, nil
}

// Start begins listening.
func (p *Proxy) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleAll)

	p.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", p.opts.Port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // no timeout for SSE streams
	}

	qlog.Info("HTTP proxy listening on http://localhost:%d → %s", p.opts.Port, p.opts.TargetURL)
	return p.server.ListenAndServe()
}

// Stop shuts down the server.
func (p *Proxy) Stop() {
	if p.server != nil {
		p.server.Close()
	}
}

// Close cleans up all resources.
func (p *Proxy) Close() {
	p.Stop()
	if p.auditDB != nil {
		p.auditDB.Close()
	}
	if p.behaviorDB != nil {
		p.behaviorDB.Close()
	}
	if p.authDB != nil {
		p.authDB.Close()
	}
	if p.approvalDB != nil {
		p.approvalDB.Close()
	}
}

// SetCredentialHeader sets the Authorization header to inject into outgoing requests.
func (p *Proxy) SetCredentialHeader(header string) {
	p.credHeaderMu.Lock()
	p.credHeader = header
	p.credHeaderMu.Unlock()
}

// handleAll is the single entry point for all requests.
func (p *Proxy) handleAll(w http.ResponseWriter, r *http.Request) {
	// For POST requests with JSON-RPC bodies, inspect and audit
	if r.Method == "POST" && isJSONContent(r) {
		p.handlePostWithInspection(w, r)
		return
	}

	// Everything else: forward transparently via reverse proxy
	p.reverseProxy.ServeHTTP(w, r)
}

func isJSONContent(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.Contains(ct, "application/json") || ct == ""
}

func (p *Proxy) handlePostWithInspection(w http.ResponseWriter, r *http.Request) {
	// Read body for inspection
	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.reverseProxy.ServeHTTP(w, r)
		return
	}
	r.Body.Close()

	bodyStr := string(body)

	// Check if this is a JSON-RPC tool call we should inspect
	result := intercept.InspectRequest(bodyStr, p.opts.ServerName, p.opts.Policy)

	// Identity resolution (only when --auth is enabled)
	identity := &auth.Identity{SubjectID: "anonymous"}
	if p.authDB != nil {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := authHeader[7:]
			resolved, authResult := p.authDB.ResolveIdentity(token)
			if resolved != nil {
				identity = resolved
				if authResult.RateLimitRpm != nil {
					p.rateLimiter.SetKeyLimit(identity.SubjectID, authResult.RateLimitRpm)
				}
			}
		}
	}

	// Audit the request
	p.logger.Log(audit.LogOpts{
		ServerName:    p.opts.ServerName,
		Direction:     "request",
		Method:        result.Method,
		MessageID:     result.MessageID,
		ToolName:      result.ToolName,
		ArgumentsJSON: result.ArgumentsJson,
		Verdict:       string(result.Verdict),
		AgentID:       identity.AgentID,
		AgentName:     identity.AgentName,
	})

	// Policy deny
	if result.Verdict == intercept.VerdictDeny {
		denyResp := intercept.BuildDenyResponse(result.RawID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(denyResp))
		qlog.Info("denied %s on %s", result.ToolName, p.opts.ServerName)
		return
	}

	// Scope enforcement (agents only)
	if result.ToolName != "" && identity.IsAgent {
		if requiredScope, ok := auth.EnforceScope(identity, result.ToolName); !ok {
			denyResp := intercept.BuildScopeDenyResponse(result.RawID, result.ToolName, requiredScope)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			w.Write([]byte(denyResp))
			qlog.Info("scope-denied %s for agent %s (requires %s)", result.ToolName, identity.AgentName, requiredScope)
			return
		}
	}

	// Risk scoring for tool calls
	if result.ToolName != "" {
		score := p.riskEngine.ScoreToolCall(result.ToolName, result.ArgumentsJson, identity.SubjectID)
		action := p.riskEngine.Evaluate(score.Value)

		if action == "deny" {
			denyResp := intercept.BuildDenyResponse(result.RawID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(denyResp))
			qlog.Warn("risk-denied %s (score=%d, level=%s)", result.ToolName, score.Value, score.Level)
			return
		}
		if action == "flag" {
			qlog.Warn("high-risk %s (score=%d, level=%s)", result.ToolName, score.Value, score.Level)
		}
	}

	// Restore body and forward via reverse proxy
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	p.reverseProxy.ServeHTTP(w, r)
}

// getPrivateKey loads the private key for signing.
func (p *Proxy) getPrivateKey() string {
	dataDir := intercept.ResolveDataDir(p.opts.Policy.DataDir)
	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		return ""
	}
	return kp.PrivateKey
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash && b != "":
		return a + "/" + b
	}
	return a + b
}
