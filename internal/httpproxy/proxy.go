package httpproxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	credHeader   string
	credHeaderMu sync.RWMutex
	counter      atomic.Int64
	pending      sync.Map // requestKey → *pendingRequest
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

	rlCfg := opts.Policy
	rpm := 60
	burst := 10
	_ = rlCfg // rate_limit not in PolicyConfig struct yet, use defaults

	rateLimiter := ratelimit.New(rpm, burst)

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

	return &Proxy{
		opts:        opts,
		logger:      logger,
		riskEngine:  riskEngine,
		rateLimiter: rateLimiter,
		authDB:      authDB,
		auditDB:     auditDB,
		approvalDB:  approvalDB,
		behaviorDB:  behaviorDB,
	}, nil
}

// Start begins listening.
func (p *Proxy) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/approvals", p.handleApprovals)
	mux.HandleFunc("/approvals/", p.handleApprovalAction)
	mux.HandleFunc("/", p.handleRequest)

	p.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", p.opts.Port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
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

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	// CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Quint-Approval")

	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}

	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(405)
		w.Write([]byte(`{"error":"Method not allowed. Use POST."}`))
		return
	}

	// Identity resolution
	identity := &auth.Identity{SubjectID: "anonymous"}
	if p.authDB != nil {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": nil,
				"error": map[string]any{"code": -32600, "message": "Quint: missing or invalid Authorization header. Use: Bearer <api-key>"},
			})
			return
		}
		token := authHeader[7:]
		resolved, authResult := p.authDB.ResolveIdentity(token)
		if resolved == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": nil,
				"error": map[string]any{"code": -32600, "message": "Quint: invalid or expired API key"},
			})
			return
		}
		identity = resolved
		if authResult.RateLimitRpm != nil {
			p.rateLimiter.SetKeyLimit(identity.SubjectID, authResult.RateLimitRpm)
		}
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	bodyStr := string(body)
	headers := map[string]string{}
	for _, key := range []string{"authorization", "content-type", "accept"} {
		if v := r.Header.Get(key); v != "" {
			headers[key] = v
		}
	}

	// Check for approval header
	approvalID := r.Header.Get("X-Quint-Approval")

	// Process the request
	p.processRequest(w, bodyStr, headers, identity, approvalID)
}

func (p *Proxy) processRequest(w http.ResponseWriter, body string, headers map[string]string, identity *auth.Identity, approvalID string) {
	result := intercept.InspectRequest(body, p.opts.ServerName, p.opts.Policy)
	subjectID := identity.SubjectID

	logOpts := func(direction, verdict string, extra ...func(*audit.LogOpts)) audit.LogOpts {
		o := audit.LogOpts{
			ServerName: p.opts.ServerName, Direction: direction, Method: result.Method,
			MessageID: result.MessageID, ToolName: result.ToolName, ArgumentsJSON: result.ArgumentsJson,
			Verdict: verdict, AgentID: identity.AgentID, AgentName: identity.AgentName,
		}
		for _, f := range extra {
			f(&o)
		}
		return o
	}

	// Rate limiting
	rlResult := p.rateLimiter.Check(subjectID)
	if !rlResult.Allowed {
		p.logger.Log(logOpts("request", "rate_limited"))

		errBody := fmt.Sprintf(
			`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Quint: rate limit exceeded (%d/%d requests per minute)"}}`,
			rlResult.Used, rlResult.Limit,
		)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", fmt.Sprintf("%d", rlResult.RetryAfterSec))
		w.WriteHeader(429)
		w.Write([]byte(errBody))

		p.logger.Log(logOpts("response", "rate_limited", func(o *audit.LogOpts) { o.ResponseJSON = errBody }))
		qlog.Warn("rate-limited %s (%d/%d rpm)", subjectID, rlResult.Used, rlResult.Limit)
		return
	}

	// Policy deny
	if result.Verdict == intercept.VerdictDeny {
		p.logger.Log(logOpts("request", string(result.Verdict)))

		denyResp := intercept.BuildDenyResponse(result.RawID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(denyResp))

		p.logger.Log(logOpts("response", "deny", func(o *audit.LogOpts) { o.ResponseJSON = denyResp }))
		qlog.Info("denied %s on %s", result.ToolName, p.opts.ServerName)
		return
	}

	// Scope enforcement (agents only)
	if result.ToolName != "" {
		if requiredScope, ok := auth.EnforceScope(identity, result.ToolName); !ok {
			p.logger.Log(logOpts("request", "scope_denied"))

			denyResp := intercept.BuildScopeDenyResponse(result.RawID, result.ToolName, requiredScope)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			w.Write([]byte(denyResp))

			p.logger.Log(logOpts("response", "scope_denied", func(o *audit.LogOpts) { o.ResponseJSON = denyResp }))
			qlog.Info("scope-denied %s for agent %s (requires %s)", result.ToolName, identity.AgentName, requiredScope)
			return
		}
	}

	// Tool call — risk scoring
	if result.ToolName != "" {
		score := p.riskEngine.ScoreToolCall(result.ToolName, result.ArgumentsJson, subjectID)
		action := p.riskEngine.Evaluate(score.Value)

		verdict := string(result.Verdict)
		if action == "deny" {
			verdict = "deny"
		}
		p.logger.Log(logOpts("request", verdict, func(o *audit.LogOpts) {
			o.RiskScore = &score.Value
			o.RiskLevel = &score.Level
		}))

		if action == "deny" {
			denyResp := intercept.BuildDenyResponse(result.RawID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(denyResp))

			p.logger.Log(logOpts("response", "deny", func(o *audit.LogOpts) {
				o.ResponseJSON = denyResp
				o.RiskScore = &score.Value
				o.RiskLevel = &score.Level
			}))
			qlog.Warn("risk-denied %s (score=%d, level=%s)", result.ToolName, score.Value, score.Level)
			return
		}

		// Approval flow: flagged calls with approval_required
		if action == "flag" && p.opts.Policy.ApprovalRequired && p.approvalDB != nil {
			// Check if this request has an approved approval ID
			if approvalID != "" && p.approvalDB.IsApproved(approvalID) {
				qlog.Info("approved %s via approval %s", result.ToolName, approvalID)
				p.logger.Log(logOpts("request", "approved", func(o *audit.LogOpts) {
					o.RiskScore = &score.Value
					o.RiskLevel = &score.Level
				}))
			} else {
				// Create approval request and return 202
				req, err := p.approvalDB.Create(
					identity.AgentID, identity.AgentName,
					result.ToolName, result.ArgumentsJson, p.opts.ServerName,
					&score.Value, &score.Level,
					p.opts.Policy.GetApprovalTimeout(),
				)
				if err != nil {
					qlog.Error("failed to create approval request: %v", err)
				} else {
					pendingResp := intercept.BuildApprovalPendingResponse(result.RawID, req.ID)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(202)
					w.Write([]byte(pendingResp))

					p.logger.Log(logOpts("response", "approval_pending", func(o *audit.LogOpts) {
						o.ResponseJSON = pendingResp
						o.RiskScore = &score.Value
						o.RiskLevel = &score.Level
					}))
					qlog.Warn("approval-pending %s (approval_id=%s, score=%d)", result.ToolName, req.ID, score.Value)
					return
				}
			}
		} else if action == "flag" {
			qlog.Warn("high-risk %s (score=%d, level=%s)", result.ToolName, score.Value, score.Level)
		}

		if p.riskEngine.ShouldRevoke(subjectID) {
			qlog.Warn("repeated high-risk actions detected - consider revoking credentials for %s", subjectID)
		}
	} else {
		// Non-tool-call
		p.logger.Log(logOpts("request", string(result.Verdict)))
	}

	// Forward to remote
	p.forwardToRemote(w, body, headers)
}

func (p *Proxy) forwardToRemote(w http.ResponseWriter, body string, reqHeaders map[string]string) {
	fwdHeaders := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}
	if auth, ok := reqHeaders["authorization"]; ok {
		fwdHeaders["Authorization"] = auth
	} else {
		p.credHeaderMu.RLock()
		if p.credHeader != "" {
			fwdHeaders["Authorization"] = p.credHeader
		}
		p.credHeaderMu.RUnlock()
	}

	req, err := http.NewRequest("POST", p.opts.TargetURL, strings.NewReader(body))
	if err != nil {
		p.sendRemoteError(w, err)
		return
	}
	for k, v := range fwdHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		p.sendRemoteError(w, err)
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")

	if strings.Contains(contentType, "text/event-stream") {
		// SSE streaming
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(resp.StatusCode)

		flusher, canFlush := w.(http.Flusher)
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			w.Write([]byte(line + "\n"))
			if canFlush {
				flusher.Flush()
			}

			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimSpace(line[6:])
				if data != "" {
					p.logResponse(data)
				}
			}
		}
	} else {
		// Standard JSON response
		respBody, _ := io.ReadAll(resp.Body)
		respStr := string(respBody)
		p.logResponse(respStr)

		if contentType == "" {
			contentType = "application/json"
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	}
}

func (p *Proxy) logResponse(body string) {
	method, msgID, respJSON := intercept.InspectResponse(body)
	p.logger.Log(audit.LogOpts{
		ServerName:   p.opts.ServerName,
		Direction:    "response",
		Method:       method,
		MessageID:    msgID,
		ResponseJSON: respJSON,
		Verdict:      "passthrough",
	})
}

func (p *Proxy) sendRemoteError(w http.ResponseWriter, err error) {
	errBody := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Quint: failed to reach remote server: %s"}}`,
		err.Error(),
	)
	p.logResponse(errBody)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(502)
	w.Write([]byte(errBody))
}

// requireOperatorAuth checks the bearer token for approval management endpoints.
// Only non-agent API keys are accepted (agents cannot approve their own requests).
func (p *Proxy) requireOperatorAuth(w http.ResponseWriter, r *http.Request) bool {
	if p.authDB == nil {
		return true // no auth configured, allow
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "Authorization required for approval management"})
		return false
	}
	identity, _ := p.authDB.ResolveIdentity(authHeader[7:])
	if identity == nil {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired API key"})
		return false
	}
	if identity.IsAgent {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]string{"error": "agents cannot manage approvals"})
		return false
	}
	return true
}

// handleApprovals lists pending approval requests (GET /approvals).
func (p *Proxy) handleApprovals(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if p.approvalDB == nil {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "approval flow not enabled"})
		return
	}

	if r.Method != "GET" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]string{"error": "use GET"})
		return
	}

	if !p.requireOperatorAuth(w, r) {
		return
	}

	pending, err := p.approvalDB.ListPending()
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{"pending": pending})
}

// handleApprovalAction handles POST /approvals/{id}/approve or /approvals/{id}/deny.
func (p *Proxy) handleApprovalAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if p.approvalDB == nil {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "approval flow not enabled"})
		return
	}

	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]string{"error": "use POST"})
		return
	}

	if !p.requireOperatorAuth(w, r) {
		return
	}

	// Parse path: /approvals/{id}/approve or /approvals/{id}/deny
	path := strings.TrimPrefix(r.URL.Path, "/approvals/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "expected /approvals/{id}/approve or /approvals/{id}/deny"})
		return
	}

	id := parts[0]
	action := parts[1]

	approved := action == "approve"
	if action != "approve" && action != "deny" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "action must be 'approve' or 'deny'"})
		return
	}

	// Sign the decision
	decisionData := fmt.Sprintf("%s:%s:%s", id, action, time.Now().UTC().Format(time.RFC3339))
	signature := ""
	if p.logger != nil {
		// Use the proxy's signing key for the decision
		sig, err := crypto.SignData(decisionData, p.getPrivateKey())
		if err == nil {
			signature = sig
		}
	}

	if err := p.approvalDB.Decide(id, approved, "operator", signature); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "decision": action, "approval_id": id})
}

// getPrivateKey extracts the private key from the logger for signing approval decisions.
func (p *Proxy) getPrivateKey() string {
	dataDir := intercept.ResolveDataDir(p.opts.Policy.DataDir)
	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(dataDir, passphrase)
	if err != nil {
		return ""
	}
	return kp.PrivateKey
}
