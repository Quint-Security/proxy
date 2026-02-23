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

	return &Proxy{
		opts:        opts,
		logger:      logger,
		riskEngine:  riskEngine,
		rateLimiter: rateLimiter,
		authDB:      authDB,
		auditDB:     auditDB,
		behaviorDB:  behaviorDB,
	}, nil
}

// Start begins listening.
func (p *Proxy) Start() error {
	mux := http.NewServeMux()
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
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

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

	// Auth check
	subjectID := "anonymous"
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
		result := p.authDB.AuthenticateBearer(token)
		if result == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": nil,
				"error": map[string]any{"code": -32600, "message": "Quint: invalid or expired API key"},
			})
			return
		}
		subjectID = result.SubjectID
		if result.RateLimitRpm != nil {
			p.rateLimiter.SetKeyLimit(subjectID, result.RateLimitRpm)
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

	// Process the request
	p.processRequest(w, bodyStr, headers, subjectID)
}

func (p *Proxy) processRequest(w http.ResponseWriter, body string, headers map[string]string, subjectID string) {
	result := intercept.InspectRequest(body, p.opts.ServerName, p.opts.Policy)

	// Rate limiting
	rlKey := subjectID
	rlResult := p.rateLimiter.Check(rlKey)
	if !rlResult.Allowed {
		p.logger.Log(audit.LogOpts{
			ServerName: p.opts.ServerName, Direction: "request", Method: result.Method,
			MessageID: result.MessageID, ToolName: result.ToolName, ArgumentsJSON: result.ArgumentsJson,
			Verdict: "rate_limited",
		})

		errBody := fmt.Sprintf(
			`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Quint: rate limit exceeded (%d/%d requests per minute)"}}`,
			rlResult.Used, rlResult.Limit,
		)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", fmt.Sprintf("%d", rlResult.RetryAfterSec))
		w.WriteHeader(429)
		w.Write([]byte(errBody))

		p.logger.Log(audit.LogOpts{
			ServerName: p.opts.ServerName, Direction: "response", Method: result.Method,
			MessageID: result.MessageID, ResponseJSON: errBody, Verdict: "rate_limited",
		})
		qlog.Warn("rate-limited %s (%d/%d rpm)", rlKey, rlResult.Used, rlResult.Limit)
		return
	}

	// Policy deny
	if result.Verdict == intercept.VerdictDeny {
		p.logger.Log(audit.LogOpts{
			ServerName: p.opts.ServerName, Direction: "request", Method: result.Method,
			MessageID: result.MessageID, ToolName: result.ToolName, ArgumentsJSON: result.ArgumentsJson,
			Verdict: string(result.Verdict),
		})

		denyResp := intercept.BuildDenyResponse(result.RawID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(denyResp))

		p.logger.Log(audit.LogOpts{
			ServerName: p.opts.ServerName, Direction: "response", Method: result.Method,
			MessageID: result.MessageID, ToolName: result.ToolName, ResponseJSON: denyResp,
			Verdict: "deny",
		})
		qlog.Info("denied %s on %s", result.ToolName, p.opts.ServerName)
		return
	}

	// Tool call — risk scoring
	if result.ToolName != "" {
		score := p.riskEngine.ScoreToolCall(result.ToolName, result.ArgumentsJson, subjectID)
		action := p.riskEngine.Evaluate(score.Value)

		p.logger.Log(audit.LogOpts{
			ServerName: p.opts.ServerName, Direction: "request", Method: result.Method,
			MessageID: result.MessageID, ToolName: result.ToolName, ArgumentsJSON: result.ArgumentsJson,
			Verdict: func() string {
				if action == "deny" {
					return "deny"
				}
				return string(result.Verdict)
			}(),
			RiskScore: &score.Value, RiskLevel: &score.Level,
		})

		if action == "deny" {
			denyResp := intercept.BuildDenyResponse(result.RawID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(denyResp))

			p.logger.Log(audit.LogOpts{
				ServerName: p.opts.ServerName, Direction: "response", Method: result.Method,
				MessageID: result.MessageID, ToolName: result.ToolName, ResponseJSON: denyResp,
				Verdict: "deny", RiskScore: &score.Value, RiskLevel: &score.Level,
			})
			qlog.Warn("risk-denied %s (score=%d, level=%s)", result.ToolName, score.Value, score.Level)
			return
		}
		if action == "flag" {
			qlog.Warn("high-risk %s (score=%d, level=%s)", result.ToolName, score.Value, score.Level)
		}

		if p.riskEngine.ShouldRevoke(subjectID) {
			qlog.Warn("repeated high-risk actions detected - consider revoking credentials for %s", subjectID)
		}
	} else {
		// Non-tool-call
		p.logger.Log(audit.LogOpts{
			ServerName: p.opts.ServerName, Direction: "request", Method: result.Method,
			MessageID: result.MessageID, Verdict: string(result.Verdict),
		})
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
