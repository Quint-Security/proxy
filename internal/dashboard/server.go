package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/approval"
	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
)

//go:embed all:static
var staticFiles embed.FS

// Server is the dashboard web server.
type Server struct {
	auditDB    *audit.DB
	authDB     *auth.DB
	approvalDB *approval.DB
	policy     intercept.PolicyConfig
	dataDir    string

	// SSE
	sseClients   map[chan string]struct{}
	sseClientsMu sync.Mutex
	stopPoll     chan struct{}
}

// New creates a new dashboard server.
func New(dataDir string, policy intercept.PolicyConfig) (*Server, error) {
	auditDB, err := audit.OpenDB(dataDir)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

	authDB, err := auth.OpenDB(dataDir)
	if err != nil {
		auditDB.Close()
		return nil, fmt.Errorf("open auth db: %w", err)
	}

	approvalDB, err := approval.OpenDB(dataDir)
	if err != nil {
		auditDB.Close()
		authDB.Close()
		return nil, fmt.Errorf("open approval db: %w", err)
	}

	s := &Server{
		auditDB:    auditDB,
		authDB:     authDB,
		approvalDB: approvalDB,
		policy:     policy,
		dataDir:    dataDir,
		sseClients: make(map[chan string]struct{}),
		stopPoll:   make(chan struct{}),
	}

	// Verify audit chain integrity on startup
	verified, brokenAt, err := auditDB.VerifyChain()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: audit chain verification failed: %v\n", err)
	} else if brokenAt != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: Audit chain tamper detected at entry #%d (verified %d entries)\n", brokenAt, verified)
	}

	return s, nil
}

// Start starts the dashboard on the given port.
func (s *Server) Start(port int) error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/audit", s.handleAudit)
	mux.HandleFunc("/api/agents", s.handleAgents)
	mux.HandleFunc("/api/agents/", s.handleAgentAction)
	mux.HandleFunc("/api/approvals", s.handleApprovals)
	mux.HandleFunc("/api/approvals/", s.handleApprovalAction)
	mux.HandleFunc("/api/policy", s.handlePolicy)
	mux.HandleFunc("/api/events", s.handleSSE)

	// Cloud API proxy routes
	mux.HandleFunc("/api/cloud/scores", s.handleCloudScores)
	mux.HandleFunc("/api/cloud/summary", s.handleCloudSummary)
	mux.HandleFunc("/api/cloud/event/", s.handleCloudEventScore)
	mux.HandleFunc("/api/cloud/justification", s.handleCloudJustification)
	mux.HandleFunc("/api/cloud/health", s.handleCloudHealth)

	// Start polling for new audit entries
	go s.pollAuditUpdates()

	// Static files — SPA-aware handler for Next.js static export
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("static files: %w", err)
	}
	mux.Handle("/", &spaHandler{fs: http.FS(sub)})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      corsMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	fmt.Printf("Quint dashboard: http://localhost:%d\n", port)
	return srv.ListenAndServe()
}

// Close cleans up resources.
func (s *Server) Close() {
	close(s.stopPoll)
	if s.auditDB != nil {
		s.auditDB.Close()
	}
	if s.authDB != nil {
		s.authDB.Close()
	}
	if s.approvalDB != nil {
		s.approvalDB.Close()
	}
}

func (s *Server) json(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonErr(w http.ResponseWriter, status int, msg string) {
	s.json(w, status, map[string]string{"error": msg})
}

// --- Handlers ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.auditDB.Stats()

	agents, _ := s.authDB.ListAgents()
	activeAgents := 0
	for _, a := range agents {
		if a.Status == "active" {
			activeAgents++
		}
	}

	pending, _ := s.approvalDB.ListPending()

	response := map[string]any{
		"audit":             stats,
		"agents_total":      len(agents),
		"agents_active":     activeAgents,
		"approvals_pending": len(pending),
		"policy_version":    s.policy.Version,
		"data_dir":          s.dataDir,
	}

	// Add remote scoring health info if configured
	if s.policy.Risk != nil && s.policy.Risk.RemoteAPI != nil {
		remoteInfo := map[string]any{
			"configured": s.policy.Risk.RemoteAPI.Enabled,
			"url":        s.policy.Risk.RemoteAPI.URL,
		}

		// Check if we have any audit entries with remote scoring
		entries, _, _ := s.auditDB.Query(audit.QueryOpts{Limit: 1})
		if len(entries) > 0 && entries[0].ScoringSource != nil && *entries[0].ScoringSource == "remote" {
			remoteInfo["last_response"] = entries[0].Timestamp
			remoteInfo["status"] = "healthy"
		} else if s.policy.Risk.RemoteAPI.Enabled {
			remoteInfo["status"] = "no_recent_activity"
		} else {
			remoteInfo["status"] = "disabled"
		}

		response["remote_scoring"] = remoteInfo
	} else {
		response["remote_scoring"] = map[string]any{
			"configured": false,
			"status":     "not_configured",
		}
	}

	// Add audit chain integrity check
	verified, brokenAt, err := s.auditDB.VerifyChain()
	chainInfo := map[string]any{
		"verified_entries": verified,
	}
	if err != nil {
		chainInfo["status"] = "error"
		chainInfo["error"] = err.Error()
	} else if brokenAt != 0 {
		chainInfo["status"] = "tamper_detected"
		chainInfo["broken_at_entry"] = brokenAt
		chainInfo["warning"] = "Audit log tampering detected - integrity compromised"
	} else if verified > 0 {
		chainInfo["status"] = "verified"
	} else {
		chainInfo["status"] = "empty"
	}
	response["audit_integrity"] = chainInfo

	s.json(w, 200, response)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	entries, total, err := s.auditDB.Query(audit.QueryOpts{
		Limit:      limit,
		Offset:     offset,
		Verdict:    q.Get("verdict"),
		ToolName:   q.Get("tool"),
		ServerName: q.Get("server"),
		AgentName:  q.Get("agent"),
	})
	if err != nil {
		s.jsonErr(w, 500, err.Error())
		return
	}

	s.json(w, 200, map[string]any{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		agents, err := s.authDB.ListAgents()
		if err != nil {
			s.jsonErr(w, 500, err.Error())
			return
		}
		s.json(w, 200, map[string]any{"agents": agents})

	case "POST":
		var req struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			Scopes      string `json:"scopes"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonErr(w, 400, "invalid JSON")
			return
		}
		if req.Name == "" {
			s.jsonErr(w, 400, "name is required")
			return
		}
		if req.Type == "" {
			req.Type = "generic"
		}

		agent, rawKey, err := s.authDB.CreateAgent(req.Name, req.Type, req.Description, req.Scopes, "dashboard")
		if err != nil {
			s.jsonErr(w, 400, err.Error())
			return
		}
		s.json(w, 201, map[string]any{"agent": agent, "api_key": rawKey})

	default:
		s.jsonErr(w, 405, "use GET or POST")
	}
}

func (s *Server) handleAgentAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.jsonErr(w, 405, "use POST")
		return
	}

	// /api/agents/{name}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/agents/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		s.jsonErr(w, 400, "expected /api/agents/{name}/{action}")
		return
	}

	name := parts[0]
	action := parts[1]

	switch action {
	case "suspend":
		if err := s.authDB.UpdateAgentStatus(name, "suspended"); err != nil {
			s.jsonErr(w, 400, err.Error())
			return
		}
		s.json(w, 200, map[string]string{"status": "suspended"})
	case "revoke":
		if err := s.authDB.UpdateAgentStatus(name, "revoked"); err != nil {
			s.jsonErr(w, 400, err.Error())
			return
		}
		s.json(w, 200, map[string]string{"status": "revoked"})
	case "activate":
		if err := s.authDB.UpdateAgentStatus(name, "active"); err != nil {
			s.jsonErr(w, 400, err.Error())
			return
		}
		s.json(w, 200, map[string]string{"status": "active"})
	default:
		s.jsonErr(w, 400, "action must be suspend, revoke, or activate")
	}
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	pending, err := s.approvalDB.ListPending()
	if err != nil {
		s.jsonErr(w, 500, err.Error())
		return
	}
	s.json(w, 200, map[string]any{"pending": pending})
}

func (s *Server) handleApprovalAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.jsonErr(w, 405, "use POST")
		return
	}

	// /api/approvals/{id}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/approvals/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		s.jsonErr(w, 400, "expected /api/approvals/{id}/{action}")
		return
	}

	id := parts[0]
	action := parts[1]

	approved := action == "approve"
	if action != "approve" && action != "deny" {
		s.jsonErr(w, 400, "action must be approve or deny")
		return
	}

	// Sign the decision
	passphrase := os.Getenv("QUINT_PASSPHRASE")
	kp, err := crypto.EnsureKeyPair(s.dataDir, passphrase)
	if err != nil {
		s.jsonErr(w, 500, "signing key not available: "+err.Error())
		return
	}
	decisionData := fmt.Sprintf("%s:%s", id, action)
	sig, err := crypto.SignData(decisionData, kp.PrivateKey)
	if err != nil {
		s.jsonErr(w, 500, "failed to sign decision: "+err.Error())
		return
	}

	if err := s.approvalDB.Decide(id, approved, "dashboard", sig); err != nil {
		s.jsonErr(w, 400, err.Error())
		return
	}

	s.json(w, 200, map[string]string{"status": "ok", "decision": action})
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.json(w, 200, s.policy)
	default:
		s.jsonErr(w, 405, "use GET")
	}
}

// --- SSE Live Updates ---

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 16)
	s.sseClientsMu.Lock()
	s.sseClients[ch] = struct{}{}
	s.sseClientsMu.Unlock()

	defer func() {
		s.sseClientsMu.Lock()
		delete(s.sseClients, ch)
		close(ch)
		s.sseClientsMu.Unlock()
	}()

	// Send initial connected event
	total := s.auditDB.Count()
	fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]any{"type": "connected", "total": total}))
	flusher.Flush()

	// Stream events until client disconnects
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *Server) broadcast(msg string) {
	s.sseClientsMu.Lock()
	defer s.sseClientsMu.Unlock()
	for ch := range s.sseClients {
		select {
		case ch <- msg:
		default:
			// Client too slow, skip
		}
	}
}

func (s *Server) pollAuditUpdates() {
	lastCount := s.auditDB.Count()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopPoll:
			return
		case <-ticker.C:
			current := s.auditDB.Count()
			if current > lastCount {
				delta := current - lastCount
				entries, _ := s.auditDB.GetLast(delta)
				lastCount = current

				msg := mustJSON(map[string]any{
					"type":    "new_entries",
					"entries": entries,
					"total":   current,
				})
				s.broadcast(msg)
			}
		}
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// corsMiddleware adds CORS headers for local dev when dashboard runs separately.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Cloud API Proxy Handlers ---

// handleCloudScores proxies GET /scores/{customer_id}
func (s *Server) handleCloudScores(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		s.jsonErr(w, 405, "use GET")
		return
	}

	cfg := s.getCloudAPIConfig()
	if cfg == nil {
		s.jsonErr(w, 503, "cloud API not configured")
		return
	}

	// Build query string with customer_id from config
	q := r.URL.Query()
	q.Set("customer_id", cfg.CustomerID)
	url := fmt.Sprintf("%s/scores/%s?%s", strings.TrimSuffix(cfg.URL, "/"), cfg.CustomerID, q.Encode())

	s.proxyCloudRequest(w, url, cfg.APIKey)
}

// handleCloudSummary proxies GET /scores/{customer_id}/summary
func (s *Server) handleCloudSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		s.jsonErr(w, 405, "use GET")
		return
	}

	cfg := s.getCloudAPIConfig()
	if cfg == nil {
		s.jsonErr(w, 503, "cloud API not configured")
		return
	}

	url := fmt.Sprintf("%s/scores/%s/summary", strings.TrimSuffix(cfg.URL, "/"), cfg.CustomerID)
	s.proxyCloudRequest(w, url, cfg.APIKey)
}

// handleCloudEventScore proxies GET /scores/event/{event_id}
func (s *Server) handleCloudEventScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		s.jsonErr(w, 405, "use GET")
		return
	}

	cfg := s.getCloudAPIConfig()
	if cfg == nil {
		s.jsonErr(w, 503, "cloud API not configured")
		return
	}

	// Extract event_id from path
	eventID := strings.TrimPrefix(r.URL.Path, "/api/cloud/event/")
	if eventID == "" {
		s.jsonErr(w, 400, "event_id is required")
		return
	}

	url := fmt.Sprintf("%s/scores/event/%s", strings.TrimSuffix(cfg.URL, "/"), eventID)
	s.proxyCloudRequest(w, url, cfg.APIKey)
}

// handleCloudJustification proxies GET /justification?event_id=...
func (s *Server) handleCloudJustification(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		s.jsonErr(w, 405, "use GET")
		return
	}

	cfg := s.getCloudAPIConfig()
	if cfg == nil {
		s.jsonErr(w, 503, "cloud API not configured")
		return
	}

	eventID := r.URL.Query().Get("event_id")
	if eventID == "" {
		s.jsonErr(w, 400, "event_id query parameter is required")
		return
	}

	url := fmt.Sprintf("%s/justification?event_id=%s", strings.TrimSuffix(cfg.URL, "/"), eventID)
	s.proxyCloudRequest(w, url, cfg.APIKey)
}

// handleCloudHealth proxies GET /health/detailed
func (s *Server) handleCloudHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		s.jsonErr(w, 405, "use GET")
		return
	}

	cfg := s.getCloudAPIConfig()
	if cfg == nil {
		s.jsonErr(w, 503, "cloud API not configured")
		return
	}

	url := fmt.Sprintf("%s/health/detailed", strings.TrimSuffix(cfg.URL, "/"))
	s.proxyCloudRequest(w, url, cfg.APIKey)
}

// getCloudAPIConfig returns the remote API config if available and enabled.
func (s *Server) getCloudAPIConfig() *intercept.RemoteAPIConfig {
	if s.policy.Risk == nil || s.policy.Risk.RemoteAPI == nil {
		return nil
	}
	cfg := s.policy.Risk.RemoteAPI
	if !cfg.Enabled || cfg.URL == "" || cfg.APIKey == "" || cfg.CustomerID == "" {
		return nil
	}
	return cfg
}

// proxyCloudRequest forwards a request to the cloud API with authentication.
func (s *Server) proxyCloudRequest(w http.ResponseWriter, url, apiKey string) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		s.jsonErr(w, 500, "failed to build request: "+err.Error())
		return
	}

	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		s.jsonErr(w, 502, "cloud API unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Copy status code and content-type
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(w, `{"error": "failed to read cloud API response"}`)
		return
	}
	w.Write(body)
}

// spaHandler serves static files and falls back to .html extension or index.html
// for Next.js static export routing (e.g., /audit → audit.html).
type spaHandler struct {
	fs http.FileSystem
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Strip trailing slash to prevent redirect loops
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}

	// Try exact path first (for static assets like /_next/*, .css, .js)
	if f, err := h.fs.Open(path); err == nil {
		stat, statErr := f.Stat()
		if statErr == nil && !stat.IsDir() {
			defer f.Close()
			http.ServeContent(w, r, stat.Name(), stat.ModTime(), f.(io.ReadSeeker))
			return
		}
		f.Close()
	}

	// Try path + .html (e.g., /audit → /audit.html)
	if f, err := h.fs.Open(path + ".html"); err == nil {
		stat, statErr := f.Stat()
		if statErr == nil {
			defer f.Close()
			http.ServeContent(w, r, stat.Name(), stat.ModTime(), f.(io.ReadSeeker))
			return
		}
		f.Close()
	}

	// Try path/index.html (e.g., /some/path/ → /some/path/index.html)
	if f, err := h.fs.Open(path + "/index.html"); err == nil {
		stat, statErr := f.Stat()
		if statErr == nil {
			defer f.Close()
			http.ServeContent(w, r, stat.Name(), stat.ModTime(), f.(io.ReadSeeker))
			return
		}
		f.Close()
	}

	// Fallback to index.html for client-side routing
	if f, err := h.fs.Open("/index.html"); err == nil {
		stat, statErr := f.Stat()
		if statErr == nil {
			defer f.Close()
			http.ServeContent(w, r, stat.Name(), stat.ModTime(), f.(io.ReadSeeker))
			return
		}
		f.Close()
	}

	http.NotFound(w, r)
}
