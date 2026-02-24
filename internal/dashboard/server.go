package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
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

//go:embed static/*
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

	return &Server{
		auditDB:    auditDB,
		authDB:     authDB,
		approvalDB: approvalDB,
		policy:     policy,
		dataDir:    dataDir,
		sseClients: make(map[chan string]struct{}),
		stopPoll:   make(chan struct{}),
	}, nil
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

	// Start polling for new audit entries
	go s.pollAuditUpdates()

	// Static files
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("static files: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

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

	s.json(w, 200, map[string]any{
		"audit":            stats,
		"agents_total":     len(agents),
		"agents_active":    activeAgents,
		"approvals_pending": len(pending),
		"policy_version":   s.policy.Version,
		"data_dir":         s.dataDir,
	})
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
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan string, 16)
	s.sseClientsMu.Lock()
	s.sseClients[ch] = struct{}{}
	s.sseClientsMu.Unlock()

	defer func() {
		s.sseClientsMu.Lock()
		delete(s.sseClients, ch)
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

// corsMiddleware adds CORS headers so the external Next.js dashboard can call the API.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only add CORS for API routes
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
