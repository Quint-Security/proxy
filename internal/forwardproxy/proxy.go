package forwardproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/auth"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
	"github.com/Quint-Security/quint-proxy/internal/intercept"
	"github.com/Quint-Security/quint-proxy/internal/llmparse"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/Quint-Security/quint-proxy/internal/risk"
	"github.com/Quint-Security/quint-proxy/internal/stream"
)

// EventInfo carries event data for external consumers (e.g. cloud forwarding).
type EventInfo struct {
	Action    string
	Agent     string
	RiskScore *int
	Blocked   bool
	Timestamp time.Time
}

// AgentToolEvent carries a parsed LLM tool call extracted from AI provider traffic.
type AgentToolEvent struct {
	EventID     string
	Timestamp   time.Time
	Provider    string
	Model       string
	Agent       string
	ToolName    string
	ToolArgs    string
	ToolResult  string
	RiskScore   int
	Blocked     bool
	ProcessPID  int
	ProcessName string
}

// Options configures the forward proxy.
type Options struct {
	Port       int
	Policy     intercept.PolicyConfig
	DataDir    string
	OnEvent    func(EventInfo)      // optional callback for each intercepted request event
	OnToolCall func(AgentToolEvent) // optional callback for parsed LLM tool calls
}

// Proxy is the HTTP forward proxy server with MITM TLS interception.
type Proxy struct {
	opts              Options
	server            *http.Server
	logger            *audit.Logger
	riskEngine        *risk.Engine
	sessionTracker    *risk.SessionTracker
	auditDB           *audit.DB
	authDB            *auth.DB
	behaviorDB        *risk.BehaviorDB
	kafkaProducer     *stream.Producer
	transport         *http.Transport
	certCache         *CertCache
	identityResolver  *IdentityResolver
	correlationEngine *intercept.CorrelationEngine
	traceMap          sync.Map // traceID (string) → agentID (string)
	agentTraces       sync.Map // agentID (string) → *intercept.TraceContext
	tunnelTracker     *tunnelTracker
	agentCookieStore  *agentCookieStore
}

// tunnelTracker detects new agent instances and child subprocesses by monitoring
// CONNECT tunnel patterns. A single process opens multiple tunnels in a quick
// burst (connection pooling). A new process (child or peer) opens tunnels after
// a temporal gap from the existing process.
type tunnelTracker struct {
	mu              sync.Mutex
	burstWindowMS   int64 // ms — CONNECTs within this window are same agent
	ipState         map[string]*ipTunnelState
}

type ipTunnelState struct {
	activeTunnels  int                // total active tunnels from this key
	lastConnect    time.Time          // last CONNECT timestamp
	sessionEndTime time.Time          // when activeTunnels last dropped to 0
	parentID       *auth.Identity     // the key's primary (first) identity
	currentID      *auth.Identity     // the identity assigned to the latest burst
	childCount     int                // children spawned (with parent trace)
	peerCount      int                // independent instances spawned (no parent trace)

	// Concurrency baseline tracking — detects sub-agents that open tunnels
	// while the parent is still active (e.g. Claude Code Task tool).
	firstConnect    time.Time        // when this key was first seen
	peakTunnels     int              // high-water mark during stabilization
	baselineSet     bool             // true once stabilization window elapses
	baseline        int              // established concurrency baseline
	parentModel     string           // model used by parent (e.g. "claude-opus-4-6")
	pendingChildren []*pendingChild  // tentative sub-agents awaiting model confirmation

	// Model-divergence split tracking — detects sub-agents when the model
	// field in POST bodies changes (e.g. Opus → Haiku in same tunnel).
	splitTunnels    map[string]bool  // tunnelID → true if identity was already split in this tunnel
}

// pendingChild represents a tentative sub-agent detected by concurrency spike,
// awaiting model divergence confirmation.
type pendingChild struct {
	identity  *auth.Identity
	confirmed bool // true once model divergence confirms
}

const (
	// stabilizationWindow is the time after first CONNECT during which the
	// tracker learns the normal concurrency level (connection pooling baseline).
	stabilizationWindow = 10 * time.Second

	// spikeThreshold is the number of concurrent tunnels above the baseline
	// that triggers sub-agent detection.
	spikeThreshold = 2
)

func newTunnelTracker(burstWindowMS int64) *tunnelTracker {
	if burstWindowMS <= 0 {
		burstWindowMS = 2000
	}
	return &tunnelTracker{
		burstWindowMS: burstWindowMS,
		ipState:       make(map[string]*ipTunnelState),
	}
}

// resolve checks whether a CONNECT from the given key should reuse the current
// identity, create a new child (hasParentTrace=true), or a new peer instance
// (hasParentTrace=false). Returns the identity to use, a parent agent ID if
// this is a child, and whether a new agent was created.
//
// Detection uses two complementary strategies:
//   - Phase A (temporal gap): A gap > burstWindow between CONNECTs while tunnels
//     are active indicates a new sequential process (original behavior).
//   - Phase B (concurrency spike): After a stabilization period, a spike in
//     concurrent tunnels beyond the established baseline indicates new sub-agent
//     processes (e.g. Claude Code Task tool spawning parallel sub-agents).
func (t *tunnelTracker) resolve(key string, resolved *auth.Identity, resolver *IdentityResolver, ua string, hasParentTrace bool) (identity *auth.Identity, parentAgentID string, isNew bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	state, ok := t.ipState[key]
	if !ok {
		// First CONNECT from this key — establish as primary
		state = &ipTunnelState{
			parentID:     resolved,
			currentID:    resolved,
			firstConnect: now,
			peakTunnels:  1,
		}
		t.ipState[key] = state
		state.activeTunnels++
		state.lastConnect = now
		return resolved, "", false
	}

	gap := now.Sub(state.lastConnect)
	burstWindow := time.Duration(t.burstWindowMS) * time.Millisecond

	// Phase A0: New session detection — all tunnels were closed and enough
	// time has passed since the session ended. This is a genuinely new
	// session (e.g. user closed Claude Code and opened a new one), not a
	// rapid reconnect from connection pooling.
	if state.activeTunnels == 0 && !state.sessionEndTime.IsZero() {
		sessionGap := now.Sub(state.sessionEndTime)
		if sessionGap > burstWindow {
			// New session from same IP+tool+provider — create a fresh peer identity
			// and reset the tracker state so this session gets its own baseline.
			state.peerCount++
			peerSeed := fmt.Sprintf("%s:session:%d", key, state.peerCount)
			newAgent := resolver.ResolveFromHeaders(ua, "", peerSeed)
			if newAgent != nil {
				qlog.Info("tunnel: new session from %s → %s (session #%d, gap=%v since last session ended)",
					key, newAgent.AgentName, state.peerCount+1, sessionGap)
			}

			// Update the httpIdentities cache so subsequent ResolveForHTTP
			// calls within this session return the new identity.
			resolver.RotateIdentity(key, newAgent)

			// Reset state for the new session
			state.parentID = newAgent
			state.currentID = newAgent
			state.firstConnect = now
			state.peakTunnels = 1
			state.baselineSet = false
			state.baseline = 0
			state.childCount = 0
			state.pendingChildren = nil
			state.splitTunnels = nil
			state.sessionEndTime = time.Time{}
			state.activeTunnels = 1
			state.lastConnect = now
			return newAgent, "", true
		}
		// Rapid reconnect after session close (within burst window) —
		// same session resuming, reuse current identity.
	}

	// Phase A: Temporal gap detection (preserves existing sequential handoff behavior).
	// A gap > burstWindow while tunnels are still active means a new process connected.
	if gap > burstWindow && state.activeTunnels > 0 {
		newAgent, parentIDStr := t.resolveNewAgent(key, state, resolver, ua, hasParentTrace, gap)

		state.currentID = newAgent
		state.activeTunnels++
		state.lastConnect = now
		return newAgent, parentIDStr, true
	}

	// Phase B: Concurrency spike detection (new — handles concurrent sub-agents).
	// During stabilization, learn the concurrency baseline (connection pool size).
	if !state.baselineSet {
		if now.Sub(state.firstConnect) > stabilizationWindow {
			// Stabilization complete — freeze the baseline
			state.baseline = state.peakTunnels
			state.baselineSet = true
			qlog.Debug("tunnel: baseline set for %s: %d concurrent tunnels", key, state.baseline)
		} else {
			// Still stabilizing — track high-water mark, reuse current identity
			state.activeTunnels++
			if state.activeTunnels > state.peakTunnels {
				state.peakTunnels = state.activeTunnels
			}
			state.lastConnect = now
			return state.currentID, "", false
		}
	}

	// Baseline is set — check for concurrency spike
	if state.baselineSet && state.activeTunnels >= state.baseline+spikeThreshold {
		// Concurrency spike detected → tentative sub-agent
		parentIDStr := ""
		if state.parentID != nil {
			parentIDStr = state.parentID.AgentID
		}

		state.childCount++
		newAgent := resolver.ResolveChild(state.parentID, state.childCount)
		if newAgent == nil {
			fallbackSeed := fmt.Sprintf("%s:spike:%d", key, state.childCount)
			newAgent = resolver.ResolveFromHeaders(ua, "", fallbackSeed)
		}
		if newAgent != nil {
			state.pendingChildren = append(state.pendingChildren, &pendingChild{
				identity: newAgent,
			})
			qlog.Info("tunnel: detected sub-agent from %s → %s (parent=%s, active=%d, baseline=%d)",
				key, newAgent.AgentName, parentIDStr, state.activeTunnels, state.baseline)
		}

		state.currentID = newAgent
		state.activeTunnels++
		state.lastConnect = now
		return newAgent, parentIDStr, true
	}

	// Within burst window or within baseline concurrency → same agent (connection pooling)
	state.activeTunnels++
	if state.activeTunnels > state.peakTunnels {
		state.peakTunnels = state.activeTunnels
	}
	state.lastConnect = now

	return state.currentID, "", false
}

// resolveNewAgent creates a new child or peer identity for a temporal gap detection.
func (t *tunnelTracker) resolveNewAgent(key string, state *ipTunnelState, resolver *IdentityResolver, ua string, hasParentTrace bool, gap time.Duration) (newAgent *auth.Identity, parentIDStr string) {
	if state.parentID != nil {
		parentIDStr = state.parentID.AgentID
	}

	if hasParentTrace {
		// Confirmed child (trace header present)
		state.childCount++
		newAgent = resolver.ResolveChild(state.parentID, state.childCount)
		if newAgent != nil {
			qlog.Info("tunnel: detected child from %s → %s (parent=%s, gap=%v, active=%d)",
				key, newAgent.AgentName, parentIDStr, gap, state.activeTunnels)
		}
	} else if state.activeTunnels > 0 {
		// Inferred child: parent still active, new process without trace header.
		// Strong evidence of sub-agent (e.g. Codex spawning sub-agents).
		state.childCount++
		newAgent = resolver.ResolveChild(state.parentID, state.childCount)
		if newAgent != nil {
			newAgent.Source = "inferred_child"
			qlog.Info("tunnel: inferred child from %s → %s (parent=%s, gap=%v, active=%d)",
				key, newAgent.AgentName, parentIDStr, gap, state.activeTunnels)
		}
	} else {
		// True peer: all parent tunnels closed, new process started independently.
		state.peerCount++
		peerSeed := fmt.Sprintf("%s:peer:%d", key, state.peerCount)
		newAgent = resolver.ResolveFromHeaders(ua, "", peerSeed)
		if newAgent != nil {
			qlog.Info("tunnel: detected new instance from %s → %s (peer #%d, gap=%v, active=%d)",
				key, newAgent.AgentName, state.peerCount, gap, state.activeTunnels)
		}
		parentIDStr = ""
	}

	if newAgent == nil {
		fallbackSeed := fmt.Sprintf("%s:fallback:%d", key, resolver.NextSuffix())
		newAgent = resolver.ResolveFromHeaders(ua, "", fallbackSeed)
	}

	return newAgent, parentIDStr
}

// parentIdentity returns the parent (first) identity for an IP.
func (t *tunnelTracker) parentIdentity(ip string) *auth.Identity {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state, ok := t.ipState[ip]; ok {
		return state.parentID
	}
	return nil
}

// release decrements the active tunnel count for an IP.
func (t *tunnelTracker) release(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state, ok := t.ipState[ip]; ok {
		state.activeTunnels--
		if state.activeTunnels <= 0 {
			// All tunnels closed — record when the session ended so we
			// can distinguish a rapid reconnect (same session) from a
			// genuinely new session after a gap.
			state.activeTunnels = 0
			state.sessionEndTime = time.Now()
		}
	}
}

// confirmModel records a model observation for a tunnel key. The first model
// seen becomes the parent's model. Subsequent models are checked against the
// parent for divergence, which confirms tentative sub-agent detections.
func (t *tunnelTracker) confirmModel(key, agentID, model string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	state := t.ipState[key]
	if state == nil {
		return
	}

	// Track parent's model (first model seen is the parent's)
	if state.parentModel == "" {
		state.parentModel = model
		return
	}

	// Check pending children for model divergence
	for _, pc := range state.pendingChildren {
		if pc.identity != nil && pc.identity.AgentID == agentID && !pc.confirmed {
			if isModelDivergence(state.parentModel, model) {
				pc.confirmed = true
				qlog.Info("tunnel: confirmed sub-agent %s (model=%s diverges from parent model=%s)",
					pc.identity.AgentName, model, state.parentModel)
			}
		}
	}
}

// isModelDivergence checks if the child model differs from the parent model,
// indicating a sub-agent. Known patterns: parent=opus/sonnet, child=haiku;
// parent=gpt-4o, child=gpt-4o-mini; parent=pro, child=flash.
func isModelDivergence(parentModel, childModel string) bool {
	if parentModel == childModel || parentModel == "" || childModel == "" {
		return false
	}
	p := strings.ToLower(parentModel)
	c := strings.ToLower(childModel)

	// Anthropic: opus/sonnet parent → haiku child
	if (strings.Contains(p, "opus") || strings.Contains(p, "sonnet")) &&
		strings.Contains(c, "haiku") {
		return true
	}
	// OpenAI: gpt-4o parent → gpt-4o-mini child
	if strings.Contains(p, "gpt-4") && !strings.Contains(p, "mini") &&
		strings.Contains(c, "mini") {
		return true
	}
	// Google: pro parent → flash child
	if strings.Contains(p, "pro") && strings.Contains(c, "flash") {
		return true
	}
	// Any model difference is still a signal
	return true
}

// modelSplitResult describes whether a model observation should trigger an
// identity split within a tunnel (Layer 1: request-level sub-agent detection).
type modelSplitResult struct {
	ShouldSplit    bool
	ParentIdentity *auth.Identity
	ParentModel    string
}

// detectModelSplit checks whether a model observation in a tunnel should trigger
// an identity split. This detects sub-agents like Haiku running inside an Opus
// tunnel where HTTP/2 means only 1-2 tunnels exist (no concurrency spike).
// Each tunnel can only be split once.
func (t *tunnelTracker) detectModelSplit(key, tunnelID, model string) modelSplitResult {
	t.mu.Lock()
	defer t.mu.Unlock()

	state := t.ipState[key]
	if state == nil {
		return modelSplitResult{}
	}

	// First model observation establishes the parent's model
	if state.parentModel == "" {
		state.parentModel = model
		return modelSplitResult{}
	}

	// Check if this tunnel was already split (max once per tunnel)
	if state.splitTunnels != nil && state.splitTunnels[tunnelID] {
		return modelSplitResult{}
	}

	// Check for model divergence
	if !isModelDivergence(state.parentModel, model) {
		return modelSplitResult{}
	}

	// Mark this tunnel as split
	if state.splitTunnels == nil {
		state.splitTunnels = make(map[string]bool)
	}
	state.splitTunnels[tunnelID] = true

	return modelSplitResult{
		ShouldSplit:    true,
		ParentIdentity: state.parentID,
		ParentModel:    state.parentModel,
	}
}

// New creates a new forward proxy.
func New(opts Options) (*Proxy, error) {
	dataDir := intercept.ResolveDataDir(opts.DataDir)

	// CA for MITM
	ca, err := crypto.EnsureCA(dataDir)
	if err != nil {
		return nil, fmt.Errorf("ensure CA: %w", err)
	}
	qlog.Info("CA cert: %s", crypto.CertPath(dataDir))

	// Audit infrastructure
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

	// Auth DB for agent identity resolution
	authDB, err := auth.OpenDB(dataDir)
	if err != nil {
		return nil, fmt.Errorf("open auth db: %w", err)
	}

	// Risk engine with HTTP patterns
	behaviorDB, err := risk.OpenBehaviorDB(dataDir)
	if err != nil {
		qlog.Error("failed to open behavior db: %v", err)
	}
	riskEngine := risk.NewEngineFromPolicy(opts.Policy.Risk, behaviorDB)
	riskEngine.SetIncludeHTTP(true)

	// Session tracker
	sessionTracker := risk.NewSessionTracker(20, 0)

	// Kafka producer
	var kafkaProducer *stream.Producer
	if opts.Policy.Kafka != nil && opts.Policy.Kafka.Enabled {
		kafkaProducer = stream.NewProducer(&stream.ProducerConfig{
			Brokers:     opts.Policy.Kafka.Brokers,
			Async:       opts.Policy.Kafka.Async,
			BatchSize:   opts.Policy.Kafka.BatchSize,
			BatchTimeMs: opts.Policy.Kafka.BatchTimeMs,
		})
	}

	p := &Proxy{
		opts:              opts,
		logger:            logger,
		riskEngine:        riskEngine,
		sessionTracker:    sessionTracker,
		auditDB:           auditDB,
		authDB:            authDB,
		behaviorDB:        behaviorDB,
		kafkaProducer:     kafkaProducer,
		certCache:         NewCertCache(ca),
		identityResolver:  NewIdentityResolver(authDB),
		correlationEngine: intercept.NewCorrelationEngine(),
		tunnelTracker:     newTunnelTracker(2000),
		agentCookieStore:  newAgentCookieStore(),
		transport: &http.Transport{
			Proxy:               nil, // never inherit HTTP_PROXY/HTTPS_PROXY from env
			TLSClientConfig:     &tls.Config{},
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	return p, nil
}

// Start begins listening.
func (p *Proxy) Start() error {
	p.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", p.opts.Port),
		Handler:      p,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // no timeout for streaming
	}

	qlog.Info("forward proxy listening on http://localhost:%d", p.opts.Port)
	qlog.Info("set HTTP_PROXY=http://localhost:%d HTTPS_PROXY=http://localhost:%d", p.opts.Port, p.opts.Port)
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
	if p.authDB != nil {
		p.authDB.Close()
	}
	if p.behaviorDB != nil {
		p.behaviorDB.Close()
	}
	if p.kafkaProducer != nil {
		p.kafkaProducer.Close()
	}
}

// ServeHTTP dispatches HTTP vs CONNECT requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// resolveProxyAuth extracts agent identity from the Proxy-Authorization header.
// HTTP clients automatically send this header when the proxy URL contains a username
// (e.g. http://my-agent@localhost:9090). Returns nil for anonymous connections.
func (p *Proxy) resolveProxyAuth(r *http.Request) *auth.Identity {
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return nil
	}
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return nil
	}
	// Format is "username:password" — we only use the username
	username, _, _ := strings.Cut(string(decoded), ":")
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}

	identity, created, err := p.authDB.FindOrCreateAgent(username, "http-agent", "")
	if err != nil {
		qlog.Error("resolve proxy auth for %q: %v", username, err)
		return nil
	}
	if created {
		qlog.Info("auto-registered agent %q (id=%s)", username, identity.AgentID)
	}
	identity.Source = "proxy_auth"
	return identity
}

// resolveProxyAuthOrAgent tries X-Quint-Agent header first, then Proxy-Authorization.
// Returns nil if neither is present. Provider-aware resolution is done by callers.
func (p *Proxy) resolveProxyAuthOrAgent(r *http.Request) *auth.Identity {
	if agentHeader := r.Header.Get("X-Quint-Agent"); agentHeader != "" {
		if identity := p.identityResolver.ResolveFromAgentID(agentHeader); identity != nil {
			return identity
		}
	}
	return p.resolveProxyAuth(r)
}

// subjectFromIdentity returns the subject ID from an identity, or a fallback default.
func subjectFromIdentity(identity *auth.Identity, fallback string) (subjectID, agentID, agentName string) {
	if identity != nil {
		return identity.SubjectID, identity.AgentID, identity.AgentName
	}
	return fallback, "", ""
}

// assignTrace returns the existing trace context for an agent, or creates a new
// root trace. All tunnels/connections from the same agent share one trace.
func (p *Proxy) assignTrace(identity *auth.Identity) *intercept.TraceContext {
	if identity != nil {
		// Return existing trace for this agent if one was already assigned
		if existing, ok := p.agentTraces.Load(identity.AgentID); ok {
			return existing.(*intercept.TraceContext)
		}
	}

	tc := intercept.NewTraceContext()
	if identity != nil {
		p.agentTraces.Store(identity.AgentID, tc)
		p.traceMap.Store(tc.TraceID, identity.AgentID)
	}
	return tc
}

// resolveParentFromTrace checks a request for an incoming X-Quint-Trace header.
// If present, it looks up the parent agent ID from the trace map.
func (p *Proxy) resolveParentFromTrace(r *http.Request) (parentAgentID string, tc *intercept.TraceContext) {
	header := r.Header.Get("X-Quint-Trace")
	if header == "" {
		return "", nil
	}
	tc = intercept.ParseTraceHeader(header)
	if tc == nil {
		return "", nil
	}
	if val, ok := p.traceMap.Load(tc.TraceID); ok {
		parentAgentID = val.(string)
	}
	return parentAgentID, tc
}

// handleHTTP forwards plain HTTP requests with full inspection.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Detect provider from request host for proper agent naming.
	provider := InferProvider(r.Host)
	identity := p.resolveProxyAuthOrAgent(r)
	if identity == nil {
		identity = p.identityResolver.ResolveForHTTP(r.RemoteAddr, r.Header.Get("User-Agent"), provider)
	}

	// Cookie-based identity override
	if cookieAgentID := extractAgentCookie(r); cookieAgentID != "" {
		if cookieIdentity := p.agentCookieStore.Lookup(cookieAgentID); cookieIdentity != nil {
			identity = cookieIdentity
		}
	}

	// Strip proxy cookie before forwarding to upstream
	stripQuintCookie(r)

	// Register identity for future cookie lookups
	p.agentCookieStore.Register(identity)

	subjectID, agentID, agentName := subjectFromIdentity(identity, "http-agent")

	// Trace context: check for incoming parent trace, then assign our own
	parentAgentID, incomingTrace := p.resolveParentFromTrace(r)
	tc := p.assignTrace(identity)
	var agentDepth int
	if incomingTrace != nil && parentAgentID != "" {
		agentDepth = incomingTrace.Depth + 1
		tc = &intercept.TraceContext{TraceID: incomingTrace.TraceID, Depth: agentDepth}
		// Store this agent's mapping too so its children can find it
		if identity != nil {
			p.traceMap.Store(tc.TraceID, identity.AgentID)
		}
		p.correlationEngine.AddContextSignal(parentAgentID, agentID, tc.TraceID, agentDepth)
		p.logger.RecordRelationship(parentAgentID, agentID, 0.95, agentDepth, "direct", "context")
		qlog.Info("trace: linked child %s → parent %s (depth=%d, trace=%s)", agentID, parentAgentID, agentDepth, tc.TraceID)
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	action := intercept.ClassifyHTTPAction(r.Method, host, r.URL.Path)
	domain := intercept.StripPort(host)

	// Domain policy check
	verdict := intercept.EvaluateDomainPolicy(p.opts.Policy, host)
	if verdict == intercept.VerdictDeny {
		p.logAndDeny(w, domain, r.Method, action, r.URL.String(), "domain_policy")
		return
	}

	// Read a capped preview for logging/scoring; stream the full body to upstream
	maxBody := p.maxBodyLogSize()
	var bodyPreview string
	var forwardBody io.Reader
	if r.Body != nil {
		previewBuf, _ := io.ReadAll(io.LimitReader(r.Body, int64(maxBody+1)))
		if len(previewBuf) > maxBody {
			bodyPreview = string(previewBuf[:maxBody]) + "..."
		} else {
			bodyPreview = string(previewBuf)
		}
		// Reconstruct full body: already-read preview + remaining (streamed)
		forwardBody = io.MultiReader(bytes.NewReader(previewBuf), r.Body)
		defer r.Body.Close()
	}

	// Risk scoring — only score on action pattern, not body content.
	// HTTP request bodies (e.g. API payloads) contain conversation text that
	// triggers false positives on keyword patterns designed for MCP tool args.
	score := p.riskEngine.ScoreToolCall(action, "", subjectID)
	riskAction := p.riskEngine.Evaluate(score.Value)

	if riskAction == "deny" {
		p.logAndDeny(w, domain, r.Method, action, r.URL.String(), "risk_denied")
		return
	}

	// Session tracking
	p.sessionTracker.Record(subjectID, action)

	// Audit log request
	argsJSON := buildRequestArgs(r.URL.String(), r.Method, r.Header.Get("Content-Type"), bodyPreview, p.logBodies())
	riskScore := score.Value
	riskLevel := score.Level
	p.logger.Log(audit.LogOpts{
		ServerName:    domain,
		Direction:     "request",
		Method:        r.Method,
		ToolName:      action,
		ArgumentsJSON: argsJSON,
		Verdict:       "allow",
		RiskScore:     &riskScore,
		RiskLevel:     &riskLevel,
		AgentID:       agentID,
		AgentName:     agentName,
		TraceID:       tc.TraceID,
		AgentDepth:    &agentDepth,
		ParentAgentID: parentAgentID,
	})
	if p.opts.OnEvent != nil {
		p.opts.OnEvent(EventInfo{
			Action:    action,
			Agent:     agentName,
			RiskScore: &riskScore,
			Blocked:   false,
			Timestamp: time.Now(),
		})
	}

	// Forward the request — stream body directly to upstream
	outReq, err := http.NewRequest(r.Method, r.URL.String(), forwardBody)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	outReq.ContentLength = r.ContentLength
	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("X-Quint-Agent")
	outReq.Header.Del("X-Quint-Trace")

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		qlog.Error("forward error for %s %s: %v", r.Method, r.URL, err)
		http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body preview
	var respBodyPreview string
	if p.logBodies() {
		respBuf, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody+1)))
		if len(respBuf) > maxBody {
			respBodyPreview = string(respBuf[:maxBody]) + "..."
		} else {
			respBodyPreview = string(respBuf)
		}
		// Need to re-create reader for the client
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(respBuf), resp.Body))
	}

	// Copy response to client, injecting trace header so the process
	// can discover its trace ID and propagate to child processes.
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("X-Quint-Trace", tc.String())
	if agentID != "" {
		w.Header().Set("X-Quint-Agent", agentID)
	}
	// Inject agent cookie for plain HTTP responses
	cookie := &http.Cookie{
		Name:     quintCookieName,
		Value:    agentID,
		Path:     "/",
		HttpOnly: true,
	}
	if agentID != "" {
		http.SetCookie(w, cookie)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	// Audit log response
	respJSON := buildResponseArgs(resp.StatusCode, resp.Header.Get("Content-Type"), respBodyPreview)
	p.logger.Log(audit.LogOpts{
		ServerName:    domain,
		Direction:     "response",
		Method:        r.Method,
		ToolName:      action,
		ResponseJSON:  respJSON,
		Verdict:       "passthrough",
		RiskScore:     &riskScore,
		RiskLevel:     &riskLevel,
		AgentID:       agentID,
		AgentName:     agentName,
		TraceID:       tc.TraceID,
		AgentDepth:    &agentDepth,
		ParentAgentID: parentAgentID,
	})

	if riskAction == "flag" {
		qlog.Warn("flagged %s %s (risk=%d, level=%s)", r.Method, r.URL, score.Value, score.Level)
	}

	qlog.Debug("forwarded %s %s → %d (risk=%d)", r.Method, r.URL, resp.StatusCode, score.Value)
}

// handleConnect implements MITM TLS interception for HTTPS.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Extract the source IP for tunnel tracking.
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Detect destination domain and API provider FIRST so we can resolve
	// the correct identity per-provider (e.g. Claude Code → Anthropic vs
	// Claude Code → OpenAI get distinct agent identities).
	host := r.Host
	domain := intercept.StripPort(host)
	provider := InferProvider(domain)

	// Passthrough: AI provider APIs get a blind TCP tunnel (no MITM).
	// We intercept agent tool calls, not model inference traffic.
	if isPassthroughDomain(domain) {
		p.blindTunnel(w, r, host)
		return
	}

	// Build tracker key as ip:toolName:provider.
	toolName, _ := ParseToolFromUA(r.Header.Get("User-Agent"))
	if toolName == "" {
		toolName = "_unknown"
	}
	trackerKey := ip + ":" + toolName
	if provider != "" {
		trackerKey = ip + ":" + toolName + ":" + provider
	}

	qlog.Debug("CONNECT %s ua=%q trackerKey=%s provider=%s", host, r.Header.Get("User-Agent"), trackerKey, provider)

	// Resolve identity with provider: try X-Quint-Agent / Proxy-Auth first,
	// then fall back to IP+tool+provider-based resolution.
	baseIdentity := p.resolveProxyAuthOrAgent(r)
	if baseIdentity == nil {
		baseIdentity = p.identityResolver.ResolveForHTTP(r.RemoteAddr, r.Header.Get("User-Agent"), provider)
	}

	// Check for parent trace BEFORE tunnel tracking — this determines whether
	// a new process detected by temporal gap is a child or an independent peer.
	parentAgentID, incomingTrace := p.resolveParentFromTrace(r)
	hasParentTrace := parentAgentID != ""

	// Tunnel tracker: detects new processes by looking for temporal gaps
	// between CONNECT requests. Same-process connections pool quickly (< 2s).
	// With parent trace → child subprocess (derived_{parent}_{id}).
	// Without parent trace → independent peer instance (word-based name).
	identity, tunnelParentID, isNew := p.tunnelTracker.resolve(
		trackerKey, baseIdentity, p.identityResolver, r.Header.Get("User-Agent"), hasParentTrace,
	)
	// Debug: log tunnel state after resolve
	resolvedAgentName := ""
	if identity != nil {
		resolvedAgentName = identity.AgentName
	}
	p.tunnelTracker.mu.Lock()
	if st := p.tunnelTracker.ipState[trackerKey]; st != nil {
		qlog.Debug("CONNECT resolve: key=%s agent=%s isNew=%v active=%d peak=%d baseline=%d baselineSet=%v hasParent=%v",
			trackerKey, resolvedAgentName, isNew, st.activeTunnels, st.peakTunnels, st.baseline, st.baselineSet, hasParentTrace)
	}
	p.tunnelTracker.mu.Unlock()
	// Release this tunnel slot when serveMITM (or early return) finishes.
	defer p.tunnelTracker.release(trackerKey)

	// Tag the identity with provider and tool info
	if provider != "" && identity != nil && identity.Provider == "" {
		identity.Provider = provider
		toolName, _ := ParseToolFromUA(r.Header.Get("User-Agent"))
		identity.Tool = toolName
		_ = p.authDB.UpdateAgentProvider(identity.AgentID, provider, toolName, domain)
	}

	subjectID, agentID, agentName := subjectFromIdentity(identity, "http-agent")

	// If tunnel tracker detected a child (had parent trace), link to parent
	if isNew && tunnelParentID != "" {
		parentAgentID = tunnelParentID
		// Child inherits the parent's trace
		if incomingTrace == nil {
			if parentIdentity := p.tunnelTracker.parentIdentity(trackerKey); parentIdentity != nil {
				incomingTrace = p.assignTrace(parentIdentity)
			}
		}
	}

	action := intercept.ClassifyHTTPAction("CONNECT", host, "")

	// Domain policy check
	verdict := intercept.EvaluateDomainPolicy(p.opts.Policy, host)
	if verdict == intercept.VerdictDeny {
		p.logAndDeny(w, domain, "CONNECT", action, host, "domain_policy")
		return
	}

	// Assign trace (reuses existing trace for this agent)
	tc := p.assignTrace(identity)
	var agentDepth int
	if incomingTrace != nil {
		agentDepth = incomingTrace.Depth + 1
		tc = &intercept.TraceContext{TraceID: incomingTrace.TraceID, Depth: agentDepth}
	}

	// Audit log the tunnel attempt
	riskScore := 15
	riskLevel := "low"
	p.logger.Log(audit.LogOpts{
		ServerName:    domain,
		Direction:     "request",
		Method:        "CONNECT",
		ToolName:      action,
		ArgumentsJSON: fmt.Sprintf(`{"host":"%s"}`, host),
		Verdict:       "allow",
		RiskScore:     &riskScore,
		RiskLevel:     &riskLevel,
		AgentID:       agentID,
		AgentName:     agentName,
		TraceID:       tc.TraceID,
		AgentDepth:    &agentDepth,
		ParentAgentID: parentAgentID,
	})
	if p.opts.OnEvent != nil {
		p.opts.OnEvent(EventInfo{
			Action:    action,
			Agent:     agentName,
			RiskScore: &riskScore,
			Blocked:   false,
			Timestamp: time.Now(),
		})
	}

	p.sessionTracker.Record(subjectID, action)

	// Get leaf cert for this hostname
	hostname := domain
	leafCert, err := p.certCache.GetOrCreate(hostname)
	if err != nil {
		qlog.Error("generate cert for %s: %v", hostname, err)
		http.Error(w, "cert generation failed", http.StatusBadGateway)
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		qlog.Error("hijack: %v", err)
		return
	}

	// Tell the client the tunnel is established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// TLS handshake with the client (using our generated cert)
	tlsClientConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
	})
	if err := tlsClientConn.Handshake(); err != nil {
		qlog.Error("client TLS handshake for %s: %v", hostname, err)
		clientConn.Close()
		return
	}

	// Connect to the real server via TLS
	targetAddr := host
	if !strings.Contains(targetAddr, ":") {
		targetAddr = targetAddr + ":443"
	}
	serverConn, err := tls.Dial("tcp", targetAddr, &tls.Config{
		ServerName: hostname,
	})
	if err != nil {
		qlog.Error("dial %s: %v", targetAddr, err)
		tlsClientConn.Close()
		return
	}

	// Serve HTTP on the decrypted connection — read requests, inspect, forward
	p.serveMITM(tlsClientConn, serverConn, identity, parentAgentID, incomingTrace, trackerKey)
}

// serveMITM reads HTTP requests from the decrypted client connection,
// inspects them, forwards to the real server, and returns responses.
// Identity and trace are resolved by handleConnect before this is called.
// parentAgentID and incomingTrace are from the CONNECT request's X-Quint-Trace header.
// trackerKey is the tunnel tracker key (ip:tool:provider) for model confirmation.
func (p *Proxy) serveMITM(clientConn, serverConn net.Conn, identity *auth.Identity, parentAgentID string, incomingTrace *intercept.TraceContext, trackerKey string) {
	defer clientConn.Close()
	defer serverConn.Close()

	// Unique ID for this tunnel — used to track model-divergence splits (max once per tunnel).
	tunnelID := uuid.New().String()[:8]

	// Register the CONNECT-level identity in the cookie store so it can be
	// recognized by cookie on subsequent requests within this tunnel.
	p.agentCookieStore.Register(identity)

	subjectID, agentID, agentName := subjectFromIdentity(identity, "http-agent")

	// Trace context — already resolved by handleConnect
	tc := p.assignTrace(identity)
	var agentDepth int
	if incomingTrace != nil {
		agentDepth = incomingTrace.Depth + 1
		tc = &intercept.TraceContext{TraceID: incomingTrace.TraceID, Depth: agentDepth}
		if identity != nil {
			p.traceMap.Store(tc.TraceID, identity.AgentID)
		}
	}

	// Record parent-child relationship once per tunnel
	if parentAgentID != "" && agentID != "" {
		confidence := 0.95
		spawnType := "direct"
		if identity != nil && identity.Source == "inferred_child" {
			confidence = 0.70
			spawnType = "inferred"
		}
		p.correlationEngine.AddContextSignal(parentAgentID, agentID, tc.TraceID, agentDepth)
		p.logger.RecordRelationship(parentAgentID, agentID, confidence, agentDepth, spawnType, "context")
		qlog.Info("trace: linked child %s → parent %s (depth=%d, trace=%s, spawn=%s)", agentID, parentAgentID, agentDepth, tc.TraceID, spawnType)
	}

	clientBuf := bufio.NewReader(clientConn)

	for {
		// Read one HTTP request from the client
		req, err := http.ReadRequest(clientBuf)
		if err != nil {
			return // Connection closed or error
		}

		// Cookie-based identity check: if the client sends our cookie,
		// use the stored identity (highest priority within MITM).
		if cookieAgentID := extractAgentCookie(req); cookieAgentID != "" {
			if cookieIdentity := p.agentCookieStore.Lookup(cookieAgentID); cookieIdentity != nil {
				identity = cookieIdentity
				subjectID, agentID, agentName = subjectFromIdentity(identity, "http-agent")
			}
		}

		// Strip proxy cookie before forwarding to upstream
		stripQuintCookie(req)

		host := req.Host
		domain := intercept.StripPort(host)
		action := intercept.ClassifyHTTPAction(req.Method, host, req.URL.Path)
		isLLM := isLLMProviderDomain(domain)

		// Read request body: for LLM provider domains, buffer the full body
		// so we can parse tool calls. For other domains, read a capped preview.
		maxBody := p.maxBodyLogSize()
		var bodyPreview string
		var llmBodyBytes []byte
		if req.Body != nil {
			if isLLM {
				// Buffer full body for LLM parsing — cap at 10MB to avoid OOM
				const maxLLMBody = 10 * 1024 * 1024
				llmBodyBytes, _ = io.ReadAll(io.LimitReader(req.Body, maxLLMBody))
				// Use the buffered body as the preview too (capped)
				if len(llmBodyBytes) > maxBody {
					bodyPreview = string(llmBodyBytes[:maxBody]) + "..."
				} else {
					bodyPreview = string(llmBodyBytes)
				}
				// Reconstruct body from buffer for forwarding
				req.Body = io.NopCloser(bytes.NewReader(llmBodyBytes))
			} else {
				previewBuf, _ := io.ReadAll(io.LimitReader(req.Body, int64(maxBody+1)))
				if len(previewBuf) > maxBody {
					bodyPreview = string(previewBuf[:maxBody]) + "..."
				} else {
					bodyPreview = string(previewBuf)
				}
				// Reconstruct full body: already-read preview + remaining (streamed)
				req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(previewBuf), req.Body))
			}
		}

		// Parse LLM tool calls from buffered body (read-only, does not modify traffic).
		if isLLM && len(llmBodyBytes) > 0 && p.opts.OnToolCall != nil {
			func() {
				defer func() {
					if r := recover(); r != nil {
						qlog.Error("llmparse panic for %s: %v", domain, r)
					}
				}()
				if result := llmparse.Parse(domain, llmBodyBytes, req.Header.Get("User-Agent")); result != nil {
					for _, evt := range result.Events {
						p.opts.OnToolCall(AgentToolEvent{
							EventID:   fmt.Sprintf("tool-%d", time.Now().UnixMilli()),
							Timestamp: evt.Timestamp,
							Provider:  evt.Provider,
							Model:     result.Model,
							Agent:     agentName,
							ToolName:  evt.ToolName,
							ToolArgs:  evt.ToolArgs,
							ToolResult: evt.ToolResult,
						})
					}
				}
			}()
		}

		// Classify unregistered agent on first event: detect provider from
		// the MITM domain and extract model from API request body.
		if identity != nil {
			if identity.Provider == "" {
				if provider := InferProvider(domain); provider != "" {
					identity.Provider = provider
					toolName, _ := ParseToolFromUA(req.Header.Get("User-Agent"))
					if toolName == "" {
						toolName = identity.Tool
					}
					identity.Tool = toolName
					_ = p.authDB.UpdateAgentProvider(identity.AgentID, provider, toolName, domain)
					qlog.Info("classified agent %s as provider=%s tool=%s from domain %s", agentName, provider, toolName, domain)
				}
			}
			if req.Method == "POST" && bodyPreview != "" {
				if model := ExtractModel(bodyPreview); model != "" {
					// Layer 1: Request-level sub-agent detection via model divergence.
					// If the model changes within a tunnel (e.g. Opus → Haiku),
					// split identity to a new child agent for the rest of this tunnel.
					result := p.tunnelTracker.detectModelSplit(trackerKey, tunnelID, model)
					if result.ShouldSplit {
						// Create child identity for the divergent model
						p.tunnelTracker.mu.Lock()
						state := p.tunnelTracker.ipState[trackerKey]
						if state != nil {
							state.childCount++
						}
						childCount := 0
						if state != nil {
							childCount = state.childCount
						}
						p.tunnelTracker.mu.Unlock()

						childIdentity := p.identityResolver.ResolveChild(result.ParentIdentity, childCount)
						if childIdentity != nil {
							// Switch to child identity for remainder of this tunnel
							identity = childIdentity
							identity.Model = model
							subjectID, agentID, agentName = subjectFromIdentity(identity, "http-agent")
							_ = p.authDB.UpdateAgentModel(identity.AgentID, model)
							p.agentCookieStore.Register(identity)

							// Assign trace and link to parent
							parentAgentID = result.ParentIdentity.AgentID
							agentDepth = 1
							parentTrace := p.assignTrace(result.ParentIdentity)
							tc = &intercept.TraceContext{TraceID: parentTrace.TraceID, Depth: agentDepth}
							p.traceMap.Store(tc.TraceID, identity.AgentID)

							// Record relationship
							p.correlationEngine.AddContextSignal(parentAgentID, agentID, tc.TraceID, agentDepth)
							p.logger.RecordRelationship(parentAgentID, agentID, 0.85, agentDepth, "model_divergence", "context")

							qlog.Info("tunnel: model split in %s — %s → child %s (parent_model=%s, child_model=%s)",
								trackerKey, result.ParentIdentity.AgentName, agentName, result.ParentModel, model)
						}
					} else if model != identity.Model {
						// No split — just update the model on the current identity
						identity.Model = model
						_ = p.authDB.UpdateAgentModel(identity.AgentID, model)
						qlog.Info("detected model %s for agent %s", model, agentName)
						// Confirm sub-agent detection via model divergence (concurrency spike path)
						p.tunnelTracker.confirmModel(trackerKey, identity.AgentID, model)
					}
				}
			}
		}

		// Risk scoring — only score on action pattern, not body content.
		// HTTP request bodies contain conversation text that triggers false
		// positives on keyword patterns designed for MCP tool args.
		score := p.riskEngine.ScoreToolCall(action, "", subjectID)
		riskAction := p.riskEngine.Evaluate(score.Value)
		riskScore := score.Value
		riskLevel := score.Level

		// Session tracking
		p.sessionTracker.Record(subjectID, action)

		// Audit log request
		argsJSON := buildRequestArgs(
			fmt.Sprintf("https://%s%s", host, req.URL.RequestURI()),
			req.Method, req.Header.Get("Content-Type"), bodyPreview, p.logBodies(),
		)
		p.logger.Log(audit.LogOpts{
			ServerName:    domain,
			Direction:     "request",
			Method:        req.Method,
			ToolName:      action,
			ArgumentsJSON: argsJSON,
			Verdict:       "allow",
			RiskScore:     &riskScore,
			RiskLevel:     &riskLevel,
			AgentID:       agentID,
			AgentName:     agentName,
			TraceID:       tc.TraceID,
			AgentDepth:    &agentDepth,
			ParentAgentID: parentAgentID,
		})
		// For LLM provider domains, tool call events are emitted via OnToolCall
		// above (from parsed request bodies). Skip OnEvent to avoid duplicate events.
		if !isLLM && p.opts.OnEvent != nil {
			p.opts.OnEvent(EventInfo{
				Action:    action,
				Agent:     agentName,
				RiskScore: &riskScore,
				Blocked:   riskAction == "deny",
				Timestamp: time.Now(),
			})
		}

		if riskAction == "deny" {
			// Send a 403 back to the client through the TLS connection
			resp := &http.Response{
				StatusCode: 403,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"blocked by quint proxy","reason":"risk_denied"}`)),
			}
			resp.Write(clientConn)
			continue
		}

		// Strip quint headers before forwarding to upstream
		req.Header.Del("X-Quint-Agent")
		req.Header.Del("X-Quint-Trace")

		// Forward request to real server (body streams through)
		if err := req.Write(serverConn); err != nil {
			qlog.Error("write to server %s: %v", host, err)
			return
		}

		// Read response from real server
		resp, err := http.ReadResponse(bufio.NewReader(serverConn), req)
		if err != nil {
			qlog.Error("read response from %s: %v", host, err)
			return
		}

		// Read response body preview
		var respBodyPreview string
		if p.logBodies() && resp.Body != nil {
			respBuf, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody+1)))
			if len(respBuf) > maxBody {
				respBodyPreview = string(respBuf[:maxBody]) + "..."
			} else {
				respBodyPreview = string(respBuf)
			}
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(respBuf), resp.Body))
		}

		// Inject trace header on response back to client so the process
		// can discover its trace ID and propagate to child processes.
		resp.Header.Set("X-Quint-Trace", tc.String())

		// Inject agent ID header so the client can propagate it
		if agentID != "" {
			resp.Header.Set("X-Quint-Agent", agentID)
		}

		// Inject agent cookie so the client sends it on subsequent requests
		injectAgentCookie(resp, agentID)

		// Forward response to client
		if err := resp.Write(clientConn); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		// Audit log response
		respJSON := buildResponseArgs(resp.StatusCode, resp.Header.Get("Content-Type"), respBodyPreview)
		p.logger.Log(audit.LogOpts{
			ServerName:    domain,
			Direction:     "response",
			Method:        req.Method,
			ToolName:      action,
			ResponseJSON:  respJSON,
			Verdict:       "passthrough",
			RiskScore:     &riskScore,
			RiskLevel:     &riskLevel,
			AgentID:       agentID,
			AgentName:     agentName,
			TraceID:       tc.TraceID,
			AgentDepth:    &agentDepth,
			ParentAgentID: parentAgentID,
		})

		if riskAction == "flag" {
			qlog.Warn("flagged HTTPS %s %s%s (risk=%d)", req.Method, host, req.URL.Path, score.Value)
		}

		qlog.Debug("MITM %s https://%s%s → %d (risk=%d)", req.Method, host, req.URL.Path, resp.StatusCode, score.Value)
	}
}

func (p *Proxy) logAndDeny(w http.ResponseWriter, domain, method, action, target, reason string) {
	riskScore := 0
	riskLevel := "blocked"
	p.logger.Log(audit.LogOpts{
		ServerName:    domain,
		Direction:     "request",
		Method:        method,
		ToolName:      action,
		ArgumentsJSON: fmt.Sprintf(`{"target":"%s","reason":"%s"}`, target, reason),
		Verdict:       "deny",
		RiskScore:     &riskScore,
		RiskLevel:     &riskLevel,
	})
	if p.opts.OnEvent != nil {
		p.opts.OnEvent(EventInfo{
			Action:    action,
			Agent:     "",
			RiskScore: &riskScore,
			Blocked:   true,
			Timestamp: time.Now(),
		})
	}
	qlog.Info("denied %s %s (%s)", method, target, reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(fmt.Sprintf(`{"error":"blocked by quint proxy","reason":"%s","target":"%s"}`, reason, target)))
}

func (p *Proxy) logBodies() bool {
	return p.opts.Policy.ForwardProxy != nil && p.opts.Policy.ForwardProxy.LogBodies
}

func (p *Proxy) maxBodyLogSize() int {
	if p.opts.Policy.ForwardProxy != nil {
		return p.opts.Policy.ForwardProxy.GetMaxBodyLogSize()
	}
	return 8192
}

func buildRequestArgs(url, method, contentType, bodyPreview string, logBody bool) string {
	m := map[string]any{
		"url":    url,
		"method": method,
	}
	if contentType != "" {
		m["content_type"] = contentType
	}
	if logBody && bodyPreview != "" {
		m["body_preview"] = bodyPreview
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func buildResponseArgs(statusCode int, contentType, bodyPreview string) string {
	m := map[string]any{
		"status": statusCode,
	}
	if contentType != "" {
		m["content_type"] = contentType
	}
	if bodyPreview != "" {
		m["body_preview"] = bodyPreview
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
