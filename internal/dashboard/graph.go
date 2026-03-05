package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
)

// AgentGraphNode matches the frontend AgentGraphNode type.
type AgentGraphNode struct {
	ID        string              `json:"id"`
	AgentID   string              `json:"agentId"`
	AgentName string              `json:"agentName"`
	Type      string              `json:"type"`     // orchestrator, worker, tool, evaluator, router
	Status    string              `json:"status"`   // running, completed, failed, waiting
	ParentID  *string             `json:"parentId"` // null for root
	Metadata  AgentNodeMetadata   `json:"metadata"`
}

// AgentNodeMetadata matches the frontend metadata shape.
type AgentNodeMetadata struct {
	Model       string `json:"model,omitempty"`
	Tool        string `json:"tool,omitempty"`
	StartedAt   string `json:"startedAt"`
	CompletedAt string `json:"completedAt,omitempty"`
	Duration    *int   `json:"duration,omitempty"`
	Error       string `json:"error,omitempty"`
}

// AgentGraph matches the frontend AgentGraph type.
type AgentGraph struct {
	ID            string           `json:"id"`
	RootAgentID   string           `json:"rootAgentId"`
	RootAgentName string           `json:"rootAgentName"`
	Nodes         []AgentGraphNode `json:"nodes"`
	Status        string           `json:"status"` // running, completed, failed
	StartedAt     string           `json:"startedAt"`
	CompletedAt   string           `json:"completedAt,omitempty"`
	TotalNodes    int              `json:"totalNodes"`
	Metadata      AgentGraphMeta   `json:"metadata"`
}

// AgentGraphMeta matches the frontend metadata shape.
type AgentGraphMeta struct {
	Trigger    string `json:"trigger,omitempty"`
	PipelineID string `json:"pipelineId,omitempty"`
}

// AgentNodeEvent matches the frontend AgentNodeEvent type.
type AgentNodeEvent struct {
	ID        string         `json:"id"`
	GraphID   string         `json:"graphId"`
	NodeID    string         `json:"nodeId"`
	AgentID   string         `json:"agentId"`
	EventType string         `json:"eventType"` // tool_call, decision, delegation, completion, error, scoring
	Timestamp string         `json:"timestamp"`
	Data      map[string]any `json:"data"`
	RiskScore *int           `json:"riskScore,omitempty"`
	Verdict   string         `json:"verdict,omitempty"`
}

// buildAgentGraphs constructs AgentGraph objects from audit entries and relationships.
// Each distinct root agent (no parent or depth 0) becomes a separate graph.
func buildAgentGraphs(entries []audit.Entry, relationships []audit.AgentRelationshipRow) []AgentGraph {
	// Group entries by root agent. An agent is a root if it has no parent_agent_id,
	// or if its parent doesn't appear in the entry set.
	type agentInfo struct {
		id       string
		name     string
		parentID string
		depth    int
		entries  []audit.Entry
		firstTS  string
		lastTS   string
	}

	agents := make(map[string]*agentInfo) // keyed by agent_id

	for _, e := range entries {
		aid := derefOr(e.AgentID, "")
		if aid == "" {
			continue
		}
		aname := derefOr(e.AgentName, aid)
		parentID := derefOr(e.ParentAgentID, "")
		depth := 0
		if e.AgentDepth != nil {
			depth = *e.AgentDepth
		}

		info, ok := agents[aid]
		if !ok {
			info = &agentInfo{
				id:       aid,
				name:     aname,
				parentID: parentID,
				depth:    depth,
				firstTS:  e.Timestamp,
			}
			agents[aid] = info
		}
		info.lastTS = e.Timestamp
		// Update parent if we see it in a later entry
		if parentID != "" && info.parentID == "" {
			info.parentID = parentID
		}

		// Only collect MCP tool calls for graph nodes — HTTP requests
		// are shown in the HTTP stream graph and would create excessive noise.
		toolName := derefOr(e.ToolName, "")
		if toolName != "" && !strings.HasPrefix(toolName, "http:") {
			info.entries = append(info.entries, e)
		}
	}

	// Also pull parent info from relationships table
	for _, r := range relationships {
		if child, ok := agents[r.ChildAgent]; ok {
			if child.parentID == "" {
				child.parentID = r.ParentAgent
			}
			if child.depth == 0 && r.Depth > 0 {
				child.depth = r.Depth
			}
		}
		// Ensure parent agent exists in the map even if it has no tool calls
		if _, ok := agents[r.ParentAgent]; !ok {
			agents[r.ParentAgent] = &agentInfo{
				id:      r.ParentAgent,
				name:    r.ParentAgent,
				firstTS: r.FirstSeen,
				lastTS:  r.LastSeen,
			}
		}
	}

	// Find root agents (no parent or parent not in our set)
	rootAgents := map[string]bool{}
	for aid, info := range agents {
		if info.parentID == "" || agents[info.parentID] == nil {
			rootAgents[aid] = true
		}
	}
	// If no roots, make every agent a root
	if len(rootAgents) == 0 {
		for aid := range agents {
			rootAgents[aid] = true
		}
	}

	// Resolve the root for any agent by walking up the parent chain
	rootOf := func(aid string) string {
		visited := map[string]bool{}
		cur := aid
		for {
			if rootAgents[cur] {
				return cur
			}
			info := agents[cur]
			if info == nil || info.parentID == "" || visited[cur] {
				return cur
			}
			visited[cur] = true
			cur = info.parentID
		}
	}

	// Group agents by their root
	graphAgents := map[string][]string{} // rootID → [agent IDs in this graph]
	for aid := range agents {
		root := rootOf(aid)
		graphAgents[root] = append(graphAgents[root], aid)
	}

	// Build one AgentGraph per root
	var graphs []AgentGraph
	for rootID, memberIDs := range graphAgents {
		rootInfo := agents[rootID]
		if rootInfo == nil {
			continue
		}

		graphID := stableHash(rootID)
		var nodes []AgentGraphNode
		var allEntries []audit.Entry
		var graphFirstTS, graphLastTS string
		hasFailure := false

		for _, aid := range memberIDs {
			info := agents[aid]
			if info == nil {
				continue
			}
			allEntries = append(allEntries, info.entries...)

			// Track graph-level timestamps
			if graphFirstTS == "" || info.firstTS < graphFirstTS {
				graphFirstTS = info.firstTS
			}
			if info.lastTS > graphLastTS {
				graphLastTS = info.lastTS
			}

			// Agent node: root agents are orchestrators, children are workers
			var parentPtr *string
			nodeType := "orchestrator"
			if aid != rootID {
				nodeType = "worker"
				if info.parentID != "" {
					pid := stableNodeID(graphID, info.parentID)
					parentPtr = &pid
				}
			}

			agentNodeID := stableNodeID(graphID, aid)
			nodes = append(nodes, AgentGraphNode{
				ID:        agentNodeID,
				AgentID:   info.id,
				AgentName: info.name,
				Type:      nodeType,
				Status:    "completed",
				ParentID:  parentPtr,
				Metadata: AgentNodeMetadata{
					StartedAt:   info.firstTS,
					CompletedAt: info.lastTS,
				},
			})

			// Tool call nodes under this agent.
			// Only include MCP tool calls — HTTP requests (http:*) are shown
			// in the HTTP stream graph and would create excessive noise here.
			for _, e := range info.entries {
				toolName := derefOr(e.ToolName, "")
				if toolName == "" || strings.HasPrefix(toolName, "http:") {
					continue
				}

				toolNodeID := stableNodeID(graphID, fmt.Sprintf("tool-%d", e.ID))
				callParent := agentNodeID

				nt := inferNodeType(toolName, e.Verdict)
				status := "completed"
				if e.Verdict == "deny" || e.Verdict == "scope_denied" || e.Verdict == "flag_denied" {
					status = "failed"
					hasFailure = true
				}

				var dur *int
				// Compute duration from timestamp if we have start/end
				meta := AgentNodeMetadata{
					Tool:        fmt.Sprintf("%s.%s", e.ServerName, toolName),
					StartedAt:   e.Timestamp,
					CompletedAt: e.Timestamp,
					Duration:    dur,
				}
				if status == "failed" {
					meta.Error = fmt.Sprintf("%s: %s", e.Verdict, toolName)
				}

				nodes = append(nodes, AgentGraphNode{
					ID:        toolNodeID,
					AgentID:   info.id,
					AgentName: info.name,
					Type:      nt,
					Status:    status,
					ParentID:  &callParent,
					Metadata:  meta,
				})
			}
		}

		graphStatus := "completed"
		if hasFailure {
			graphStatus = "failed"
		}

		graphs = append(graphs, AgentGraph{
			ID:            graphID,
			RootAgentID:   rootInfo.id,
			RootAgentName: rootInfo.name,
			Nodes:         nodes,
			Status:        graphStatus,
			StartedAt:     graphFirstTS,
			CompletedAt:   graphLastTS,
			TotalNodes:    len(nodes),
			Metadata:      AgentGraphMeta{Trigger: "mcp"},
		})
	}

	// Sort by startedAt descending (newest first)
	sort.Slice(graphs, func(i, j int) bool {
		return graphs[i].StartedAt > graphs[j].StartedAt
	})

	return graphs
}

// inferNodeType maps a tool call to an AgentGraphNode type.
func inferNodeType(toolName, verdict string) string {
	lower := strings.ToLower(toolName)
	switch {
	case strings.Contains(lower, "create_agent") || strings.Contains(lower, "spawn"):
		return "router" // delegation / spawn
	case strings.Contains(lower, "execute") || strings.Contains(lower, "command") || strings.Contains(lower, "shell"):
		return "tool"
	case strings.Contains(lower, "read") || strings.Contains(lower, "list") || strings.Contains(lower, "get"):
		return "evaluator" // read/observe
	case strings.Contains(lower, "write") || strings.Contains(lower, "create") || strings.Contains(lower, "delete"):
		return "worker" // mutation
	default:
		return "tool"
	}
}

func stableHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func stableNodeID(graphID, seed string) string {
	h := sha256.Sum256([]byte(graphID + ":" + seed))
	return hex.EncodeToString(h[:8])
}

func derefOr(s *string, fallback string) string {
	if s != nil && *s != "" {
		return *s
	}
	return fallback
}

// nodeEventsForAgent returns audit entries for a given agent formatted as AgentNodeEvents.
func nodeEventsForAgent(entries []audit.Entry, agentName string) []AgentNodeEvent {
	var events []AgentNodeEvent
	for _, e := range entries {
		aname := derefOr(e.AgentName, "")
		if aname != agentName {
			continue
		}
		toolName := derefOr(e.ToolName, "")
		if toolName == "" {
			continue
		}

		evType := "tool_call"
		if e.SpawnDetected != nil && *e.SpawnDetected != "" {
			evType = "delegation"
		} else if e.Verdict == "deny" || e.Verdict == "scope_denied" || e.Verdict == "flag_denied" {
			evType = "decision"
		}

		data := map[string]any{
			"server_name": e.ServerName,
			"tool_name":   toolName,
			"method":      e.Method,
		}
		if e.RiskLevel != nil {
			data["risk_level"] = *e.RiskLevel
		}

		ev := AgentNodeEvent{
			ID:        fmt.Sprintf("evt-%d", e.ID),
			GraphID:   "", // filled by caller
			NodeID:    "", // filled by caller
			AgentID:   derefOr(e.AgentID, ""),
			EventType: evType,
			Timestamp: e.Timestamp,
			Data:      data,
			Verdict:   e.Verdict,
		}
		if e.RiskScore != nil {
			ev.RiskScore = e.RiskScore
		}
		events = append(events, ev)
	}
	return events
}

// diffGraphs returns which graphs are new or updated compared to previous state.
func diffGraphs(oldGraphs, newGraphs []AgentGraph) (added []AgentGraph, updated []AgentGraph) {
	oldMap := make(map[string]AgentGraph, len(oldGraphs))
	for _, g := range oldGraphs {
		oldMap[g.ID] = g
	}

	for _, g := range newGraphs {
		prev, exists := oldMap[g.ID]
		if !exists {
			added = append(added, g)
		} else if prev.TotalNodes != g.TotalNodes || prev.Status != g.Status ||
			prev.CompletedAt != g.CompletedAt {
			updated = append(updated, g)
		}
	}
	return
}

// graphLastTimestamp returns the latest timestamp in the audit data used to build graphs.
func graphLastTimestamp(entries []audit.Entry) time.Time {
	var latest time.Time
	for _, e := range entries {
		if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
			if t.After(latest) {
				latest = t
			}
		}
		// Also try the millisecond format used in the codebase
		if t, err := time.Parse("2006-01-02T15:04:05.000Z", e.Timestamp); err == nil {
			if t.After(latest) {
				latest = t
			}
		}
	}
	return latest
}

// --- HTTP Traffic Stream Graphs ---

// HTTPStreamGraph represents a real-time graph of HTTP traffic flowing through the forward proxy.
type HTTPStreamGraph struct {
	ID        string           `json:"id"`
	Type      string           `json:"type"`   // always "http_stream"
	Status    string           `json:"status"` // "active"
	StartedAt string           `json:"startedAt"`
	UpdatedAt string           `json:"updatedAt"`
	Domains   []HTTPDomainNode `json:"domains"`
	Stats     HTTPStreamStats  `json:"stats"`
}

// HTTPDomainNode is a domain endpoint in the HTTP stream graph.
type HTTPDomainNode struct {
	ID           string            `json:"id"`
	Domain       string            `json:"domain"`
	RequestCount int               `json:"requestCount"`
	LastSeen     string            `json:"lastSeen"`
	RiskMax      int               `json:"riskMax"`
	RiskAvg      float64           `json:"riskAvg"`
	Methods      map[string]int    `json:"methods"` // GET: 5, POST: 2, etc.
	Requests     []HTTPRequestNode `json:"requests"`
}

// HTTPRequestNode is a single HTTP request in the stream graph.
type HTTPRequestNode struct {
	ID          string `json:"id"`
	Action      string `json:"action"` // http:domain:method.slug
	Method      string `json:"method"`
	URL         string `json:"url,omitempty"`
	Timestamp   string `json:"timestamp"`
	RiskScore   int    `json:"riskScore"`
	RiskLevel   string `json:"riskLevel"`
	Verdict     string `json:"verdict"`
	StatusCode  int    `json:"statusCode,omitempty"`
	BodyPreview string `json:"bodyPreview,omitempty"`
}

// HTTPStreamStats aggregates traffic statistics.
type HTTPStreamStats struct {
	TotalRequests    int            `json:"totalRequests"`
	TotalDomains     int            `json:"totalDomains"`
	Denied           int            `json:"denied"`
	Flagged          int            `json:"flagged"`
	MethodCounts     map[string]int `json:"methodCounts"`
	RiskDistribution map[string]int `json:"riskDistribution"` // low, medium, high, critical
}

// HTTPStreamEvent is an SSE event for real-time HTTP traffic streaming.
type HTTPStreamEvent struct {
	Type        string `json:"type"` // http_request, http_response, http_denied
	Timestamp   string `json:"timestamp"`
	Domain      string `json:"domain"`
	Action      string `json:"action"`
	Method      string `json:"method"`
	URL         string `json:"url,omitempty"`
	RiskScore   int    `json:"riskScore"`
	RiskLevel   string `json:"riskLevel"`
	Verdict     string `json:"verdict"`
	StatusCode  int    `json:"statusCode,omitempty"`
	BodyPreview string `json:"bodyPreview,omitempty"`
}

// buildHTTPStreamGraph creates a domain-centric graph from HTTP audit entries.
func buildHTTPStreamGraph(entries []audit.Entry) *HTTPStreamGraph {
	// Filter to HTTP request entries only
	var httpEntries []audit.Entry
	for _, e := range entries {
		tn := derefOr(e.ToolName, "")
		if strings.HasPrefix(tn, "http:") && e.Direction == "request" {
			httpEntries = append(httpEntries, e)
		}
	}

	if len(httpEntries) == 0 {
		return nil
	}

	// Group by domain
	type domainData struct {
		entries []audit.Entry
		methods map[string]int
		riskSum int
		riskMax int
		firstTS string
		lastTS  string
	}
	domains := make(map[string]*domainData)

	stats := HTTPStreamStats{
		MethodCounts:     make(map[string]int),
		RiskDistribution: make(map[string]int),
	}

	var graphFirstTS, graphLastTS string

	for _, e := range httpEntries {
		domain := e.ServerName
		dd, ok := domains[domain]
		if !ok {
			dd = &domainData{methods: make(map[string]int), firstTS: e.Timestamp}
			domains[domain] = dd
		}
		dd.entries = append(dd.entries, e)
		dd.methods[e.Method]++
		dd.lastTS = e.Timestamp

		rs := 0
		if e.RiskScore != nil {
			rs = *e.RiskScore
		}
		dd.riskSum += rs
		if rs > dd.riskMax {
			dd.riskMax = rs
		}

		if graphFirstTS == "" || e.Timestamp < graphFirstTS {
			graphFirstTS = e.Timestamp
		}
		if e.Timestamp > graphLastTS {
			graphLastTS = e.Timestamp
		}

		stats.TotalRequests++
		stats.MethodCounts[e.Method]++
		rl := derefOr(e.RiskLevel, "low")
		stats.RiskDistribution[rl]++
		if e.Verdict == "deny" {
			stats.Denied++
		}
		if rl == "high" || rl == "critical" {
			stats.Flagged++
		}
	}

	stats.TotalDomains = len(domains)

	// Build domain nodes
	var domainNodes []HTTPDomainNode
	for domain, dd := range domains {
		var requests []HTTPRequestNode
		// Keep last 50 requests per domain
		start := 0
		if len(dd.entries) > 50 {
			start = len(dd.entries) - 50
		}
		for _, e := range dd.entries[start:] {
			tn := derefOr(e.ToolName, "")
			rs := 0
			if e.RiskScore != nil {
				rs = *e.RiskScore
			}
			rl := derefOr(e.RiskLevel, "low")

			rn := HTTPRequestNode{
				ID:        fmt.Sprintf("req-%d", e.ID),
				Action:    tn,
				Method:    e.Method,
				Timestamp: e.Timestamp,
				RiskScore: rs,
				RiskLevel: rl,
				Verdict:   e.Verdict,
			}

			if e.ArgumentsJSON != nil {
				var args map[string]any
				if json.Unmarshal([]byte(*e.ArgumentsJSON), &args) == nil {
					if u, ok := args["url"].(string); ok {
						rn.URL = u
					}
					if bp, ok := args["body_preview"].(string); ok {
						if len(bp) > 200 {
							rn.BodyPreview = bp[:200] + "..."
						} else {
							rn.BodyPreview = bp
						}
					}
				}
			}

			requests = append(requests, rn)
		}

		avg := 0.0
		if len(dd.entries) > 0 {
			avg = float64(dd.riskSum) / float64(len(dd.entries))
		}

		domainNodes = append(domainNodes, HTTPDomainNode{
			ID:           stableHash("http-domain:" + domain),
			Domain:       domain,
			RequestCount: len(dd.entries),
			LastSeen:     dd.lastTS,
			RiskMax:      dd.riskMax,
			RiskAvg:      avg,
			Methods:      dd.methods,
			Requests:     requests,
		})
	}

	// Sort domains by request count descending
	sort.Slice(domainNodes, func(i, j int) bool {
		return domainNodes[i].RequestCount > domainNodes[j].RequestCount
	})

	return &HTTPStreamGraph{
		ID:        "http-stream",
		Type:      "http_stream",
		Status:    "active",
		StartedAt: graphFirstTS,
		UpdatedAt: graphLastTS,
		Domains:   domainNodes,
		Stats:     stats,
	}
}

// entryToHTTPStreamEvent converts an audit entry to an SSE-friendly event.
func entryToHTTPStreamEvent(e audit.Entry) *HTTPStreamEvent {
	tn := derefOr(e.ToolName, "")
	if !strings.HasPrefix(tn, "http:") {
		return nil
	}

	rs := 0
	if e.RiskScore != nil {
		rs = *e.RiskScore
	}
	rl := derefOr(e.RiskLevel, "low")

	evType := "http_request"
	if e.Direction == "response" {
		evType = "http_response"
	}
	if e.Verdict == "deny" {
		evType = "http_denied"
	}

	ev := &HTTPStreamEvent{
		Type:      evType,
		Timestamp: e.Timestamp,
		Domain:    e.ServerName,
		Action:    tn,
		Method:    e.Method,
		RiskScore: rs,
		RiskLevel: rl,
		Verdict:   e.Verdict,
	}

	if e.ArgumentsJSON != nil {
		var args map[string]any
		if json.Unmarshal([]byte(*e.ArgumentsJSON), &args) == nil {
			if u, ok := args["url"].(string); ok {
				ev.URL = u
			}
			if bp, ok := args["body_preview"].(string); ok {
				if len(bp) > 200 {
					ev.BodyPreview = bp[:200] + "..."
				} else {
					ev.BodyPreview = bp
				}
			}
		}
	}

	if e.Direction == "response" && e.ResponseJSON != nil {
		var resp map[string]any
		if json.Unmarshal([]byte(*e.ResponseJSON), &resp) == nil {
			if sc, ok := resp["status"].(float64); ok {
				ev.StatusCode = int(sc)
			}
		}
	}

	return ev
}
