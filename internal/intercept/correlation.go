package intercept

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// SignalType identifies the detection method that produced a relationship signal.
type SignalType string

const (
	SignalSpawn     SignalType = "spawn"     // Pattern-matched tool call (confidence ~0.85)
	SignalContext   SignalType = "context"   // X-Quint-Trace header or _quint field (confidence ~0.95)
	SignalTemporal  SignalType = "temporal"  // Timing-based correlation (confidence ~0.50)
	SignalSignature SignalType = "signature" // HMAC-verified spawn ticket (confidence 1.0)
)

// RelationshipSignal is a single observation that two agents may be related.
type RelationshipSignal struct {
	Type        SignalType `json:"type"`
	ParentAgent string     `json:"parent_agent"`
	ChildAgent  string     `json:"child_agent"`
	Confidence  float64    `json:"confidence"`
	Source      string     `json:"source"` // pattern ID, header name, or "temporal"
	Timestamp   time.Time  `json:"timestamp"`
}

// AgentRelationship represents a confirmed or suspected parent-child relationship.
type AgentRelationship struct {
	ParentAgent string    `json:"parent_agent"`
	ChildAgent  string    `json:"child_agent"`
	Confidence  float64   `json:"confidence"`    // merged confidence 0.0-1.0
	Depth       int       `json:"depth"`         // tree depth (root=0)
	SpawnType   string    `json:"spawn_type"`    // "direct", "delegation", "fork"
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	SignalCount int       `json:"signal_count"`  // number of corroborating signals
}

// CorrelationEngine merges signals from spawn detection, context threads,
// and temporal analysis to maintain the agent relationship graph.
type CorrelationEngine struct {
	mu            sync.RWMutex
	relationships map[string]*AgentRelationship // key: "parent:child"
	depths        map[string]int                // agentID → tree depth
}

// NewCorrelationEngine creates a new correlation engine.
func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		relationships: make(map[string]*AgentRelationship),
		depths:        make(map[string]int),
	}
}

// AddSignal processes a new relationship signal, creating or updating the relationship.
func (ce *CorrelationEngine) AddSignal(signal RelationshipSignal) *AgentRelationship {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	key := relationshipKey(signal.ParentAgent, signal.ChildAgent)
	rel, exists := ce.relationships[key]

	if !exists {
		parentDepth := ce.depths[signal.ParentAgent] // 0 if root/unknown
		rel = &AgentRelationship{
			ParentAgent: signal.ParentAgent,
			ChildAgent:  signal.ChildAgent,
			Confidence:  signal.Confidence,
			Depth:       parentDepth + 1,
			FirstSeen:   signal.Timestamp,
			LastSeen:    signal.Timestamp,
			SignalCount: 1,
		}
		ce.relationships[key] = rel
		ce.depths[signal.ChildAgent] = rel.Depth
	} else {
		// Merge: take max confidence, update timestamps
		rel.Confidence = mergeConfidence(rel.Confidence, signal.Confidence)
		rel.LastSeen = signal.Timestamp
		rel.SignalCount++
	}

	return rel
}

// AddSpawnEvent converts a SpawnEvent into a signal and processes it.
func (ce *CorrelationEngine) AddSpawnEvent(event *SpawnEvent) *AgentRelationship {
	if event == nil {
		return nil
	}

	childAgent := event.ChildHint
	if childAgent == "" {
		childAgent = fmt.Sprintf("unknown:%s:%s", event.ServerName, event.ToolName)
	}

	signal := RelationshipSignal{
		Type:        SignalSpawn,
		ParentAgent: event.ParentAgent,
		ChildAgent:  childAgent,
		Confidence:  event.Confidence,
		Source:      event.PatternID,
		Timestamp:   event.DetectedAt,
	}

	rel := ce.AddSignal(signal)
	if rel != nil && event.SpawnType != "" {
		ce.mu.Lock()
		rel.SpawnType = event.SpawnType
		ce.mu.Unlock()
	}
	return rel
}

// AddContextSignal processes an X-Quint-Trace context thread signal.
func (ce *CorrelationEngine) AddContextSignal(parentAgent, childAgent, traceID string, depth int) *AgentRelationship {
	signal := RelationshipSignal{
		Type:        SignalContext,
		ParentAgent: parentAgent,
		ChildAgent:  childAgent,
		Confidence:  0.95, // context thread is high confidence
		Source:      "X-Quint-Trace:" + traceID,
		Timestamp:   time.Now(),
	}

	rel := ce.AddSignal(signal)
	if rel != nil && depth > 0 {
		ce.mu.Lock()
		rel.Depth = depth
		ce.depths[childAgent] = depth
		ce.mu.Unlock()
	}
	return rel
}

// AddSignatureSignal processes an HMAC-verified spawn ticket signal (confidence 1.0).
func (ce *CorrelationEngine) AddSignatureSignal(parentAgent, childAgent, traceID string, depth int, spawnType string) *AgentRelationship {
	signal := RelationshipSignal{
		Type:        SignalSignature,
		ParentAgent: parentAgent,
		ChildAgent:  childAgent,
		Confidence:  1.0, // HMAC-verified — deterministic
		Source:      "spawn_ticket:" + traceID,
		Timestamp:   time.Now(),
	}

	rel := ce.AddSignal(signal)
	if rel != nil {
		ce.mu.Lock()
		rel.Depth = depth
		ce.depths[childAgent] = depth
		if spawnType != "" {
			rel.SpawnType = spawnType
		}
		ce.mu.Unlock()
	}
	return rel
}

// GetDepth returns the tree depth for an agent (0 if root or unknown).
func (ce *CorrelationEngine) GetDepth(agentID string) int {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.depths[agentID]
}

// GetParent returns the parent relationship for an agent, or nil if root.
func (ce *CorrelationEngine) GetParent(agentID string) *AgentRelationship {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	for _, rel := range ce.relationships {
		if rel.ChildAgent == agentID {
			return rel
		}
	}
	return nil
}

// GetChildren returns all child relationships for an agent.
func (ce *CorrelationEngine) GetChildren(agentID string) []*AgentRelationship {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	var children []*AgentRelationship
	for _, rel := range ce.relationships {
		if rel.ParentAgent == agentID {
			children = append(children, rel)
		}
	}
	return children
}

// GetRelationship returns the relationship between two agents, if any.
func (ce *CorrelationEngine) GetRelationship(parentAgent, childAgent string) *AgentRelationship {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.relationships[relationshipKey(parentAgent, childAgent)]
}

// AllRelationships returns a snapshot of all tracked relationships.
func (ce *CorrelationEngine) AllRelationships() []AgentRelationship {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	result := make([]AgentRelationship, 0, len(ce.relationships))
	for _, rel := range ce.relationships {
		result = append(result, *rel)
	}
	return result
}

// mergeConfidence combines two confidence values using max (simple but effective).
// Multiple corroborating signals boost confidence slightly via diminishing returns.
func mergeConfidence(existing, new float64) float64 {
	// Take max as base, then slightly boost for corroboration
	base := math.Max(existing, new)
	// Diminishing returns: each corroborating signal adds less
	boost := (1.0 - base) * 0.1
	result := base + boost
	if result > 1.0 {
		result = 1.0
	}
	return result
}

func relationshipKey(parent, child string) string {
	return parent + "→" + child
}
