package intercept

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// TraceContext represents the X-Quint-Trace header value.
// Format: {trace_id}.{depth}
type TraceContext struct {
	TraceID string `json:"trace_id"`
	Depth   int    `json:"depth"`
}

// ParseTraceHeader parses an X-Quint-Trace header value.
// Format: "{trace_id}.{depth}" e.g. "abc123.2"
// Returns nil if the header is empty or malformed.
func ParseTraceHeader(header string) *TraceContext {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}

	// Find last dot for depth separator
	lastDot := strings.LastIndex(header, ".")
	if lastDot < 0 || lastDot == len(header)-1 {
		// No depth specified, assume depth 0
		return &TraceContext{TraceID: header, Depth: 0}
	}

	traceID := header[:lastDot]
	depthStr := header[lastDot+1:]

	depth, err := strconv.Atoi(depthStr)
	if err != nil {
		return &TraceContext{TraceID: header, Depth: 0}
	}

	return &TraceContext{TraceID: traceID, Depth: depth}
}

// String formats the trace context as a header value.
func (tc *TraceContext) String() string {
	return fmt.Sprintf("%s.%d", tc.TraceID, tc.Depth)
}

// Child returns a new trace context for a child agent (depth + 1).
func (tc *TraceContext) Child() *TraceContext {
	return &TraceContext{
		TraceID: tc.TraceID,
		Depth:   tc.Depth + 1,
	}
}

// NewTraceContext creates a new root trace context.
func NewTraceContext() *TraceContext {
	return &TraceContext{
		TraceID: uuid.New().String(),
		Depth:   0,
	}
}

// ExtractQuintField extracts the _quint metadata field from JSON-RPC params.
// This is the in-band alternative to the X-Quint-Trace header for stdio mode.
// Returns nil if no _quint field is present.
func ExtractQuintField(paramsJSON json.RawMessage) *TraceContext {
	if paramsJSON == nil {
		return nil
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return nil
	}

	quintRaw, ok := params["_quint"]
	if !ok {
		return nil
	}

	var quintField struct {
		TraceID string `json:"trace_id"`
		Depth   int    `json:"depth"`
	}
	if err := json.Unmarshal(quintRaw, &quintField); err != nil {
		// Try as string format "trace_id.depth"
		var s string
		if err := json.Unmarshal(quintRaw, &s); err == nil {
			return ParseTraceHeader(s)
		}
		return nil
	}

	if quintField.TraceID == "" {
		return nil
	}

	return &TraceContext{
		TraceID: quintField.TraceID,
		Depth:   quintField.Depth,
	}
}

// QuintAuth holds in-band authentication data from the _quint field in initialize params.
type QuintAuth struct {
	APIKey      string `json:"api_key,omitempty"`
	Token       string `json:"token,omitempty"`
	AgentName   string `json:"agent_name,omitempty"`
	SpawnTicket string `json:"spawn_ticket,omitempty"`
}

// ExtractQuintAuth extracts authentication data from the _quint field in JSON-RPC params.
// Returns nil if no _quint field or no auth data is present.
func ExtractQuintAuth(paramsJSON json.RawMessage) *QuintAuth {
	if paramsJSON == nil {
		return nil
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return nil
	}
	quintRaw, ok := params["_quint"]
	if !ok {
		return nil
	}
	var qa QuintAuth
	if err := json.Unmarshal(quintRaw, &qa); err != nil {
		return nil
	}
	if qa.APIKey == "" && qa.Token == "" && qa.AgentName == "" && qa.SpawnTicket == "" {
		return nil
	}
	return &qa
}

// InjectQuintField adds or updates the _quint field in JSON-RPC params.
// Returns the modified params JSON.
func InjectQuintField(paramsJSON json.RawMessage, tc *TraceContext) json.RawMessage {
	if tc == nil {
		return paramsJSON
	}

	var params map[string]json.RawMessage
	if paramsJSON == nil {
		params = make(map[string]json.RawMessage)
	} else if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return paramsJSON
	}

	quintValue, _ := json.Marshal(map[string]any{
		"trace_id": tc.TraceID,
		"depth":    tc.Depth,
	})
	params["_quint"] = quintValue

	result, err := json.Marshal(params)
	if err != nil {
		return paramsJSON
	}
	return result
}

// InjectSpawnTicket merges a spawn_ticket into the _quint object in tool call arguments.
// If _quint already exists, spawn_ticket is added to it; otherwise a new _quint object is created.
func InjectSpawnTicket(paramsJSON json.RawMessage, ticket string) json.RawMessage {
	if ticket == "" {
		return paramsJSON
	}

	var params map[string]json.RawMessage
	if paramsJSON == nil {
		params = make(map[string]json.RawMessage)
	} else if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return paramsJSON
	}

	// Merge into existing _quint object or create new one
	quintData := make(map[string]any)
	if existing, ok := params["_quint"]; ok {
		json.Unmarshal(existing, &quintData)
	}
	quintData["spawn_ticket"] = ticket

	quintJSON, err := json.Marshal(quintData)
	if err != nil {
		return paramsJSON
	}
	params["_quint"] = quintJSON

	result, err := json.Marshal(params)
	if err != nil {
		return paramsJSON
	}
	return result
}
