package intercept

import "encoding/json"

// InspectionResult is the result of inspecting a JSON-RPC line.
type InspectionResult struct {
	// RawID is the JSON-RPC id as raw JSON (preserved for deny responses).
	RawID json.RawMessage
	// Verdict is the policy verdict.
	Verdict Verdict
	// ToolName is the extracted tool name (for tools/call requests), or "".
	ToolName string
	// ArgumentsJson is the JSON-encoded arguments, or "".
	ArgumentsJson string
	// Method is the JSON-RPC method, or "unknown".
	Method string
	// MessageID is the string form of the JSON-RPC id, or "".
	MessageID string
}

// InspectRequest parses a line as JSON-RPC and determines the policy verdict.
// Non-parseable lines or non-tools/call methods get "passthrough".
func InspectRequest(line string, serverName string, policy PolicyConfig) InspectionResult {
	req, respID := ParseJsonRpc(line)

	if req == nil {
		// Either not JSON, or a JSON-RPC response
		return InspectionResult{
			RawID:   respID,
			Verdict: VerdictPassthrough,
			Method:  "unknown",
			MessageID: func() string {
				if respID != nil {
					return IDString(respID)
				}
				return ""
			}(),
		}
	}

	toolName, args := ExtractToolInfo(req)
	var argsJSON string
	if args != nil {
		b, _ := json.Marshal(args)
		argsJSON = string(b)
	}

	var verdict Verdict
	if IsToolCall(req) {
		verdict = EvaluatePolicy(policy, serverName, toolName)
	} else {
		verdict = VerdictPassthrough
	}

	return InspectionResult{
		RawID:         req.ID,
		Verdict:       verdict,
		ToolName:      toolName,
		ArgumentsJson: argsJSON,
		Method:        req.Method,
		MessageID:     IDString(req.ID),
	}
}

// InspectResponse parses a response line from the child for logging.
func InspectResponse(line string) (method string, messageID string, responseJson string) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return "unknown", "", ""
	}

	id := ""
	if v, ok := raw["id"]; ok {
		id = IDString(v)
	}

	return "response", id, line
}

// BuildDenyResponse creates a JSON-RPC error response for a denied tool call.
func BuildDenyResponse(rawID json.RawMessage) string {
	idPart := "null"
	if rawID != nil && len(rawID) > 0 {
		idPart = string(rawID)
	}

	resp := `{"jsonrpc":"2.0","id":` + idPart + `,"error":{"code":-32600,"message":"Quint: tool call denied by policy"}}`
	return resp
}
