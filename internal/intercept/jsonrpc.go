package intercept

import "encoding/json"

// JsonRpcRequest represents a JSON-RPC 2.0 request.
type JsonRpcRequest struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// McpToolCallParams represents the params of a tools/call request.
type McpToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ParseJsonRpc attempts to parse a line as a JSON-RPC 2.0 message.
// Returns nil if the line is not valid JSON or not a JSON-RPC message.
func ParseJsonRpc(line string) (*JsonRpcRequest, json.RawMessage) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, nil
	}

	// Check for jsonrpc field
	var jsonrpc string
	if v, ok := raw["jsonrpc"]; ok {
		if err := json.Unmarshal(v, &jsonrpc); err != nil || jsonrpc != "2.0" {
			return nil, nil
		}
	} else {
		return nil, nil
	}

	// Must have method to be a request (vs response)
	var method string
	if v, ok := raw["method"]; ok {
		if err := json.Unmarshal(v, &method); err != nil {
			return nil, nil
		}
	} else {
		// It's a response (has result or error), not a request
		id, _ := raw["id"]
		return nil, id
	}

	req := &JsonRpcRequest{
		Jsonrpc: jsonrpc,
		Method:  method,
	}
	if v, ok := raw["id"]; ok {
		req.ID = v
	}
	if v, ok := raw["params"]; ok {
		req.Params = v
	}

	return req, nil
}

// IsToolCall returns true if the request is a tools/call.
func IsToolCall(req *JsonRpcRequest) bool {
	return req != nil && req.Method == "tools/call"
}

// ExtractToolInfo extracts the tool name and arguments from a tools/call request.
// Returns ("", nil) if not a tools/call or params are invalid.
func ExtractToolInfo(req *JsonRpcRequest) (name string, args map[string]interface{}) {
	if !IsToolCall(req) || req.Params == nil {
		return "", nil
	}

	var params McpToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
		return "", nil
	}
	if params.Arguments == nil {
		params.Arguments = map[string]interface{}{}
	}
	return params.Name, params.Arguments
}

// IDString extracts the id as a string from a JSON-RPC message.
// Returns "" if id is null or absent.
func IDString(raw json.RawMessage) string {
	if raw == nil || string(raw) == "null" {
		return ""
	}
	// Try string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Try number
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return string(raw)
}
