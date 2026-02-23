package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Canonicalize produces a canonical JSON string matching the TypeScript implementation:
// JSON.stringify(obj, Object.keys(obj).sort())
//
// Key requirements for cross-language compatibility:
// - Keys sorted alphabetically
// - null values encoded as null (not omitted)
// - Numbers formatted to match JS (no trailing .0 for integers)
// - Minimal string escaping matching JSON.stringify (no HTML escaping)
func Canonicalize(obj map[string]any) (string, error) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		keyJSON, err := marshalStringNoHTMLEscape(k)
		if err != nil {
			return "", fmt.Errorf("marshal key %q: %w", k, err)
		}
		b.Write(keyJSON)
		b.WriteByte(':')

		if err := writeValue(&b, obj[k]); err != nil {
			return "", fmt.Errorf("marshal value for key %q: %w", k, err)
		}
	}
	b.WriteByte('}')
	return b.String(), nil
}

func writeValue(b *strings.Builder, v any) error {
	if v == nil {
		b.WriteString("null")
		return nil
	}

	switch val := v.(type) {
	case string:
		j, err := marshalStringNoHTMLEscape(val)
		if err != nil {
			return err
		}
		b.Write(j)
	case float64:
		if val == math.Trunc(val) && !math.IsInf(val, 0) && !math.IsNaN(val) {
			fmt.Fprintf(b, "%d", int64(val))
		} else {
			j, err := json.Marshal(val)
			if err != nil {
				return err
			}
			b.Write(j)
		}
	case int:
		fmt.Fprintf(b, "%d", val)
	case int64:
		fmt.Fprintf(b, "%d", val)
	case bool:
		if val {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	default:
		j, err := json.Marshal(val)
		if err != nil {
			return err
		}
		b.Write(j)
	}
	return nil
}

// BuildSignableObject constructs the map to be canonicalized for signing.
// The proxy always includes risk_score and risk_level (even when null),
// which differs from quint-api's BuildSignableObject that conditionally omits them.
// agent_id and agent_name are included when provided (nil otherwise).
func BuildSignableObject(
	timestamp, serverName, direction, method string,
	messageID, toolName, argumentsJSON, responseJSON *string,
	verdict, policyHash, prevHash, nonce, publicKey string,
	riskScore *int, riskLevel *string,
	agentID, agentName *string,
) map[string]any {
	obj := map[string]any{
		"timestamp":      timestamp,
		"server_name":    serverName,
		"direction":      direction,
		"method":         method,
		"message_id":     ptrToAny(messageID),
		"tool_name":      ptrToAny(toolName),
		"arguments_json": ptrToAny(argumentsJSON),
		"response_json":  ptrToAny(responseJSON),
		"verdict":        verdict,
		"policy_hash":    policyHash,
		"prev_hash":      prevHash,
		"nonce":          nonce,
		"public_key":     publicKey,
		"risk_score":     ptrToAny(riskScore),
		"risk_level":     ptrToAny(riskLevel),
		"agent_id":       ptrToAny(agentID),
		"agent_name":     ptrToAny(agentName),
	}
	return obj
}

// marshalStringNoHTMLEscape encodes a string as JSON without escaping
// <, >, and & to \u003c, \u003e, \u0026. This matches JavaScript's
// JSON.stringify behavior.
func marshalStringNoHTMLEscape(s string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	return bytes.TrimRight(b, "\n"), nil
}

func ptrToAny[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}
