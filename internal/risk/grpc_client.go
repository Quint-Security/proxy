package risk

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const grpcTimeout = 100 * time.Millisecond

// GRPCClient is an optional remote risk scoring client.
// When configured (via QUINT_RISK_SERVICE_URL), it calls the risk-engine's
// RiskEvaluationService to get ML-enhanced risk scores. Falls back to local
// scoring on any failure.
//
// The remote service implements quint.v1.RiskEvaluationService
// (see proto/quint/v1/risk_evaluation.proto).
//
// Without protoc-generated Go stubs, the client uses raw proto wire encoding
// and the gRPC raw codec to communicate. This matches the wire format produced
// by the Python risk-engine's generated protobuf code.
//
// To enable full typed gRPC support:
//  1. Install protoc + protoc-gen-go + protoc-gen-go-grpc
//  2. Run: protoc --go_out=gen --go-grpc_out=gen proto/quint/v1/risk_evaluation.proto
//  3. Update this file to use the generated client stub.
type GRPCClient struct {
	conn *grpc.ClientConn
	addr string
}

// NewGRPCClient creates a new gRPC risk service client.
// Returns nil if QUINT_RISK_SERVICE_URL is not set.
func NewGRPCClient() *GRPCClient {
	addr := os.Getenv("QUINT_RISK_SERVICE_URL")
	if addr == "" {
		return nil
	}
	qlog.Info("gRPC risk service configured: %s", addr)
	return &GRPCClient{addr: addr}
}

// connect establishes the gRPC connection lazily.
func (c *GRPCClient) connect() error {
	if c.conn != nil {
		return nil
	}
	conn, err := grpc.NewClient(c.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("grpc dial %s: %w", c.addr, err)
	}
	c.conn = conn
	qlog.Info("connected to risk service at %s", c.addr)
	return nil
}

// EnhanceScore calls the remote RiskEvaluationService and returns an enhanced score.
// Falls back to localScore on any failure (connection error, timeout, service down).
//
// Wire mapping to EvaluateRiskRequest:
//
//	Field 1 (ActionContext):
//	  1: tool_name (string)
//	  2: tool_input (string) — JSON-encoded arguments
//	  3: resource (string) — server_name used as resource
//	  4: user_id (string) — subject_id
//	Field 2 (request_id): left empty (no correlation needed for inline scoring)
//
// Wire mapping from EvaluateRiskResponse:
//
//	Field 1 (RiskAssessment):
//	  1: level (RiskLevel enum/varint)
//	  2: confidence (float)
//	  3: reasoning (string)
//	  4: mitigations (repeated string)
//	Field 2 (request_id): ignored
func (c *GRPCClient) EnhanceScore(localScore Score, toolName, argsJSON, subjectID, serverName string) Score {
	if err := c.connect(); err != nil {
		qlog.Debug("risk service connect failed, using local score: %v", err)
		return localScore
	}

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	reqBytes := encodeEvaluateRiskRequest(toolName, argsJSON, serverName, subjectID)
	respBytes := &rawMessage{}

	err := c.conn.Invoke(ctx, "/quint.v1.RiskEvaluationService/EvaluateRisk", &rawMessage{data: reqBytes}, respBytes,
		grpc.ForceCodec(rawCodec{}))
	if err != nil {
		qlog.Debug("risk service call failed, using local score: %v", err)
		return localScore
	}

	level, confidence, reasoning, mitigations := decodeEvaluateRiskResponse(respBytes.data)
	if level == 0 {
		// RISK_LEVEL_UNSPECIFIED — remote didn't produce a useful result
		return localScore
	}

	levelStr := riskLevelToString(level)
	score := riskLevelToScore(level)

	qlog.Debug("risk service enhanced score: %d → %d (%s, confidence=%.2f, reasoning=%s)",
		localScore.Value, score, levelStr, confidence, reasoning)

	reasons := localScore.Reasons
	if reasoning != "" {
		reasons = append(reasons, reasoning)
	}
	reasons = append(reasons, mitigations...)

	return Score{
		Value:         score,
		BaseScore:     localScore.BaseScore,
		ArgBoost:      localScore.ArgBoost,
		BehaviorBoost: localScore.BehaviorBoost,
		Level:         levelStr,
		Reasons:       reasons,
	}
}

// Close closes the gRPC connection.
func (c *GRPCClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// riskLevelToString converts the proto enum value to a string.
func riskLevelToString(level int32) string {
	switch level {
	case 1:
		return "none"
	case 2:
		return "low"
	case 3:
		return "medium"
	case 4:
		return "high"
	case 5:
		return "critical"
	default:
		return "unknown"
	}
}

// riskLevelToScore maps RiskLevel enum to a 0-100 numeric score.
func riskLevelToScore(level int32) int {
	switch level {
	case 1: // NONE
		return 0
	case 2: // LOW
		return 25
	case 3: // MEDIUM
		return 50
	case 4: // HIGH
		return 75
	case 5: // CRITICAL
		return 95
	default:
		return 50
	}
}

// rawCodec is a gRPC codec that passes raw bytes without protobuf marshaling.
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	msg, ok := v.(*rawMessage)
	if !ok {
		return nil, fmt.Errorf("rawCodec: expected *rawMessage, got %T", v)
	}
	return msg.data, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	msg, ok := v.(*rawMessage)
	if !ok {
		return fmt.Errorf("rawCodec: expected *rawMessage, got %T", v)
	}
	msg.data = data
	return nil
}

func (rawCodec) Name() string { return "raw" }

type rawMessage struct {
	data []byte
}

// encodeEvaluateRiskRequest encodes an EvaluateRiskRequest in protobuf wire format.
//
// EvaluateRiskRequest {
//
//	context: ActionContext (field 1, embedded message)
//	request_id: string (field 2) — omitted
//
// }
func encodeEvaluateRiskRequest(toolName, toolInput, resource, userID string) []byte {
	// First encode the inner ActionContext message
	var inner []byte
	inner = appendString(inner, 1, toolName)
	inner = appendString(inner, 2, toolInput)
	inner = appendString(inner, 3, resource)
	inner = appendString(inner, 4, userID)
	// Note: policies (field 5) not sent — proxy doesn't track active policy names here

	// Wrap it as field 1 (length-delimited) of EvaluateRiskRequest
	var outer []byte
	outer = appendBytes(outer, 1, inner)
	return outer
}

// decodeEvaluateRiskResponse decodes an EvaluateRiskResponse from protobuf wire format.
// Returns the RiskAssessment fields: level, confidence, reasoning, mitigations.
func decodeEvaluateRiskResponse(data []byte) (level int32, confidence float32, reasoning string, mitigations []string) {
	i := 0
	for i < len(data) {
		tag, newI := decodeVarint(data, i)
		if newI == i {
			break
		}
		i = newI
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // varint — skip at top level
			_, i = decodeVarint(data, i)
		case 2: // length-delimited
			length, newI := decodeVarint(data, i)
			i = newI
			end := i + int(length)
			if end > len(data) {
				return
			}
			if fieldNum == 1 {
				// This is the RiskAssessment sub-message
				level, confidence, reasoning, mitigations = decodeRiskAssessment(data[i:end])
			}
			// fieldNum 2 = request_id, ignored
			i = end
		default:
			return // unknown wire type
		}
	}
	return
}

// decodeRiskAssessment decodes a RiskAssessment from protobuf wire format.
func decodeRiskAssessment(data []byte) (level int32, confidence float32, reasoning string, mitigations []string) {
	i := 0
	for i < len(data) {
		tag, newI := decodeVarint(data, i)
		if newI == i {
			break
		}
		i = newI
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // varint
			val, newI := decodeVarint(data, i)
			i = newI
			if fieldNum == 1 {
				level = int32(val)
			}
		case 5: // 32-bit (float)
			if i+4 > len(data) {
				return
			}
			if fieldNum == 2 {
				bits := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
				confidence = float32FromBits(bits)
			}
			i += 4
		case 2: // length-delimited
			length, newI := decodeVarint(data, i)
			i = newI
			end := i + int(length)
			if end > len(data) {
				return
			}
			s := string(data[i:end])
			i = end
			switch fieldNum {
			case 3:
				reasoning = s
			case 4:
				mitigations = append(mitigations, s)
			case 5:
				// justification — treat as additional reasoning
				if reasoning == "" {
					reasoning = s
				} else {
					reasoning = reasoning + "; " + s
				}
			}
		default:
			return
		}
	}
	return
}

// Proto encoding helpers

func appendString(buf []byte, fieldNum int, s string) []byte {
	if s == "" {
		return buf
	}
	buf = appendTag(buf, fieldNum, 2) // wire type 2 = length-delimited
	buf = appendUvarint(buf, uint64(len(s)))
	buf = append(buf, s...)
	return buf
}

func appendBytes(buf []byte, fieldNum int, b []byte) []byte {
	if len(b) == 0 {
		return buf
	}
	buf = appendTag(buf, fieldNum, 2) // wire type 2 = length-delimited
	buf = appendUvarint(buf, uint64(len(b)))
	buf = append(buf, b...)
	return buf
}

func appendVarint(buf []byte, fieldNum int, val uint64) []byte {
	if val == 0 {
		return buf
	}
	buf = appendTag(buf, fieldNum, 0) // wire type 0 = varint
	buf = appendUvarint(buf, val)
	return buf
}

func appendTag(buf []byte, fieldNum int, wireType int) []byte {
	return appendUvarint(buf, uint64(fieldNum<<3|wireType))
}

func appendUvarint(buf []byte, val uint64) []byte {
	for val >= 0x80 {
		buf = append(buf, byte(val)|0x80)
		val >>= 7
	}
	buf = append(buf, byte(val))
	return buf
}

// decodeVarint reads a varint from data starting at position i.
// Returns the value and the new position.
func decodeVarint(data []byte, i int) (uint64, int) {
	val := uint64(0)
	shift := uint(0)
	for i < len(data) {
		b := data[i]
		i++
		val |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return val, i
		}
		shift += 7
	}
	return val, i
}

// float32FromBits converts IEEE 754 bits to float32.
func float32FromBits(bits uint32) float32 {
	return math.Float32frombits(bits)
}
