package risk

import (
	"context"
	"fmt"
	"os"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const grpcTimeout = 100 * time.Millisecond

// GRPCClient is an optional remote risk scoring client.
// When configured (via QUINT_RISK_SERVICE_URL), it calls an external ML service
// to enhance the local risk score. Falls back to local scoring on any failure.
//
// The service must implement quint.v1.RiskService (see proto/quint/v1/risk.proto).
// Without protoc-generated stubs, the client dials the server but cannot make typed
// RPC calls — it will log the connection and fall back to local scoring.
// To enable full gRPC support:
//  1. Run: protoc --go_out=. --go-grpc_out=. proto/quint/v1/risk.proto
//  2. Update this file to use the generated client stub.
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

// EnhanceScore calls the remote service and returns an enhanced score.
// Falls back to localScore on any failure (connection error, timeout, no stubs).
func (c *GRPCClient) EnhanceScore(localScore Score, toolName, argsJSON, subjectID, serverName string) Score {
	if err := c.connect(); err != nil {
		qlog.Debug("risk service connect failed, using local score: %v", err)
		return localScore
	}

	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	// Invoke the RPC using raw bytes. This requires the server to accept
	// the raw wire format. Without generated proto stubs, we serialize manually.
	//
	// Proto field layout for ScoreToolCallRequest:
	//   1: tool_name (string)
	//   2: arguments_json (string)
	//   3: subject_id (string)
	//   4: server_name (string)
	//   5: local_score (int32)
	//   6: local_level (string)
	reqBytes := encodeScoreRequest(toolName, argsJSON, subjectID, serverName, int32(localScore.Value), localScore.Level)
	respBytes := &rawMessage{}

	err := c.conn.Invoke(ctx, "/quint.v1.RiskService/ScoreToolCall", &rawMessage{data: reqBytes}, respBytes,
		grpc.ForceCodec(rawCodec{}))
	if err != nil {
		qlog.Debug("risk service call failed, using local score: %v", err)
		return localScore
	}

	score, level, reasons, enhanced := decodeScoreResponse(respBytes.data)
	if !enhanced {
		return localScore
	}

	qlog.Debug("risk service enhanced score: %d → %d (%s)", localScore.Value, score, level)
	return Score{
		Value:         int(score),
		BaseScore:     localScore.BaseScore,
		ArgBoost:      localScore.ArgBoost,
		BehaviorBoost: localScore.BehaviorBoost,
		Level:         level,
		Reasons:       append(localScore.Reasons, reasons...),
	}
}

// Close closes the gRPC connection.
func (c *GRPCClient) Close() {
	if c.conn != nil {
		c.conn.Close()
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

// encodeScoreRequest manually encodes a ScoreToolCallRequest in protobuf wire format.
func encodeScoreRequest(toolName, argsJSON, subjectID, serverName string, localScore int32, localLevel string) []byte {
	var buf []byte
	buf = appendString(buf, 1, toolName)
	buf = appendString(buf, 2, argsJSON)
	buf = appendString(buf, 3, subjectID)
	buf = appendString(buf, 4, serverName)
	buf = appendVarint(buf, 5, uint64(localScore))
	buf = appendString(buf, 6, localLevel)
	return buf
}

// decodeScoreResponse manually decodes a ScoreToolCallResponse from protobuf wire format.
func decodeScoreResponse(data []byte) (score int32, level string, reasons []string, enhanced bool) {
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}
		tag := uint64(0)
		shift := uint(0)
		for i < len(data) {
			b := data[i]
			i++
			tag |= uint64(b&0x7f) << shift
			if b < 0x80 {
				break
			}
			shift += 7
		}
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // varint
			val := uint64(0)
			shift := uint(0)
			for i < len(data) {
				b := data[i]
				i++
				val |= uint64(b&0x7f) << shift
				if b < 0x80 {
					break
				}
				shift += 7
			}
			switch fieldNum {
			case 1:
				score = int32(val)
			case 4:
				enhanced = val != 0
			}
		case 2: // length-delimited
			length := uint64(0)
			shift := uint(0)
			for i < len(data) {
				b := data[i]
				i++
				length |= uint64(b&0x7f) << shift
				if b < 0x80 {
					break
				}
				shift += 7
			}
			end := i + int(length)
			if end > len(data) {
				return
			}
			s := string(data[i:end])
			i = end
			switch fieldNum {
			case 2:
				level = s
			case 3:
				reasons = append(reasons, s)
			}
		default:
			return // unknown wire type
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
