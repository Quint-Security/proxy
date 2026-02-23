// TinkerLabs Risk Service — gRPC ML risk scoring server.
//
// This is the server that quint-proxy calls when QUINT_RISK_SERVICE_URL is set.
// It receives a tool call with the proxy's local risk score, applies ML-based
// enhancements (sensitive path detection, exfiltration patterns, privilege
// escalation), and returns an enhanced score.
//
// Usage:
//
//	quint-riskservice [--port 50051]
//
// On the proxy side:
//
//	QUINT_RISK_SERVICE_URL=localhost:50051 quint-proxy --name srv -- cmd args...
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"google.golang.org/grpc"
)

var version = "dev"

func main() {
	port := flag.Int("port", 50051, "gRPC listen port")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}))

	// Register service — HandlerType must be an interface pointer
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "quint.v1.RiskService",
		HandlerType: (*RiskServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "ScoreToolCall",
				Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					var req rawMsg
					if err := dec(&req); err != nil {
						return nil, err
					}
					resp := srv.(RiskServiceServer).ScoreToolCall(req.data)
					return &rawMsg{data: resp}, nil
				},
			},
		},
	}, &riskServer{})

	log.Printf("TinkerLabs Risk Service listening on :%d", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// RiskServiceServer is the interface gRPC needs for service registration.
type RiskServiceServer interface {
	ScoreToolCall(reqData []byte) []byte
}

type riskServer struct{}

func (s *riskServer) ScoreToolCall(reqData []byte) []byte {
	toolName, argsJSON, subjectID, serverName, localScore, localLevel := decodeRequest(reqData)

	log.Printf("scoring: tool=%s server=%s subject=%s local=%d/%s",
		toolName, serverName, subjectID, localScore, localLevel)

	score := localScore
	level := localLevel
	var reasons []string
	enhanced := false

	argsLower := strings.ToLower(argsJSON)

	// Sensitive path detection
	for _, sp := range []string{"/etc/", "/root/", "/var/log/", ".ssh/", ".aws/", ".kube/"} {
		if strings.Contains(argsLower, sp) {
			score += 15
			reasons = append(reasons, fmt.Sprintf("ML: sensitive path detected (%s)", sp))
			enhanced = true
		}
	}

	// Credential read pattern
	if strings.Contains(strings.ToLower(toolName), "read") &&
		(strings.Contains(argsLower, "token") || strings.Contains(argsLower, "key") || strings.Contains(argsLower, "secret")) {
		score += 10
		reasons = append(reasons, "ML: potential credential read")
		enhanced = true
	}

	// Privilege escalation
	if strings.Contains(argsLower, "chmod 777") || strings.Contains(argsLower, "chmod +s") {
		score += 20
		reasons = append(reasons, "ML: privilege escalation pattern")
		enhanced = true
	}

	// Cap and recompute level
	if score > 100 {
		score = 100
	}
	switch {
	case score >= 85:
		level = "critical"
	case score >= 60:
		level = "high"
	case score >= 30:
		level = "medium"
	default:
		level = "low"
	}

	if enhanced {
		log.Printf("enhanced: %d → %d (%s) %v", localScore, score, level, reasons)
	}

	return encodeResponse(int32(score), level, reasons, enhanced)
}

// --- Raw codec (matches proxy client) ---

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	if m, ok := v.(*rawMsg); ok {
		return m.data, nil
	}
	return nil, fmt.Errorf("rawCodec: expected *rawMsg, got %T", v)
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	if m, ok := v.(*rawMsg); ok {
		m.data = data
		return nil
	}
	return fmt.Errorf("rawCodec: expected *rawMsg, got %T", v)
}

func (rawCodec) Name() string { return "raw" }

type rawMsg struct{ data []byte }

// --- Proto encoding/decoding ---

func decodeRequest(data []byte) (toolName, argsJSON, subjectID, serverName string, localScore int32, localLevel string) {
	i := 0
	for i < len(data) {
		tag, n := decodeUvarint(data[i:])
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0:
			val, n := decodeUvarint(data[i:])
			i += n
			if fieldNum == 5 {
				localScore = int32(val)
			}
		case 2:
			length, n := decodeUvarint(data[i:])
			i += n
			end := i + int(length)
			if end > len(data) {
				return
			}
			s := string(data[i:end])
			i = end
			switch fieldNum {
			case 1:
				toolName = s
			case 2:
				argsJSON = s
			case 3:
				subjectID = s
			case 4:
				serverName = s
			case 6:
				localLevel = s
			}
		default:
			return
		}
	}
	return
}

func decodeUvarint(data []byte) (uint64, int) {
	val := uint64(0)
	shift := uint(0)
	for i := 0; i < len(data); i++ {
		b := data[i]
		val |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return val, i + 1
		}
		shift += 7
	}
	return val, len(data)
}

func encodeResponse(score int32, level string, reasons []string, enhanced bool) []byte {
	var buf []byte
	if score != 0 {
		buf = appendTag(buf, 1, 0)
		buf = appendUvarint(buf, uint64(score))
	}
	buf = appendString(buf, 2, level)
	for _, r := range reasons {
		buf = appendString(buf, 3, r)
	}
	if enhanced {
		buf = appendTag(buf, 4, 0)
		buf = appendUvarint(buf, 1)
	}
	return buf
}

func appendString(buf []byte, fieldNum int, s string) []byte {
	if s == "" {
		return buf
	}
	buf = appendTag(buf, fieldNum, 2)
	buf = appendUvarint(buf, uint64(len(s)))
	return append(buf, s...)
}

func appendTag(buf []byte, fieldNum int, wireType int) []byte {
	return appendUvarint(buf, uint64(fieldNum<<3|wireType))
}

func appendUvarint(buf []byte, val uint64) []byte {
	for val >= 0x80 {
		buf = append(buf, byte(val)|0x80)
		val >>= 7
	}
	return append(buf, byte(val))
}
