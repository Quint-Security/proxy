package stream

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
	"github.com/segmentio/kafka-go"
)

// Topics used by the proxy's Kafka producer.
const (
	TopicEventsRaw      = "agent.events.raw"
	TopicSpawnsDetected = "agent.spawns.detected"
	TopicRelationships  = "agent.relationships"
)

// ProducerConfig configures the Kafka producer.
type ProducerConfig struct {
	Brokers     []string `json:"brokers"`
	Enabled     bool     `json:"enabled"`
	Async       bool     `json:"async"`       // fire-and-forget (default true)
	BatchSize   int      `json:"batch_size"`   // messages per batch (default 100)
	BatchTimeMs int      `json:"batch_time_ms"` // batch flush interval ms (default 1000)
}

// Producer publishes events to Kafka topics asynchronously.
// Non-blocking: failures are logged but never block the proxy pipeline.
type Producer struct {
	writers map[string]*kafka.Writer
	config  ProducerConfig
	mu      sync.RWMutex
	closed  bool
	msgCh   chan pendingMessage
	wg      sync.WaitGroup
}

type pendingMessage struct {
	topic string
	key   string
	value []byte
}

// NewProducer creates a Kafka producer. Returns nil if config is nil or disabled.
func NewProducer(cfg *ProducerConfig) *Producer {
	if cfg == nil || !cfg.Enabled || len(cfg.Brokers) == 0 {
		return nil
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	batchTime := time.Duration(cfg.BatchTimeMs) * time.Millisecond
	if batchTime <= 0 {
		batchTime = 1 * time.Second
	}

	topics := []string{TopicEventsRaw, TopicSpawnsDetected, TopicRelationships}
	writers := make(map[string]*kafka.Writer, len(topics))

	for _, topic := range topics {
		w := &kafka.Writer{
			Addr:         kafka.TCP(cfg.Brokers...),
			Topic:        topic,
			Balancer:     &kafka.LeastBytes{},
			BatchSize:    batchSize,
			BatchTimeout: batchTime,
			Async:        cfg.Async,
			RequiredAcks: kafka.RequireOne,
			// Compression for efficiency
			Compression: kafka.Snappy,
		}
		writers[topic] = w
	}

	p := &Producer{
		writers: writers,
		config:  *cfg,
		msgCh:   make(chan pendingMessage, 10000), // buffer 10k messages
	}

	// Start background worker for async publishing
	p.wg.Add(1)
	go p.publishLoop()

	qlog.Info("kafka producer initialized: brokers=%v async=%v", cfg.Brokers, cfg.Async)
	return p
}

// PublishEvent publishes an agent event to the raw events topic.
// Non-blocking: queues the message for async delivery.
func (p *Producer) PublishEvent(key string, event any) {
	p.publish(TopicEventsRaw, key, event)
}

// PublishSpawn publishes a spawn detection event.
func (p *Producer) PublishSpawn(key string, event any) {
	p.publish(TopicSpawnsDetected, key, event)
}

// PublishRelationship publishes a relationship update.
func (p *Producer) PublishRelationship(key string, event any) {
	p.publish(TopicRelationships, key, event)
}

func (p *Producer) publish(topic, key string, event any) {
	if p == nil {
		return
	}

	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return
	}
	p.mu.RUnlock()

	data, err := json.Marshal(event)
	if err != nil {
		qlog.Error("kafka: failed to marshal event for %s: %v", topic, err)
		return
	}

	// Non-blocking send to channel
	select {
	case p.msgCh <- pendingMessage{topic: topic, key: key, value: data}:
	default:
		qlog.Warn("kafka: message channel full, dropping message for %s", topic)
	}
}

func (p *Producer) publishLoop() {
	defer p.wg.Done()

	for msg := range p.msgCh {
		writer, ok := p.writers[msg.topic]
		if !ok {
			qlog.Error("kafka: no writer for topic %s", msg.topic)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := writer.WriteMessages(ctx, kafka.Message{
			Key:   []byte(msg.key),
			Value: msg.value,
		})
		cancel()

		if err != nil {
			qlog.Warn("kafka: failed to publish to %s: %v", msg.topic, err)
		}
	}
}

// Close gracefully shuts down the producer.
func (p *Producer) Close() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()

	close(p.msgCh)
	p.wg.Wait()

	var lastErr error
	for topic, w := range p.writers {
		if err := w.Close(); err != nil {
			qlog.Error("kafka: failed to close writer for %s: %v", topic, err)
			lastErr = err
		}
	}
	return lastErr
}

// AgentEventMessage is the Kafka message format for agent.events.raw.
type AgentEventMessage struct {
	EventID         string         `json:"event_id"`
	Timestamp       string         `json:"timestamp"`
	AgentID         string         `json:"agent_id"`
	AgentName       string         `json:"agent_name,omitempty"`
	SessionID       string         `json:"session_id,omitempty"`
	ServerName      string         `json:"server_name"`
	ToolName        string         `json:"tool_name"`
	Action          string         `json:"action"`
	RiskScore       int            `json:"risk_score"`
	RiskLevel       string         `json:"risk_level"`
	Verdict         string         `json:"verdict"`
	TraceID         string         `json:"trace_id,omitempty"`
	Depth           int            `json:"depth"`
	ParentAgentID   string         `json:"parent_agent_id,omitempty"`
	Transport       string         `json:"transport"`
	ArgumentsHash   string         `json:"arguments_hash,omitempty"`
	ScoringSource   string         `json:"scoring_source,omitempty"`
	BehavioralFlags []string       `json:"behavioral_flags,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// SpawnEventMessage is the Kafka message format for agent.spawns.detected.
type SpawnEventMessage struct {
	EventID      string  `json:"event_id"`
	Timestamp    string  `json:"timestamp"`
	PatternID    string  `json:"pattern_id"`
	ParentAgent  string  `json:"parent_agent"`
	ChildHint    string  `json:"child_hint,omitempty"`
	SpawnType    string  `json:"spawn_type"`
	Confidence   float64 `json:"confidence"`
	ToolName     string  `json:"tool_name"`
	ServerName   string  `json:"server_name"`
	ArgumentsRef string  `json:"arguments_ref,omitempty"`
}

// RelationshipMessage is the Kafka message format for agent.relationships.
type RelationshipMessage struct {
	Timestamp   string  `json:"timestamp"`
	ParentAgent string  `json:"parent_agent"`
	ChildAgent  string  `json:"child_agent"`
	Confidence  float64 `json:"confidence"`
	Depth       int     `json:"depth"`
	SpawnType   string  `json:"spawn_type,omitempty"`
	SignalType  string  `json:"signal_type"`
	SignalCount int     `json:"signal_count"`
}
