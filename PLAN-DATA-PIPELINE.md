# Data Pipeline Optimization Plan: Path to Millions RPS

## Current State Analysis

### Architecture
```
Agent → Proxy (hot path) → [3 parallel outputs]
  1. Kafka (async, non-blocking) → Dashboard/Analytics
  2. Audit DB (sync, blocking) → Compliance/Tamper-proof log
  3. Remote Scoring API (sync, blocking, 15s timeout) → Risk enrichment
```

### Current Bottlenecks (ranked by severity)

| # | Bottleneck | Impact | Current Config |
|---|-----------|--------|----------------|
| 1 | **Single Kafka publish loop** | 1 goroutine drains 10k channel, writes one message at a time | `publishLoop()` calls `WriteMessages` with 1 msg per iteration |
| 2 | **Audit DB is synchronous** | Every tool call blocks on SQLite INSERT + Ed25519 signing + SHA256 chain-link | Single-row transaction per entry |
| 3 | **Remote scoring on hot path** | Blocking HTTP POST per tool call, default 15s timeout | `http.Client{Timeout: 15s}`, default `MaxIdleConnsPerHost=2` |
| 4 | **JSON serialization everywhere** | 3-4 `json.Marshal` calls per tool call (Kafka event, spawn, audit, remote) | stdlib `encoding/json` with reflection |
| 5 | **No request coalescing** | Identical tool calls each trigger separate remote scoring requests | No dedup |
| 6 | **No circuit breaker** | Remote API failures block for full timeout duration | Falls back on error, but only after waiting |

### Throughput Estimates (current)
- **Kafka**: ~1,000-5,000 msgs/sec (single goroutine, one-at-a-time writes)
- **Audit DB**: ~100-500 inserts/sec (single-row transactions, WAL mode)
- **Remote scoring**: ~50-200 req/sec (blocking HTTP, 2 idle conns per host)
- **Overall proxy**: Bottlenecked by whichever output is slowest on the hot path

---

## Phase 1: Quick Wins (1-2 days, no new dependencies)

### 1.1 Fix HTTP Client for Remote Scoring
**File: `internal/risk/remote.go`**

The default Go HTTP client uses `MaxIdleConnsPerHost=2`, which is a known performance killer.

```go
// Before (line 64):
client: &http.Client{Timeout: cfg.GetTimeout()}

// After:
client: &http.Client{
    Timeout: cfg.GetTimeout(),
    Transport: &http.Transport{
        MaxIdleConns:        200,
        MaxIdleConnsPerHost: 100,
        MaxConnsPerHost:     100,
        IdleConnTimeout:     60 * time.Second,
        ForceAttemptHTTP2:   true,
        TLSHandshakeTimeout: 5 * time.Second,
        ResponseHeaderTimeout: 3 * time.Second,
    },
}
```

**Expected impact**: p99 latency from ~80ms to ~6ms for remote scoring calls.

### 1.2 Reduce Remote Scoring Timeout
**File: `internal/risk/remote.go`**

Change default from 15s to 3s (already has `TimeoutMs` config, just change default):

```go
func (c RemoteConfig) GetTimeout() time.Duration {
    if c.TimeoutMs > 0 {
        return time.Duration(c.TimeoutMs) * time.Millisecond
    }
    return 3 * time.Second // was 15s
}
```

### 1.3 Batch Kafka Writes in publishLoop
**File: `internal/stream/producer.go`**

Current: reads 1 message at a time from channel, writes 1 message.
Fix: drain up to batch size from channel, write as batch.

```go
func (p *Producer) publishLoop() {
    defer p.wg.Done()
    batch := make(map[string][]kafka.Message) // topic → messages
    ticker := time.NewTicker(50 * time.Millisecond)
    defer ticker.Stop()

    flush := func() {
        for topic, msgs := range batch {
            if len(msgs) == 0 { continue }
            writer := p.writers[topic]
            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
            if err := writer.WriteMessages(ctx, msgs...); err != nil {
                qlog.Warn("kafka: batch write to %s failed (%d msgs): %v", topic, len(msgs), err)
            }
            cancel()
            batch[topic] = msgs[:0] // reuse slice
        }
    }

    for {
        select {
        case msg, ok := <-p.msgCh:
            if !ok { flush(); return }
            batch[msg.topic] = append(batch[msg.topic], kafka.Message{
                Key: []byte(msg.key), Value: msg.value,
            })
            // Drain up to batch size without blocking
            for i := 0; i < 99; i++ {
                select {
                case m, ok := <-p.msgCh:
                    if !ok { flush(); return }
                    batch[m.topic] = append(batch[m.topic], kafka.Message{
                        Key: []byte(m.key), Value: m.value,
                    })
                default:
                    goto flushBatch
                }
            }
            flushBatch:
                flush()
        case <-ticker.C:
            flush()
        }
    }
}
```

**Expected impact**: 10-50x Kafka throughput (batch writes amortize network round-trips).

### 1.4 Batch Audit DB Inserts
**File: `internal/audit/logger.go`**

Move audit logging off the hot path with a buffered channel + batch writer.

```go
type Logger struct {
    db         *DB
    privateKey string
    publicKey  string
    policyHash string
    logCh      chan LogOpts     // buffered intake channel
    wg         sync.WaitGroup
}

func NewLogger(...) *Logger {
    l := &Logger{..., logCh: make(chan LogOpts, 10000)}
    l.wg.Add(1)
    go l.batchWriteLoop()
    return l
}

func (l *Logger) Log(opts LogOpts) {
    select {
    case l.logCh <- opts:
    default:
        qlog.Warn("audit: log channel full, dropping entry")
    }
}

func (l *Logger) batchWriteLoop() {
    defer l.wg.Done()
    batch := make([]LogOpts, 0, 100)
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case opts, ok := <-l.logCh:
            if !ok { l.flushBatch(batch); return }
            batch = append(batch, opts)
            if len(batch) >= 100 { l.flushBatch(batch); batch = batch[:0] }
        case <-ticker.C:
            if len(batch) > 0 { l.flushBatch(batch); batch = batch[:0] }
        }
    }
}

func (l *Logger) flushBatch(batch []LogOpts) {
    // Single transaction for entire batch
    // Chain-linking: compute prev_hash from last entry in batch
    // Sign each entry within the transaction
}
```

**Expected impact**: 10-50x audit write throughput. Hot path becomes non-blocking.

**Caveat**: Chain-linked signing must still be sequential within each batch. The batch transaction ensures atomicity.

---

## Phase 2: Request Coalescing & Circuit Breaking (2-3 days)

### 2.1 Singleflight for Remote Scoring
**File: `internal/risk/remote.go`**

Deduplicate concurrent identical scoring requests:

```go
import "golang.org/x/sync/singleflight"

type RemoteScorer struct {
    config RemoteConfig
    client *http.Client
    sf     singleflight.Group
}

func (r *RemoteScorer) EnhanceScore(localScore Score, ...) Score {
    // Coalescing key: tool + args hash (same tool+args = same risk)
    key := fmt.Sprintf("%s:%s:%s", serverName, toolName, hashArgs(argsJSON))

    result, _, _ := r.sf.Do(key, func() (any, error) {
        return r.doEnhanceScore(localScore, toolName, argsJSON, subjectID, serverName, ctx)
    })
    return result.(Score)
}
```

**Expected impact**: ~95% reduction in duplicate remote API calls under burst load.

### 2.2 Circuit Breaker for Remote Scoring
**File: `internal/risk/remote.go`**

```go
import "github.com/sony/gobreaker"

type RemoteScorer struct {
    config RemoteConfig
    client *http.Client
    sf     singleflight.Group
    cb     *gobreaker.CircuitBreaker
}

func NewRemoteScorer(cfg *RemoteConfig) *RemoteScorer {
    cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
        Name:        "remote-scoring",
        MaxRequests: 3,                    // half-open: allow 3 test requests
        Interval:    30 * time.Second,     // closed-state counter reset
        Timeout:     10 * time.Second,     // open → half-open transition
        ReadyToTrip: func(counts gobreaker.Counts) bool {
            return counts.ConsecutiveFailures >= 5
        },
    })
    // ...
}
```

**Expected impact**: Instant fallback to local scoring when API is degraded. No more 15s (now 3s) waits per request during outages.

### 2.3 Non-Blocking Remote Scoring Option
**File: `internal/risk/engine.go`**

For low-risk tool calls (score < flag threshold), make remote scoring truly async:

```go
func (e *Engine) EnhanceWithRemote(score Score, ...) Score {
    if score.Value < e.thresholds.Flag && e.remoteScorer != nil {
        // Low risk: fire-and-forget remote scoring, use local score
        go func() {
            enhanced := e.remoteScorer.EnhanceScore(score, ...)
            // Publish enrichment to Kafka for async dashboard update
        }()
        return score
    }
    // High risk: blocking remote scoring (need the enriched score for deny decision)
    return e.remoteScorer.EnhanceScore(score, ...)
}
```

**Expected impact**: Removes remote scoring from the hot path for ~80% of tool calls.

---

## Phase 3: Serialization & Memory (3-5 days)

### 3.1 Protobuf for Kafka Wire Format
**New file: `internal/stream/events.proto`**

Replace JSON serialization for Kafka messages with Protobuf:

```protobuf
syntax = "proto3";
package stream;

message AgentEvent {
    string event_id = 1;
    int64 timestamp_ms = 2;
    string agent_id = 3;
    string agent_name = 4;
    string server_name = 5;
    string tool_name = 6;
    string action = 7;
    int32 risk_score = 8;
    string risk_level = 9;
    string verdict = 10;
    int32 depth = 11;
    string transport = 12;
    repeated string behavioral_flags = 13;
    // ... other fields
}
```

**Expected impact**: 3.8x faster serialization, ~40% smaller payloads, reduced GC pressure.

**Migration**: Support both formats during transition. Kafka consumers detect format from magic byte prefix.

### 3.2 sync.Pool for Event Structs
**File: `internal/stream/producer.go`**

Pool Kafka message structs and byte buffers:

```go
var eventPool = sync.Pool{
    New: func() any { return &AgentEventMessage{} },
}

var msgBufPool = sync.Pool{
    New: func() any { return make([]byte, 0, 4096) },
}
```

**Expected impact**: ~30% throughput improvement from reduced GC pressure.

### 3.3 Pre-compute Canonical Action
**File: `internal/intercept/classify.go`**

Cache classified actions per tool (tool names are finite and repeat):

```go
var actionCache sync.Map // key: "server:tool:method" → canonical action string

func ClassifyAction(serverName, toolName, method string) string {
    key := serverName + ":" + toolName + ":" + method
    if cached, ok := actionCache.Load(key); ok {
        return cached.(string)
    }
    action := classifyActionSlow(serverName, toolName, method)
    actionCache.Store(key, action)
    return action
}
```

---

## Phase 4: Kafka Producer Architecture (1 week)

### 4.1 Multiple Publisher Goroutines
**File: `internal/stream/producer.go`**

Replace single `publishLoop` with a worker pool:

```go
const numPublishWorkers = 4

func NewProducer(cfg *ProducerConfig) *Producer {
    // ...
    for i := 0; i < numPublishWorkers; i++ {
        p.wg.Add(1)
        go p.publishLoop()
    }
}
```

### 4.2 Switch Compression to LZ4
**File: `internal/stream/producer.go`**

LZ4 outperforms Snappy for throughput-optimized workloads (200k msgs in 3.27s vs 4.17s uncompressed):

```go
Compression: kafka.Lz4,
```

### 4.3 Partitioning by Agent ID
**File: `internal/stream/producer.go`**

Current: `LeastBytes` balancer (distributes by message size).
Better: partition by agent ID for per-agent ordering:

```go
Balancer: &kafka.Hash{}, // partitions by message key (= agent ID)
```

### 4.4 Consider franz-go Migration
For maximum throughput at scale, `franz-go` offers librdkafka-class performance in pure Go:
- Throughput comparable to confluent-kafka-go (CGO/librdkafka)
- No CGO requirement → easier cross-compilation
- Built-in exactly-once semantics
- Better async producer with true non-blocking sends

**Decision point**: Only migrate if benchmarks show segmentio/kafka-go is the bottleneck after Phase 1-3 optimizations.

---

## Phase 5: Scale Beyond Single Node (2-4 weeks)

### 5.1 Async Audit with Separate Write Path
Split audit into two tiers:
1. **Hot path**: Non-blocking channel → batch writer → SQLite (compliance log)
2. **Cold path**: Kafka `agent.events.raw` → ClickHouse/TimescaleDB (analytics)

### 5.2 SQLite Tuning for High-Write
```sql
PRAGMA synchronous = NORMAL;      -- was default (FULL in DELETE, NORMAL in WAL)
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;     -- 256MB memory-mapped I/O
PRAGMA cache_size = -64000;       -- 64MB page cache
```

### 5.3 Horizontal Scaling Architecture
```
                    ┌──────────┐
Agents ──→ LB ──→  │ Proxy #1 │ ──→ Kafka cluster (3+ brokers)
                    │ Proxy #2 │ ──→      ↓
                    │ Proxy #N │     ClickHouse (analytics)
                    └──────────┘     TimescaleDB (time-series)
                         │
                    Local SQLite    (each proxy has own audit chain)
                         │
                    Periodic sync → Central audit store
```

### 5.4 Move Audit to Turso/libSQL
If single-writer SQLite becomes the bottleneck:
- **Turso**: SQLite fork with MVCC concurrent writes (4x write throughput)
- Drop-in replacement for `modernc.org/sqlite`
- Same SQL, same file format, concurrent writers

---

## Implementation Priority

| Phase | Effort | Impact | Dependencies |
|-------|--------|--------|--------------|
| **1.1** HTTP client tuning | 30 min | **HIGH** (p99: 80ms→6ms) | None |
| **1.2** Reduce timeout | 5 min | **MEDIUM** | None |
| **1.3** Batch Kafka writes | 2 hours | **HIGH** (10-50x Kafka throughput) | None |
| **1.4** Batch audit writes | 4 hours | **HIGH** (10-50x audit throughput) | None |
| **2.1** Singleflight | 1 hour | **HIGH** (~95% dedup) | `golang.org/x/sync` |
| **2.2** Circuit breaker | 2 hours | **HIGH** (instant fallback) | `sony/gobreaker` |
| **2.3** Async low-risk scoring | 1 hour | **MEDIUM** | None |
| **3.1** Protobuf for Kafka | 1 day | **MEDIUM** (3.8x serialize) | `google.golang.org/protobuf` |
| **3.2** sync.Pool for events | 2 hours | **MEDIUM** (~30% GC) | None |
| **3.3** Action cache | 30 min | **LOW** | None |
| **4.x** Kafka architecture | 1 week | **HIGH** (at scale) | Benchmarking |
| **5.x** Horizontal scaling | 2-4 weeks | **Critical** (millions RPS) | Infrastructure |

---

## Throughput Targets

| Metric | Current | After Phase 1-2 | After Phase 3-4 | Phase 5 |
|--------|---------|-----------------|-----------------|---------|
| Kafka msgs/sec | ~1-5K | ~50-100K | ~200-500K | ~1M+ (cluster) |
| Audit writes/sec | ~100-500 | ~5-10K | ~20-50K | ~100K+ (Turso) |
| Remote scoring/sec | ~50-200 | ~1-5K | ~5-10K | ~50K+ (sharded) |
| Overall proxy RPS | ~500 | ~10K | ~50-100K | ~1M+ |

---

## Key Design Principles

1. **Never block the hot path** — Audit and Kafka must be non-blocking. Remote scoring must have tight timeouts and circuit breakers.
2. **Batch everything** — Individual writes are the enemy of throughput. Batch Kafka, batch SQLite, batch remote scoring.
3. **Degrade gracefully** — Circuit breakers, local scoring fallback, event dropping over blocking.
4. **Measure before optimizing** — Add latency histograms to each pipeline stage before Phase 3+.
5. **Preserve correctness** — Audit chain-linking must remain sequential within batches. Never compromise the tamper-proof guarantee.
