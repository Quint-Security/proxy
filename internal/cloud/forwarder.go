package cloud

import (
	"sync"
	"time"

	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

const (
	bufferCapacity  = 1000
	flushInterval   = 10 * time.Second
	flushBatchSize  = 100
	maxRetries      = 5
	initialBackoff  = 1 * time.Second
	maxBackoff      = 5 * time.Minute
)

// Forwarder buffers events and batch-pushes them to the cloud API.
// It uses a ring buffer with a fixed capacity and drops the oldest
// events when full.
type Forwarder struct {
	client *Client
	mu     sync.Mutex
	buffer []EventPayload
	stopCh chan struct{}
	done   chan struct{}
}

// NewForwarder creates a new event forwarder backed by the given cloud client.
func NewForwarder(client *Client) *Forwarder {
	return &Forwarder{
		client: client,
		buffer: make([]EventPayload, 0, bufferCapacity),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Enqueue adds an event to the buffer. If the buffer is full, the oldest
// event is dropped to make room.
func (f *Forwarder) Enqueue(e EventPayload) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.buffer) >= bufferCapacity {
		// Drop oldest event
		f.buffer = f.buffer[1:]
	}
	f.buffer = append(f.buffer, e)
}

// Start launches the background goroutine that periodically flushes
// buffered events to the cloud.
func (f *Forwarder) Start() {
	go func() {
		defer close(f.done)
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				f.flush()
			case <-f.stopCh:
				// Final flush before exit
				f.flush()
				return
			}
		}
	}()
	qlog.Info("event forwarder started (buffer=%d, interval=%s)", bufferCapacity, flushInterval)
}

// Stop signals the forwarder to perform a final flush and shut down.
// Blocks until the background goroutine exits.
func (f *Forwarder) Stop() {
	close(f.stopCh)
	<-f.done
	qlog.Info("event forwarder stopped")
}

// BufferLen returns the current number of buffered events.
func (f *Forwarder) BufferLen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.buffer)
}

// flush takes up to flushBatchSize events from the buffer and pushes
// them to the cloud. Retries up to maxRetries times with exponential
// backoff. Drops the batch after exhausting retries.
func (f *Forwarder) flush() {
	f.mu.Lock()
	if len(f.buffer) == 0 {
		f.mu.Unlock()
		return
	}

	// Take up to flushBatchSize events
	n := len(f.buffer)
	if n > flushBatchSize {
		n = flushBatchSize
	}
	batch := make([]EventPayload, n)
	copy(batch, f.buffer[:n])
	f.buffer = f.buffer[n:]
	f.mu.Unlock()

	// Deduplicate: keep only the first occurrence per action+agent key
	seen := make(map[string]bool)
	deduped := make([]EventPayload, 0, len(batch))
	for _, e := range batch {
		key := e.Action + "|" + e.Agent
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, e)
		}
	}
	batch = deduped

	// Retry with exponential backoff
	backoff := initialBackoff
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := f.client.PushEvents(batch)
		if err == nil {
			return
		}

		if attempt == maxRetries {
			qlog.Error("dropping %d events after %d retries: %v", len(batch), maxRetries, err)
			return
		}

		qlog.Warn("event push failed (attempt %d/%d): %v, retrying in %s", attempt+1, maxRetries, err, backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
