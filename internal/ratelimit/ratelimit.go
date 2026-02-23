package ratelimit

import (
	"math"
	"sync"
	"time"
)

const windowMs = 60_000 // 1 minute sliding window

type Result struct {
	Allowed       bool
	Used          int
	Limit         int
	RetryAfterSec int
}

type Limiter struct {
	mu        sync.Mutex
	windows   map[string][]int64 // key → sorted timestamps (ms)
	overrides map[string]int     // key → per-key rpm override
	rpm       int
	burst     int
}

func New(rpm, burst int) *Limiter {
	if rpm <= 0 {
		rpm = 60
	}
	if burst < 0 {
		burst = 10
	}
	return &Limiter{
		windows:   make(map[string][]int64),
		overrides: make(map[string]int),
		rpm:       rpm,
		burst:     burst,
	}
}

func (l *Limiter) SetKeyLimit(key string, rpm *int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rpm == nil {
		delete(l.overrides, key)
	} else {
		l.overrides[key] = *rpm
	}
}

func (l *Limiter) Check(key string) Result {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().UnixMilli()
	cutoff := now - windowMs

	ts := l.windows[key]
	// Prune old entries
	i := 0
	for i < len(ts) && ts[i] <= cutoff {
		i++
	}
	ts = ts[i:]

	rpm := l.rpm
	if override, ok := l.overrides[key]; ok {
		rpm = override
	}
	limit := rpm + l.burst
	used := len(ts)

	if used >= limit {
		retryMs := ts[0] + windowMs - now
		retryS := int(math.Max(1, math.Ceil(float64(retryMs)/1000)))
		l.windows[key] = ts
		return Result{Allowed: false, Used: used, Limit: limit, RetryAfterSec: retryS}
	}

	ts = append(ts, now)
	l.windows[key] = ts
	return Result{Allowed: true, Used: used + 1, Limit: limit, RetryAfterSec: 0}
}
