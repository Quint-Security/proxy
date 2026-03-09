package pidlookup

import (
	"os"
	"sync"
	"time"
)

// ProcessInfo holds information about the process that owns a connection.
type ProcessInfo struct {
	PID         int
	ProcessName string
	ProcessPath string
	LookedUpAt  time.Time
}

// Lookup provides cached PID lookups for network connections.
type Lookup struct {
	cache  sync.Map // port (int) → *ProcessInfo
	ttl    time.Duration
	selfPID int
}

// New creates a new PID lookup with a cache TTL.
func New(ttl time.Duration) *Lookup {
	return &Lookup{
		ttl:     ttl,
		selfPID: os.Getpid(),
	}
}

// SelfPID returns this process's PID (used to exclude self from lookups).
func (l *Lookup) SelfPID() int {
	return l.selfPID
}

// LookupByPort returns process info for a given local TCP port.
// Results are cached for the configured TTL.
// Excludes the proxy's own PID from results.
func (l *Lookup) LookupByPort(port int) *ProcessInfo {
	if cached, ok := l.cache.Load(port); ok {
		info := cached.(*ProcessInfo)
		if time.Since(info.LookedUpAt) < l.ttl {
			return info
		}
	}

	info := lookupPort(port)
	if info != nil {
		// Skip if this is our own process
		if info.PID == l.selfPID {
			info = lookupPortExcluding(port, l.selfPID)
		}
		if info != nil {
			info.LookedUpAt = time.Now()
			l.cache.Store(port, info)
		}
	}
	return info
}
