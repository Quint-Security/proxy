# PLAN: Background Process Scanner (`internal/procscan/`)

## Overview

Build a background process scanner that continuously discovers AI coding agents running on the machine by polling the OS process table, regardless of whether they've made API calls. Reports agent inventory to the cloud dashboard via the existing `cloud.Client`.

---

## 1. Files to Create

| File | Purpose |
|------|---------|
| `internal/procscan/signatures.go` | Single source of truth for agent process signatures (`KnownAgents` slice) |
| `internal/procscan/scanner.go` | Core `Scanner` struct, lifecycle (`Start`/`Stop`/`Current`), change detection logic |
| `internal/procscan/scanner_darwin.go` | macOS implementation: `ps -axo` parsing |
| `internal/procscan/scanner_linux.go` | Linux implementation: `/proc` filesystem walking |
| `internal/procscan/scanner_other.go` | Stub for unsupported platforms |
| `internal/procscan/scanner_test.go` | Unit tests for signature matching, change detection, error resilience |

## 2. Files to Modify

| File | Change |
|------|--------|
| `cmd/proxy/daemon.go` | Wire scanner into daemon lifecycle: create, start in goroutine, coordinated shutdown |
| `cmd/proxy/watch.go` | Wire scanner into watch mode (same pattern as daemon) |
| `internal/cloud/client.go` | Add `ReportAgentInventory` method: `POST /v1/machines/{id}/agents` |

---

## 3. Step-by-Step Implementation Order

### Step 1: `internal/procscan/signatures.go` (no dependencies)

Create the `AgentSignature` type and `KnownAgents` variable. This is the single source of truth — intentionally does NOT import from `agentdetect` or `pidlookup`.

```go
type AgentSignature struct {
    Platform     string   // canonical name
    ProcessNames []string // exact process name matches (case-insensitive)
    PathPatterns []string // substring matches in binary path
    ParentHints  []string // if parent process matches, child is this agent
}

var KnownAgents = []AgentSignature{
    {Platform: "claude-code", ProcessNames: []string{"claude", "claude-code"}, PathPatterns: []string{"claude.app", ".claude/local", "/claude-code"}},
    {Platform: "cursor", ProcessNames: []string{"cursor", "Cursor Helper"}, PathPatterns: []string{"Cursor.app", "/cursor"}},
    {Platform: "copilot", ProcessNames: []string{"copilot"}, PathPatterns: []string{"copilot"}},
    {Platform: "windsurf", ProcessNames: []string{"windsurf"}, PathPatterns: []string{"Windsurf.app", "/windsurf"}},
    {Platform: "kiro", ProcessNames: []string{"kiro"}, PathPatterns: []string{"Kiro.app", "/kiro"}},
    {Platform: "codex", ProcessNames: []string{"codex"}, PathPatterns: []string{"codex-cli", "/codex"}},
    {Platform: "aider", ProcessNames: []string{"aider"}, PathPatterns: []string{"/aider"}},
    {Platform: "cline", ProcessNames: []string{"cline"}, PathPatterns: []string{"cline"}},
    {Platform: "continue", ProcessNames: []string{"continue"}, PathPatterns: []string{"continue"}},
    {Platform: "augment", ProcessNames: []string{"augment"}, PathPatterns: []string{"augment"}},
    {Platform: "goose", ProcessNames: []string{"goose"}, PathPatterns: []string{"/goose"}},
    {Platform: "gemini-cli", ProcessNames: []string{"gemini"}, PathPatterns: []string{"gemini-cli", "/gemini"}},
    {Platform: "amp", ProcessNames: []string{"amp"}, PathPatterns: []string{"/amp"}},
    {Platform: "zed", ProcessNames: []string{"zed"}, PathPatterns: []string{"Zed.app", "/zed"}},
    {Platform: "opencode", ProcessNames: []string{"opencode"}, PathPatterns: []string{"/opencode"}},
    {Platform: "pearai", ProcessNames: []string{"pearai"}, PathPatterns: []string{"PearAI.app"}},
    {Platform: "trae", ProcessNames: []string{"trae"}, PathPatterns: []string{"Trae.app"}},
    {Platform: "void", ProcessNames: []string{"void"}, PathPatterns: []string{"Void.app"}},
    {Platform: "devin", ProcessNames: []string{"devin"}, PathPatterns: []string{"devin"}},
}
```

Include helper: `MatchProcess(name, path string) (platform string, matched bool)` — iterates `KnownAgents`, returns first match. Case-insensitive name comparison, substring path matching.

**Note:** Add comment referencing `agentdetect/fingerprints.go` and vice versa, noting both must be updated when a new agent is added.

### Step 2: `internal/procscan/scanner.go` (depends on Step 1)

Core types:

```go
type AgentProcess struct {
    Platform    string    // "claude-code", "cursor", etc.
    PID         int
    PPID        int
    BinaryPath  string
    State       string    // "running"
    CPUPercent  float64
    MemoryMB    int
    StartedAt   time.Time
}

type Scanner struct {
    interval   time.Duration
    signatures []AgentSignature
    mu         sync.RWMutex
    lastReport []AgentProcess
    onChange   func(agents []AgentProcess)
    selfPID    int
    stopCh     chan struct{}
    done       chan struct{}
}
```

**Constructor:**
- `NewScanner(interval time.Duration, onChange func([]AgentProcess)) *Scanner`
- Stores `KnownAgents` as `signatures`
- Sets `selfPID = os.Getpid()` to exclude Quint daemon
- Default interval: 5 seconds if zero

**Lifecycle:**
- `Start(ctx context.Context)` — scan loop in goroutine. Each tick: call platform-specific `scanProcesses()`, then `detectChanges()`. Respects both `ctx.Done()` and `stopCh`.
- `Stop()` — closes `stopCh`, waits on `done` channel
- `Current() []AgentProcess` — returns copy of `lastReport` under read lock

**Change detection (`hasChanged` + `detectChanges`):**

```go
func hasChanged(prev, curr []AgentProcess) bool {
    if len(prev) != len(curr) { return true }
    prevMap := map[int]string{}  // PID -> Platform
    for _, a := range prev { prevMap[a.PID] = a.Platform }
    currMap := map[int]string{}
    for _, a := range curr { currMap[a.PID] = a.Platform }
    for pid, plat := range currMap {
        if prevMap[pid] != plat { return true }  // new or changed
    }
    for pid := range prevMap {
        if _, ok := currMap[pid]; !ok { return true }  // removed
    }
    return false
}
```

Extracted as standalone function for testability without OS calls.

**Design decision:** PID as diff key — unique at any point in time. A process exiting and PID reuse between 5-second scans is extremely unlikely. If it happens, Platform comparison catches it.

### Step 3: `internal/procscan/scanner_darwin.go` (depends on Steps 1-2)

Build tag: `//go:build darwin`

```go
func scanProcesses(selfPID int, sigs []AgentSignature) []AgentProcess
```

Uses single `exec.Command("ps", "-axo", "pid,ppid,pcpu,rss,lstart,comm,args")` call (~5ms).

Parse stdout line by line:
1. Skip header line
2. Extract fields: pid, ppid, pcpu, rss (KB → MB), lstart, comm, args
3. Skip if pid == selfPID
4. Extract base process name from `comm` (after last `/`)
5. Call `MatchProcess(baseName, comm)` against `KnownAgents`
6. If matched, build `AgentProcess` and append

For `lstart` parsing: macOS outputs like `Mon Mar  9 14:30:00 2026`. Use `time.Parse`. If fails, use zero value (nice-to-have per spec).

Set `LC_ALL=C` in exec environment to avoid locale-dependent output format.

Error handling: If `exec.Command` fails, return empty slice. Log at debug level. Never panic.

### Step 4: `internal/procscan/scanner_linux.go` (depends on Steps 1-2)

Build tag: `//go:build linux`

Walk `/proc/[0-9]*/` directories (~2ms, no exec calls):

For each numeric directory:
1. Read `/proc/{pid}/comm` for process name
2. Read `/proc/{pid}/exe` symlink for binary path (best-effort, may get EPERM)
3. Read `/proc/{pid}/stat` for ppid, state
4. Read `/proc/{pid}/status` for VmRSS (memory)
5. Skip if pid == selfPID
6. Call `MatchProcess(name, exePath)`
7. If matched, build `AgentProcess`

Error handling: If any `/proc` read fails (EPERM, ENOENT), skip that process silently. Spec requires "must not crash on permission errors."

CPU percent: Set to 0 in v1 (requires two samples for delta). Acceptable since CPU is "nice-to-have."

### Step 5: `internal/procscan/scanner_other.go` (no dependencies)

Build tag: `//go:build !darwin && !linux`

Stub returning empty slice:
```go
func scanProcesses(selfPID int, sigs []AgentSignature) []AgentProcess {
    return nil
}
```

### Step 6: `internal/procscan/scanner_test.go` (depends on Steps 1-2)

All unit-level, no OS calls:

1. **TestMatchProcess_ExactName** — each agent's process names match (case-insensitive). `MatchProcess("Claude", "")` → `"claude-code"`
2. **TestMatchProcess_PathPattern** — path-based matching. `MatchProcess("node", "/Applications/Cursor.app/.../node")` → `"cursor"`
3. **TestMatchProcess_NoMatch** — unknown processes return empty. `MatchProcess("python3", "/usr/bin/python3")` → `""`
4. **TestHasChanged_NewAgent** — empty prev + one curr → true
5. **TestHasChanged_RemovedAgent** — one prev + empty curr → true
6. **TestHasChanged_NoChange** — same PID/Platform → false
7. **TestHasChanged_SameAgentDifferentPID** — agent relaunches with new PID → true
8. **TestCurrent_ReturnsCopy** — `Current()` returns copy, not internal reference
9. **TestSelfPIDExclusion** — scanner's own PID excluded

### Step 7: `internal/cloud/client.go` — Add `ReportAgentInventory`

**Depends on:** Step 1 for types.

```go
type AgentInventoryEntry struct {
    Platform   string  `json:"platform"`
    PID        int     `json:"pid"`
    BinaryPath string  `json:"binary_path,omitempty"`
    State      string  `json:"state"`
    CPUPercent float64 `json:"cpu_percent,omitempty"`
    MemoryMB   int     `json:"memory_mb,omitempty"`
    StartedAt  string  `json:"started_at,omitempty"`
}

func (c *Client) ReportAgentInventory(agents []AgentInventoryEntry) error
```

Endpoint: `POST /v1/machines/{cloudUUID}/agents`

Follows same pattern as `PushEvents`: marshal JSON, set auth header, check response status.

Debounce is handled by the caller (daemon wiring), not the client. Client is a simple "fire" method.

### Step 8: `cmd/proxy/daemon.go` — Wire Scanner

**Depends on:** Steps 1-7.

Add scanner after cloud client creation, before forward proxy starts:

```go
var procScanner *procscan.Scanner
scannerStop := make(chan struct{})
scannerDone := make(chan struct{})
go func() {
    defer close(scannerDone)

    var lastReportHash string
    var lastReportTime time.Time

    procScanner = procscan.NewScanner(5*time.Second, func(agents []procscan.AgentProcess) {
        if client == nil { return }

        entries := convertToInventoryEntries(agents)
        hash := inventoryHash(entries)
        now := time.Now()

        // Send if: content changed OR 30s since last report
        if hash != lastReportHash || now.Sub(lastReportTime) >= 30*time.Second {
            if err := client.ReportAgentInventory(entries); err != nil {
                qlog.Warn("agent inventory report failed: %v", err)
            } else {
                lastReportHash = hash
                lastReportTime = now
            }
        }
    })

    ctx, cancel := context.WithCancel(context.Background())
    go func() { <-scannerStop; cancel() }()
    procScanner.Start(ctx)
}()
```

Add to shutdown: `close(scannerStop); <-scannerDone`

`inventoryHash`: Sort entries by Platform+PID, JSON-marshal, SHA256. Deterministic content hash for debounce.

### Step 9: `cmd/proxy/watch.go` — Wire Scanner

Same wiring as daemon, only when cloud forwarding is active (`deployToken != ""` and registration succeeded).

---

## 4. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Separate `procscan` package, not extending `agentdetect` | `agentdetect` is per-request HTTP detection (headers, UA, system prompt). Process scanning is timer-based OS polling. Different mechanisms, different packages. |
| Not importing from `agentdetect` or `pidlookup` | Per spec constraint. `signatures.go` is the new process-level source of truth. `agentdetect` remains HTTP-level source of truth. |
| PID-based diff key | Unique at any moment. Alternative (Platform key) fails with multiple instances of same agent (e.g., two Cursor windows). |
| `onChange` only on actual change | Primary debounce — cloud API not hammered every 5s with identical data. |
| Secondary 30s periodic refresh | Ensures cloud has fresh data even if change was missed (API was down, clock drift). |
| Single `ps` exec on macOS | `pidlookup` calls `lsof`+`ps -p` per-port per-request (fine for on-demand). Scanner needs all processes at once — single `ps -axo` is ~5ms. |
| CPU=0 on Linux v1 | Requires two-sample delta. Acceptable since CPU is "nice-to-have." |

---

## 5. Change Detection (Diff Algorithm)

```
hasChanged(prev, curr []AgentProcess) bool:
    1. If len(prev) != len(curr) → return true (fast path)
    2. Build prevMap: map[PID]Platform from prev
    3. Build currMap: map[PID]Platform from curr
    4. For each PID in currMap:
         if PID not in prevMap → return true (new agent)
         if prevMap[PID] != currMap[PID] → return true (platform changed)
    5. For each PID in prevMap:
         if PID not in currMap → return true (agent gone)
    6. return false
```

Steps 4+5 catch additions, removals, and platform changes.

---

## 6. Cloud Reporting Debounce Strategy

| Trigger | Condition | Effect |
|---------|-----------|--------|
| Agent list changed | `hasChanged(prev, curr) == true` | Immediately call `ReportAgentInventory` |
| Periodic refresh | 30s since last successful report | Call even if unchanged |
| Same content, < 30s | `hash == lastHash && elapsed < 30s` | Skip report |
| API error | `ReportAgentInventory` returns error | Log warning, do NOT update lastHash/lastTime (will retry next tick) |

---

## 7. Test Strategy

- **Unit tests** (`scanner_test.go`): Signature matching, change detection, self-PID exclusion, copy semantics. All platform-independent, no OS calls.
- **Build verification**: `make build` on macOS + `GOOS=linux make build-all` to verify build tags compile.
- **Integration**: Manual — run daemon, start Claude Code, verify agent appears in logs + cloud dashboard.
- **Edge cases**: Permission errors on `/proc`, empty process table, rapid agent start/stop.

---

## 8. Potential Challenges

| Challenge | Mitigation |
|-----------|-----------|
| `ps` output format varies by locale | Set `LC_ALL=C` in exec environment |
| PID reuse between scans | Extremely unlikely in 5s window. Platform comparison catches it. |
| Quint daemon spawning matched processes | Self-PID filter. Also exclude PPID == selfPID. |
| Cloud API endpoint doesn't exist yet | 404 logged as warning, doesn't crash. Proxy-side code is ready. |
| Memory growth | `lastReport` bounded by running agent count (<20 on any machine). |
