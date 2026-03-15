# PLAN: System Proxy via PAC File (Zero-Config Interception)

## Overview

Currently, agents need `HTTP_PROXY`/`HTTPS_PROXY` environment variables set (via `~/.quint/env.sh` sourced from shell profiles) to route traffic through Quint. This plan adds zero-config interception using PAC (Proxy Auto-Configuration) files, which macOS and Linux can apply system-wide without requiring per-process env vars.

---

## 1. Files to Create/Modify

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `internal/pac/domains.go` | **CREATE** | Default AI provider domain list (exported constant slice) |
| 2 | `internal/pac/pac.go` | **CREATE** | PAC file generator: `GeneratePAC()`, domain merge logic, file I/O |
| 3 | `internal/pac/pac_test.go` | **CREATE** | Unit tests for PAC generation and domain matching |
| 4 | `cmd/proxy/daemon.go` | **MODIFY** | Add `--write-pac` flag; call PAC generator at startup |
| 5 | `cmd/proxy/main.go` | **MODIFY** | Add `uninstall` subcommand dispatch |
| 6 | `cmd/proxy/uninstall.go` | **CREATE** | Full uninstall subcommand: daemon stop, CA removal, proxy reset, cleanup |
| 7 | `internal/cloud/client.go` | **MODIFY** | Extend `HeartbeatResult` with optional `Domains` field |
| 8 | `cmd/proxy/watch.go` | **MODIFY** | Add PAC generation in watch mode |
| 9 | `deploy/get-site/install.sh` | **MODIFY** | Add macOS PAC system proxy setup + Linux /etc/profile.d proxy |

---

## 2. Step-by-Step Implementation Order

### Step 1: Create `internal/pac/domains.go` — Default AI Provider Domain List

**No dependencies.** Pure data file.

Create a new package `internal/pac` with an exported `var DefaultDomains []string`:

- `api.anthropic.com`
- `api.openai.com`
- `*.openai.azure.com`
- `bedrock-runtime.*.amazonaws.com`
- `generativelanguage.googleapis.com`
- `api.githubcopilot.com`
- `api.codeium.com`
- `api-inference.huggingface.co`
- `api.fireworks.ai`
- `api.together.xyz`
- `api.groq.com`
- `api.mistral.ai`
- `api.deepseek.com`
- `api.cohere.com`
- `api.x.ai`

**Design decision:** Store as a Go slice rather than embedding a file. The list is small, rarely changes, and the cloud heartbeat provides runtime updates. Follows the pattern of `llmProviderDomains` in `internal/forwardproxy/passthrough.go`.

**Note:** The existing `llmProviderDomains` in `passthrough.go` is a subset (4 domains) used for MITM parsing. The PAC domain list is a superset used for proxy routing. These serve different purposes — keep them separate.

### Step 2: Create `internal/pac/pac.go` — PAC File Generator

**Depends on:** Step 1.

Core exported functions:

```go
package pac

// GeneratePAC produces a valid JavaScript PAC file string.
// Traffic to listed domains routes through PROXY 127.0.0.1:{port}; DIRECT;
// everything else goes DIRECT.
func GeneratePAC(proxyPort int, domains []string) string

// LoadCustomDomains reads ~/.quint/ai-providers.json and returns
// the custom domain list. Returns nil if the file doesn't exist.
func LoadCustomDomains(quintDir string) ([]string, error)

// SaveCustomDomains writes domains to ai-providers.json.
func SaveCustomDomains(quintDir string, domains []string) error

// MergeDomains combines default and custom domains, deduplicating.
func MergeDomains(defaults, custom []string) []string

// WritePACFile generates the PAC file and writes it to the given path.
// Returns the number of domains included.
func WritePACFile(path string, proxyPort int, domains []string) (int, error)
```

**PAC file template (valid JavaScript):**

```javascript
function FindProxyForURL(url, host) {
  // Exact match domains
  if (host == "api.anthropic.com") return "PROXY 127.0.0.1:9090; DIRECT";
  if (host == "api.openai.com") return "PROXY 127.0.0.1:9090; DIRECT";
  // ... etc

  // Wildcard match domains
  if (shExpMatch(host, "*.openai.azure.com")) return "PROXY 127.0.0.1:9090; DIRECT";
  if (shExpMatch(host, "bedrock-runtime.*.amazonaws.com")) return "PROXY 127.0.0.1:9090; DIRECT";

  return "DIRECT";
}
```

Key: use `shExpMatch()` for wildcard patterns (standard PAC function). Include `DIRECT` as fallback after `PROXY` so traffic falls through if proxy is down.

**`ai-providers.json` format:**

```json
{
  "domains": ["api.custom-llm.com", "*.internal-ai.corp.com"]
}
```

### Step 3: Create `internal/pac/pac_test.go` — Unit Tests

**Depends on:** Step 2.

Test cases:
1. `TestGeneratePAC_BasicOutput` — valid JS with `FindProxyForURL`, `PROXY`, `DIRECT`
2. `TestGeneratePAC_ExactDomains` — exact domains produce `host ==` checks
3. `TestGeneratePAC_WildcardDomains` — wildcards produce `shExpMatch` checks
4. `TestGeneratePAC_CustomPort` — port number is correctly embedded
5. `TestMergeDomains_Dedup` — duplicate domains removed
6. `TestMergeDomains_CustomOverride` — custom added alongside defaults
7. `TestLoadCustomDomains_MissingFile` — returns nil, nil
8. `TestLoadCustomDomains_ValidJSON` — parses correctly
9. `TestLoadCustomDomains_InvalidJSON` — returns error
10. `TestWritePACFile_WritesToDisk` — uses `t.TempDir()`, verifies content

### Step 4: Modify `cmd/proxy/daemon.go` — PAC Generation at Daemon Startup

**Depends on:** Steps 1-3.

**A. Add `--write-pac` flag:**

In the flag parsing, add:
```go
case "--write-pac":
    writePACOnly = true
```

If set, generate PAC file and exit immediately (before cloud registration). Used by install script.

**B. At daemon startup (after port resolution):**

1. Daemon runs as root — write PAC to `/var/lib/quint/proxy.pac` (daemon data dir)
2. Load default domains from `pac.DefaultDomains`
3. Load custom domains from `{dataDir}/ai-providers.json`
4. Merge and generate PAC file
5. Log: `"wrote PAC file: %s (%d domains)"`

**C. If `--write-pac` is set:**

Also copy to user's home if `SUDO_USER` is set:
```go
if writePACOnly {
    if realUser := os.Getenv("SUDO_USER"); realUser != "" {
        // copy to ~realUser/.quint/proxy.pac
    }
    os.Exit(0)
}
```

**Design decision:** Daemon writes to its data dir. Install script copies to `~/.quint/proxy.pac` for user-space access. Avoids daemon needing to know real user's home.

### Step 5: Modify `internal/cloud/client.go` — Extend Heartbeat Response

**Independent step.**

Extend `HeartbeatResult` struct:

```go
type HeartbeatResult struct {
    ConfigVersion string   `json:"config_version"`
    PolicyHash    string   `json:"policy_hash"`
    Domains       []string `json:"domains,omitempty"` // NEW
}
```

Backward compatible — old APIs return no `domains` field.

### Step 6: Modify `cmd/proxy/daemon.go` — Domain Update via Heartbeat

**Depends on:** Steps 4, 5.

In the heartbeat goroutine, after policy hash check:

```go
if result != nil && len(result.Domains) > 0 {
    if err := pac.SaveCustomDomains(dataDir, result.Domains); err != nil {
        qlog.Warn("failed to save domain update: %v", err)
    } else {
        merged := pac.MergeDomains(pac.DefaultDomains, result.Domains)
        if _, err := pac.WritePACFile(filepath.Join(dataDir, "proxy.pac"), port, merged); err != nil {
            qlog.Warn("failed to regenerate PAC: %v", err)
        } else {
            qlog.Info("updated PAC file with %d cloud domains", len(result.Domains))
        }
    }
}
```

### Step 7: Create `cmd/proxy/uninstall.go` — Uninstall Subcommand

**Independent step.**

Implements `runUninstall(args []string)`:

1. Parse `--force` flag (skip confirmation without it: print what will be removed and ask)
2. Require root (`os.Geteuid() == 0`)
3. Stop daemon:
   - macOS: `launchctl unload /Library/LaunchDaemons/dev.quintai.agent.plist`
   - Linux: `systemctl stop quint-agent && systemctl disable quint-agent`
4. Remove binary: `/usr/local/bin/quint`, `/opt/homebrew/bin/quint` (if exists)
5. Remove CA:
   - macOS: `security remove-trusted-cert -d ~/.quint/ca/quint-ca.crt`
   - Linux: `rm /usr/local/share/ca-certificates/quint-ca.crt && update-ca-certificates`
6. Reset system proxy (macOS): `networksetup -setautoproxyurl "$iface" ""` + `-setautoproxystate "$iface" off` for all interfaces
7. Remove `/etc/profile.d/quint-proxy.sh` (Linux)
8. Clean `/etc/environment` (Linux) — remove HTTP_PROXY/HTTPS_PROXY lines
9. Remove config dirs: `/etc/quint/`, `/var/lib/quint/`, `/var/log/quint/`
10. Remove user files: `~/.quint/`
11. Remove LaunchDaemon plist (macOS) / systemd unit (Linux)
12. Remove shell profile source lines (`[ -f ~/.quint/env.sh ] && source ~/.quint/env.sh`)
13. Print "Quint uninstalled. Restart your shell."

**Design:** Each step is best-effort with warnings (not fatal). Use `runtime.GOOS` for OS branching.

### Step 8: Modify `cmd/proxy/main.go` — Add Uninstall Dispatch

**Depends on:** Step 7.

Add to subcommand switch:
```go
case "uninstall":
    runUninstall(os.Args[2:])
    return
```

Update `printUsage()` to include `quint uninstall`.

### Step 9: Modify `deploy/get-site/install.sh` — System Proxy Setup

**Depends on:** Steps 1-4.

After shell profile injection section, add:

```bash
# ---------------------------------------------------------------------------
# System proxy via PAC (zero-config interception)
# ---------------------------------------------------------------------------
PAC_PATH="${REAL_HOME}/.quint/proxy.pac"

quint daemon --write-pac 2>/dev/null || true

if [ -f "/var/lib/quint/proxy.pac" ]; then
  cp "/var/lib/quint/proxy.pac" "$PAC_PATH" 2>/dev/null || true
  chown "${REAL_USER}" "$PAC_PATH" 2>/dev/null || true
fi

case "$OS" in
  darwin)
    if [ -f "$PAC_PATH" ]; then
      PAC_URL="file://${PAC_PATH}"
      for iface in $(networksetup -listallnetworkservices | tail -n +2); do
        networksetup -setautoproxyurl "$iface" "$PAC_URL" 2>/dev/null || true
      done
      echo "Set system auto-proxy (PAC) for all network interfaces"
    fi
    ;;
  linux)
    cat > /etc/profile.d/quint-proxy.sh <<'PROXYSH'
# Quint AI agent security proxy
export HTTP_PROXY=http://localhost:9090
export HTTPS_PROXY=http://localhost:9090
export http_proxy=http://localhost:9090
export https_proxy=http://localhost:9090
export no_proxy=localhost,127.0.0.1,*.local
export NO_PROXY=localhost,127.0.0.1,*.local
PROXYSH
    chmod 644 /etc/profile.d/quint-proxy.sh

    if ! grep -qF "HTTP_PROXY" /etc/environment 2>/dev/null; then
      echo 'HTTP_PROXY="http://localhost:9090"' >> /etc/environment
      echo 'HTTPS_PROXY="http://localhost:9090"' >> /etc/environment
    fi
    echo "Set system-wide proxy environment"
    ;;
esac
```

**Design:** On macOS, use `file://` PAC URL. On Linux, PAC files are not universally supported at system level, so fall back to env vars.

### Step 10 (Optional): PAC Generation in Watch Mode

In `cmd/proxy/watch.go`, after port resolution, generate PAC to `~/.quint/proxy.pac` for interactive use. Not system-registered (requires sudo), but available for manual config.

---

## 3. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| New `internal/pac` package | Clean separation. PAC generation has no proxy internals dependency. Follows small-package pattern (`pidlookup`, `ratelimit`, `credential`). |
| Daemon writes to `/var/lib/quint/proxy.pac`; install copies to `~/.quint/` | Daemon runs as root, doesn't know real user's home. Install has `$SUDO_USER`. |
| PAC uses `shExpMatch()` for wildcards | Standard PAC function, supported by all OS PAC evaluators. |
| Domain list in Go code, not embedded file | 15 entries, compile-time safety, cloud heartbeat provides runtime updates. |
| `ai-providers.json` for custom domains | JSON is easy to hand-edit and machine-generate. |
| Heartbeat `domains` field is optional | Backward compatible. Old cloud APIs return no field — no action taken. |
| Linux uses env vars instead of PAC | Most Linux CLI environments don't support PAC natively. Env vars via `/etc/profile.d/` are more universally effective. |
| Uninstall is best-effort | Each step continues on failure. Partial uninstall that removes proxy + resets network is better than crashing mid-removal. |
| `--write-pac` as daemon flag | PAC depends on daemon config (port, domains). Avoids duplicating config resolution. |
| `PROXY ...; DIRECT` fallback in PAC | If proxy is down, traffic falls through to direct connection. Prevents total internet breakage. |

---

## 4. Test Strategy

### Unit Tests (Go)
- `internal/pac/pac_test.go`: PAC generation correctness (valid JS, exact vs wildcard, port embedding, merge/dedup, file I/O)
- Parse JS output and check for expected `host ==` and `shExpMatch` lines

### Integration Tests
- Build binary → `./quint-proxy daemon --write-pac` → verify PAC file created with correct content
- Validate PAC with Node.js: `node -e "eval(fs.readFileSync('proxy.pac','utf8')); console.log(FindProxyForURL('https://api.anthropic.com/v1/messages','api.anthropic.com'))"` → should output `PROXY 127.0.0.1:9090; DIRECT`
- Verify DIRECT for non-AI domains

### System Tests (macOS)
- After install: `networksetup -getautoproxyurl Wi-Fi` returns PAC URL
- After uninstall: returns empty/disabled
- Agent traffic routes through Quint

---

## 5. Rollback Considerations

| Risk | Mitigation |
|------|-----------|
| PAC file breaks all internet | PAC defaults to `DIRECT` except AI domains. `PROXY ...; DIRECT` fallback if proxy is down. |
| System proxy set but daemon not running | `DIRECT` fallback in PAC template ensures traffic falls through. |
| Uninstall fails to reset system proxy | Log each step. Print manual instructions on failure. Save breadcrumb of configured interfaces. |
| Heartbeat domain update breaks PAC | Validate domains before writing. Keep `.pac.bak`. |
| Feature gate | PAC setup only performed by install script. Manual `quint watch` users are unaffected. `--no-system-proxy` flag for install script allows opt-out. |
