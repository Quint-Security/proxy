# Quint

Security gateway for AI agents. Intercepts every tool call, enforces policy, scores risk, and produces cryptographically signed audit logs.

## Quickstart

```bash
brew install quint
quint setup
# Done. Quint is now proxying your MCP servers.
```

`quint setup` detects your MCP servers (Claude Code, Cursor, Windsurf, Cline), generates Ed25519 keys, creates a default policy, and wires everything up.

## What it does

- **Policy enforcement** — allow, deny, or flag tool calls per server using glob patterns
- **Risk scoring** — multi-layer pipeline with local patterns, behavioral analysis, and cloud-based GNN scoring
- **Sub-agent detection** — three-layer detection identifies child agents via model divergence, concurrency spikes, and temporal gaps
- **Signed audit trail** — every message gets an Ed25519 signature and SHA-256 hash chain
- **Export proof bundles** — `quint export --last 7d` produces a standalone, verifiable audit file

## How it works

```
AI Agent (Claude, etc.)
        |
    quint proxy          ← policy check, risk score, audit log
        |
  MCP Server (filesystem, github, etc.)
```

Quint sits between the AI agent and MCP servers. In **stdio mode**, it wraps existing server commands transparently. In **watch mode**, it acts as an HTTP/HTTPS forward proxy with MITM TLS interception.

## Commands

| Command | Description |
|---------|-------------|
| `quint setup` | Interactive setup wizard |
| `quint start` | Run the MCP gateway (stdio multiplexer) |
| `quint watch` | HTTP/HTTPS forward proxy + dashboard |
| `quint status` | Health check |
| `quint dashboard` | Open the web dashboard |
| `quint export` | Export audit proof bundle |
| `quint admin` | Advanced commands |

## Watch Mode (Forward Proxy)

`quint watch` starts an HTTP/HTTPS forward proxy with MITM TLS interception and a real-time dashboard.

```bash
quint watch
```

This starts:
- **Forward proxy** on `:9090` — intercepts all HTTP/HTTPS traffic
- **Dashboard** on `:8080` — real-time audit viewer, agent graph, HTTP traffic

### Setup

Paste these into the agent's terminal:

```bash
# Trust the CA certificate
export SSL_CERT_FILE=~/.quint/ca/quint-ca-bundle.pem
export NODE_EXTRA_CA_CERTS=~/.quint/ca/quint-ca.crt

# Route traffic through the proxy
export HTTP_PROXY=http://localhost:9090
export HTTPS_PROXY=http://localhost:9090
```

### Agent Identity

Agents are automatically identified by IP + User-Agent + destination provider. For explicit identity:

```bash
# Via proxy URL username
export HTTP_PROXY=http://my-agent@localhost:9090
export HTTPS_PROXY=http://my-agent@localhost:9090
```

Agents get memorable word-based names like `anthropic:swift-blue-falcon`. The same tool talking to different providers (e.g. Claude Code → Anthropic vs Claude Code → OpenAI) gets distinct identities.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 9090 | Proxy port |
| `--dashboard-port` | 8080 | Dashboard port |
| `--no-dashboard` | false | Don't start dashboard |
| `--no-open` | false | Don't open browser |
| `--static-dir` | — | Serve dashboard from local dir (dev mode) |

## Sub-Agent Detection

Quint detects parent-child relationships between agents using three complementary layers:

| Layer | Signal | Confidence | Example |
|-------|--------|------------|---------|
| Model divergence | `model` field changes in POST body | 0.85 | Opus → Haiku in same tunnel |
| Concurrency spike | Tunnel count exceeds baseline | varies | Google: 2 tunnels → 4 tunnels |
| Temporal gap | New process while parent active | 0.70–0.95 | Codex spawning sub-agents |

Detected children appear in the dashboard with parent links and derived names (e.g. `derived_anthropic:swift-blue-falcon_a8e3`).

## Risk Scoring

Scoring is a multi-layer pipeline:

1. **Local** — pattern matching, keyword detection, behavioral analysis
2. **Context** — depth penalty (deeper agents = higher risk), delegation burst detection
3. **Remote** — cloud scoring API with 4-layer analysis (rules, behavior, GNN, compliance)

The remote score never downgrades the local score — it can only raise the floor.

## Links

- [Documentation](https://docs.quint.security)
- [Discord](https://discord.gg/quint)
- [Website](https://quint.security)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and development guidelines.
