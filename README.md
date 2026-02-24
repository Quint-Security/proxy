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
- **Risk scoring** — built-in patterns detect dangerous arguments, track behavioral anomalies
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

Quint sits between the AI agent and MCP servers on stdin/stdout. No code changes needed — it wraps existing server commands transparently.

## Commands

| Command | Description |
|---------|-------------|
| `quint setup` | Interactive setup wizard |
| `quint start` | Run the gateway |
| `quint status` | Health check |
| `quint dashboard` | Open the web dashboard |
| `quint export` | Export audit proof bundle |
| `quint admin` | Advanced commands |

## Links

- [Documentation](https://docs.quint.security)
- [Discord](https://discord.gg/quint)
- [Website](https://quint.security)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and development guidelines.
