# quint-proxy

Go MCP proxy for AI agent tool call interception. Enforces policy, scores risk, and produces Ed25519-signed audit logs compatible with `quint verify` and `quint sync`.

## Build

```bash
make build          # local binary
make build-all      # cross-compile for linux/darwin/windows (amd64 + arm64)
make test           # run all tests
make install        # install to $GOPATH/bin
```

## Usage

```bash
quint-proxy --name <server-name> [--policy <path>] -- <command> [args...]
```

### Example: Claude Code MCP server

In `claude.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "./quint-proxy",
      "args": ["--name", "filesystem", "--", "npx", "@anthropic/mcp-fs"]
    }
  }
}
```

### Flags

| Flag | Description |
|------|-------------|
| `--name` | MCP server name (required, used in audit log) |
| `--policy` | Path to `policy.json` or directory containing it |
| `--version` | Print version and exit |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `QUINT_DATA_DIR` | Override default data directory (`~/.quint`) |
| `QUINT_PASSPHRASE` | Passphrase for encrypted Ed25519 private key |
| `QUINT_RISK_SERVICE_URL` | Optional gRPC endpoint for ML risk scoring (e.g., `localhost:50051`) |

## Architecture

```
Parent (Claude) ←→ quint-proxy ←→ Child (MCP server)
         stdin/stdout    stdin/stdout
```

The proxy sits between the AI agent and the MCP server, intercepting all JSON-RPC messages on stdin/stdout:

1. **Policy enforcement** — tool calls checked against `policy.json` (glob matching, first-match-wins)
2. **Risk scoring** — built-in patterns + argument analysis + behavior tracking
3. **Audit logging** — every message signed with Ed25519, chain-linked with SHA-256, stored in SQLite
4. **Optional gRPC** — external ML risk service for enhanced scoring (100ms timeout, falls back to local)

## Compatibility

Audit entries are byte-identical to the TypeScript CLI's format:

- Same SQLite schema (`quint.db`)
- Same canonical JSON encoding
- Same Ed25519 signing (PKCS8/SPKI PEM)
- Same encrypted keystore format (`QUINT-ENC-V1`)

Verify with: `quint verify --all` / `quint sync`

## Dependencies

- `modernc.org/sqlite` — pure Go SQLite (no CGO)
- `golang.org/x/crypto` — scrypt for encrypted keystore
- `google.golang.org/grpc` — optional gRPC risk service client
- Everything else is stdlib
