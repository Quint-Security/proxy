# Contributing to Quint

## Build

```bash
make build          # local binary
make build-all      # cross-compile for linux/darwin/windows (amd64 + arm64)
make test           # run all tests
make install        # install to $GOPATH/bin
```

Requires Go 1.24+. No CGO — uses pure Go SQLite.

## Architecture

```
cmd/proxy/           CLI entry point and subcommands
internal/
  audit/             SQLite audit log, Ed25519 signing, chain verification
  auth/              Agent identity and scope management
  connect/           OAuth provider integration
  credential/        Encrypted credential vault
  crypto/            Ed25519, SHA-256, AES-256-GCM, canonical JSON
  dashboard/         Web dashboard server
  export/            Audit proof bundle building and verification
  gateway/           Multi-server gateway mode
  httpproxy/         HTTP/SSE MCP server proxy
  intercept/         Policy matching, tool call inspection
  log/               Logging
  ratelimit/         Rate limiting
  relay/             Stdio relay (parent <-> proxy <-> child)
  risk/              Risk scoring engine and patterns
  sync/              Audit log cloud sync
proto/               gRPC protobuf definitions
```

## Message flow

```
Parent JSON-RPC -> relay.OnParentMessage -> intercept.InspectRequest
  -> Policy check
  -> Risk score
  -> Audit log (signed + chain-linked)
  -> Forward or deny
Child JSON-RPC  -> relay.OnChildMessage  -> intercept.InspectResponse
  -> Audit log
  -> Forward to parent
```

## Audit format

Entries are byte-identical to the TypeScript CLI's format:

- Same SQLite schema (`quint.db`)
- Same canonical JSON encoding (sorted keys, no HTML escaping)
- Same Ed25519 signing (PKCS8/SPKI PEM)
- Same encrypted keystore format (`QUINT-ENC-V1` with scrypt + AES-256-GCM)

Cross-language verification works via `quint verify --all`.

## Environment variables

| Variable | Description |
|----------|-------------|
| `QUINT_DATA_DIR` | Override data directory (default: `~/.quint`) |
| `QUINT_PASSPHRASE` | Passphrase for encrypted Ed25519 private key |
| `QUINT_RISK_SERVICE_URL` | Optional gRPC endpoint for ML risk scoring |
| `QUINT_AGENT` | Agent name for identity resolution |

## Dependencies

- `modernc.org/sqlite` — pure Go SQLite (no CGO)
- `golang.org/x/crypto` — scrypt for encrypted keystore
- `google.golang.org/grpc` — optional gRPC risk service client
- Everything else is stdlib

## Submitting changes

1. Fork the repo
2. Create a branch from `main`
3. Run `make test` and ensure all tests pass
4. Open a PR with a clear description of the change
