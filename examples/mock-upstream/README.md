# mock-upstream

A minimal MCP-compatible HTTP server for local development and CI testing.

## Tools exposed

| Tool name | Description | Arguments |
|-----------|-------------|-----------|
| `echo` | Returns input text unchanged | `text: string` |
| `time.now` | Current UTC time (RFC3339) | none |

## Running

```bash
go run ./examples/mock-upstream
# Listening on :9090
```

## Endpoints

| Path | Purpose |
|------|---------|
| `POST /` | JSON-RPC 2.0 — handles `initialize`, `tools/list`, `tools/call` |
| `GET /health` | Health check (returns `200 ok`) |

## Example

```bash
# List tools
curl -s -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq .

# Call echo
curl -s -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}' | jq .
```

> This server is intentionally minimal. It has no auth, no persistence, and is
> not suitable for production use.
