# MCPShield

**MCP gateway with policy enforcement, deny-by-default access control, and tamper-evident audit logging.**

MCPShield sits between AI agents and their MCP tool servers. Every `tools/call` is evaluated against a declarative policy before being forwarded. Denied calls are never sent upstream. All decisions are logged.

> **Status:** v0.1.0-alpha — functional core, not yet production-hardened. See [Alpha Limitations](#alpha-limitations).

---

## Why MCPShield

AI agents calling tools is useful. Agents calling `filesystem.write_file` with unconstrained arguments, at unconstrained rate, logged nowhere, is not.

MCPShield addresses three specific problems:

**Tool governance.** Which tools can this agent call? Which arguments are acceptable? Without a policy layer, the answer is "anything the upstream exposes."

**Deny-by-default.** Allowlists are safer than blocklists. MCPShield blocks everything unless explicitly permitted. A misconfigured policy means fewer tools, not unlimited access.

**Audit and replay.** When something goes wrong, you need to know exactly what the agent called, with what arguments, and what the upstream returned. MCPShield records this with a cryptographic hash chain and supports replaying sessions against updated policies.

---

## Features

| Feature | Status |
|---------|--------|
| MCP `initialize`, `tools/list`, `tools/call` | ✓ |
| Deny-by-default policy engine | ✓ |
| Tool allowlists (by name, by toolset) | ✓ |
| Argument-level validation (regex, one-of, max-length) | ✓ |
| Rate limiting per-tool or per-client | ✓ |
| YAML policy with named rules | ✓ |
| Atomic hot-reload via SIGHUP | ✓ |
| Multi-upstream aggregation with prefix namespacing | ✓ |
| SQLite audit log (WAL, async, hash-chain integrity) | ✓ |
| Deterministic replay (read-only, policy-check modes) | ✓ |
| Prometheus metrics (`/metrics`) | ✓ |
| Structured JSON logs (slog) | ✓ |
| API key auth (Bearer token, SHA-256 stored) | ✓ |
| `${ENV_VAR}` interpolation in config | ✓ |

---

## Architecture

```
  MCP Client (IDE / agent)
        │  JSON-RPC 2.0
        │  HTTP POST
        ▼
  ┌─────────────────────────────┐
  │        MCPShield            │
  │  ┌──────────┐  ┌─────────┐ │
  │  │  Auth    │→ │ Policy  │ │   ← deny-by-default, arg validation,
  │  └──────────┘  │ Engine  │ │     rate limiting
  │                └────┬────┘ │
  │  ┌──────────┐       │      │
  │  │  Audit   │←──────┤      │
  │  │  Logger  │       │      │   ← async, SQLite WAL, hash-chain
  │  └──────────┘  ┌────▼────┐ │
  │                │Upstream │ │
  │                │Manager  │ │   ← prefix namespacing, TTL cache
  └────────────────┴────┬────┘─┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   github-mcp      postgres-mcp    filesystem-mcp
   (HTTP)          (HTTP)          (HTTP)
```

**Policy evaluation order:**
1. API key auth
2. Rate limit check (O(1) fixed-window counter)
3. Tool name allowlist check (O(1) map)
4. Deny-rule matching (argument regex guards)
5. Allow-rule confirmation → forward to upstream

---

## Quickstart

**Requirements:** Docker, Docker Compose.

```bash
git clone https://github.com/haze518/mcpshield
cd mcpshield
docker compose up --build
```

Wait for both services to be ready, then:

```bash
# 1. MCP handshake
curl -s -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "curl", "version": "1.0"}
    }
  }' | jq .

# 2. List available tools (policy-filtered)
curl -s -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq .

# 3. Call a tool
curl -s -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "mock.echo", "arguments": {"text": "hello world"}}
  }' | jq .

# 4. Try a denied tool (not in policy → blocked)
curl -s -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {"name": "mock.time.now", "arguments": {}}
  }' | jq .
```

The demo stack runs with `auth.type: none`. See [API Key Auth](#api-key-auth) to enable authentication.

---

## Configuration

### Full config reference

```yaml
# mcpshield.yaml

server:
  listen: ":8080"
  request_timeout: "60s"         # default: 60s; JSON-RPC request context deadline
  read_timeout: "30s"            # default: 30s; inbound HTTP read timeout
  write_timeout: "30s"           # default: 30s; outbound HTTP write timeout
  idle_timeout: "120s"           # default: 120s; keep-alive timeout
  max_request_bytes: 1048576     # default: 1 MiB; inbound request body limit
  warmup_timeout: "30s"          # default: 30s; per startup warmup attempt
  warmup_retry_interval: "5s"    # default: 5s; readiness retry cadence
  session_ttl: "30m"             # default: 30m
  session_max_entries: 10000     # default: 10000

auth:
  type: none  # "none" | "api_key"

policy_file: /etc/mcpshield/policy.yaml

upstreams:
  - id: github
    prefix: github
    url: https://api.github.com/mcp   # ${GITHUB_MCP_URL} works too
    request_timeout: "30s"            # default: 30s; per upstream HTTP request
    max_response_bytes: 4194304       # default: 4 MiB; upstream response cap
    tools_cache_ttl: "10s"            # default: 10s; merged tool cache freshness
    refresh_timeout: "30s"            # default: 30s; background tool refresh budget
    headers:
      Authorization: "Bearer ${GITHUB_TOKEN}"

  - id: postgres
    prefix: pg
    url: http://localhost:3001/mcp

observability:
  metrics:
    enabled: true
    include_client_id: false  # adds client_id label to rate-limit metrics

audit:
  enabled: true
  backend: sqlite
  sqlite:
    path: /var/lib/mcpshield/audit.db
    wal: true
  write:
    batch_max_events: 256
    batch_max_delay: "100ms"
    channel_size: 4096
    mode: drop   # "drop" | "block" | "fail_closed"
  retention:
    max_age: "90d"
    max_size: "10GB"
    vacuum_interval: "24h"
  integrity:
    hash_chain: true
```

Defaults are applied in `pkg/config` when a field is omitted. Explicit duration and byte-limit overrides must be greater than zero.

`/readyz` reports `200` only after the initial warmup has completed successfully at least once. Startup warmup retries in the background using `server.warmup_timeout` and `server.warmup_retry_interval`; the process does not fail fast by default.

`tools_cache_ttl` and `refresh_timeout` are configured per upstream in YAML, but MCPShield maintains one merged discovery cache. When upstreams specify different values, the effective shared manager value is the smallest configured one.

### Environment variable interpolation

Any `${VAR}` reference in the config file is expanded from the environment before parsing. This covers URLs, headers, paths, and any other string value:

```yaml
upstreams:
  - id: github
    url: "${GITHUB_MCP_URL}"
    headers:
      Authorization: "Bearer ${GITHUB_TOKEN}"
```

---

## Policy

### Schema

```yaml
version: "1"

defaults:
  action: deny  # deny-by-default (this is also the built-in default)

toolsets:
  read_only:
    tools:
      - github.get_file_contents
      - github.search_repositories
      - filesystem.read_file

rules:
  # Rules are evaluated top-to-bottom. First match wins.

  - name: allow-read-only
    action: allow
    toolset: read_only
    rate_limit:
      max: 100
      window: "1m"
      per: client   # "global" | "client"

  - name: block-sensitive-paths
    action: deny
    tools:
      - filesystem.read_file
    args:
      path:
        not_match: "^/etc/|^/root/|\\.\\./|\\.ssh"
    reason: "Sensitive path access blocked"

  - name: allow-single-tool
    action: allow
    tools:
      - github.create_issue
```

### Argument validators

Each argument in the `args` map accepts:

| Field | Type | Description |
|-------|------|-------------|
| `match` | regex | Value must match |
| `not_match` | regex | Value must not match |
| `one_of` | list | Value must be one of these strings |
| `max_len` | int | Maximum string length |

Validators are compiled at load time. A missing required argument fails validation.

### Tool namespacing

Tools are namespaced by their upstream `prefix`. An upstream with `prefix: github` that exposes `create_issue` is reachable as `github.create_issue`. Policy rules use the namespaced names.

---

## Running Locally

```bash
# Build
go build -o mcpshield ./cmd/mcpshield

# Validate a policy file before deploying
./mcpshield validate-policy --file policy.yaml

# Start
./mcpshield serve --config config.yaml

# Hot-reload policy without restart
kill -HUP <pid>
```

---

## CLI Commands

```
mcpshield serve               Start the gateway
  --config PATH               Config file (default: config.yaml)

mcpshield validate-policy     Parse and validate a policy YAML file
  --file PATH                 Policy file path

mcpshield validate-upstream   Test connectivity to an upstream
  --config PATH               Config file
  --upstream ID               Upstream ID from config

mcpshield audit verify        Verify hash-chain integrity of audit log
  --db PATH                   Path to audit.db

mcpshield audit export        Stream audit events as JSON Lines
  --db PATH                   Path to audit.db
  --since TIMESTAMP           Filter from RFC3339 timestamp (optional)

mcpshield replay              Replay a recorded session
  --db PATH                   Path to audit.db
  --session ID                Session ID to replay
  --mode read-only            Print event timeline (default)
  --mode policy-check         Re-evaluate against a policy file
  --policy PATH               Policy file for policy-check mode
```

---

## API Key Auth

To require authentication, generate a key hash and update the config:

```bash
# Generate a SHA-256 hash for your token:
echo -n "your-secret-token" | sha256sum | awk '{print "sha256:"$1}'
# → sha256:e3b0c44...
```

```yaml
auth:
  type: api_key
  keys:
    - id: dev-team
      key_hash: "sha256:e3b0c44..."  # SHA-256 of the raw token
      client_id: dev-team
    - id: ci-bot
      key_hash: "sha256:a1b2c3..."
      client_id: ci-bot
```

Clients authenticate with:
```
Authorization: Bearer your-secret-token
```

Requests without a valid token receive a JSON-RPC `-32002` error.

---

## Prometheus Metrics

```
GET /metrics
```

| Metric | Labels |
|--------|--------|
| `mcpshield_requests_total` | `method`, `tool`, `decision` |
| `mcpshield_rate_limit_hits_total` | `tool` (+ `client_id` if enabled) |
| `mcpshield_policy_denies_total` | `rule` |
| `mcpshield_audit_dropped_total` | `backend` |

---

## Audit Log

The SQLite audit backend records every `tools/call` decision with arguments and upstream response. Events are linked by a SHA-256 hash chain — any tampering (direct database edits) is detectable.

```bash
# Verify integrity
mcpshield audit verify --db /var/lib/mcpshield/audit.db

# Export recent events
mcpshield audit export --db /var/lib/mcpshield/audit.db \
  --since "2026-01-01T00:00:00Z" > audit.jsonl
```

**Replay against a new policy:**
```bash
mcpshield replay \
  --db /var/lib/mcpshield/audit.db \
  --session sess_abc123 \
  --mode policy-check \
  --policy new-policy.yaml
```

This shows which historical calls the new policy would have blocked or allowed, without re-executing them against real upstreams.

---

## Security Model

**Authentication:** API key (Bearer token). Keys are stored as SHA-256 hashes — the raw token is never persisted. `auth.type: none` is available for development but must not be used in production.

**Policy evaluation:** Deny-by-default. A tool must appear in at least one `allow` rule and pass all argument validators of matching rules. Any error in policy evaluation denies the request.

**Audit integrity:** Events are linked by `SHA-256(prev_hash || canonical_json)`. The hash chain is verified end-to-end on `audit verify`. An audit gap under extreme load is recorded as a dropped-event counter (`mcpshield_audit_dropped_total`).

**TLS:** MCPShield does not terminate TLS. Deploy behind a reverse proxy (nginx, Caddy, Envoy) that handles certificates. This is intentional — MCPShield focuses on MCP semantics, not TLS management.

**Upstreams:** Upstream URLs and credentials are set in config. `${ENV_VAR}` interpolation is supported; tokens are never logged.

---

## Alpha Limitations

This is v0.1.0-alpha. Known limitations:

- **HTTP upstreams only.** stdio transport (for local process upstreams) is planned for v0.2.
- **No TLS termination.** Use a reverse proxy.
- **No approval workflow.** `require_approval` action is not yet implemented.
- **No web UI or control-plane API.** Policy changes require file edits + SIGHUP.
- **No distributed mode.** Single-node only; no shared state across gateway instances.
- **No resources/prompts proxying.** Only `tools/*` methods are handled.
- **Basic auth only.** JWT/OIDC planned for v1.0.
- **No OTel tracing.** Prometheus metrics and structured logs are available; OTel traces are planned.
- **Policy expressiveness.** YAML validators cover most cases; CEL expressions are planned for v0.3 for complex predicates.
- **No automatic retry.** Tool call failures return an error immediately (by design for side-effecting tools).

---

## Roadmap

**v0.2 (next)**
- stdio upstream transport (spawn local MCP processes)
- `mcpshield bench` — built-in load benchmark tool
- Improved upstream error surfacing

**v1.0**
- JWT/OIDC authentication
- Approval workflow (webhook callback)
- CEL expressions for complex policy predicates
- OTel trace export (OTLP)
- Active upstream health checking + circuit breaker
- Control-plane HTTP API for policy management

---

## License

MIT — see [LICENSE](LICENSE).
