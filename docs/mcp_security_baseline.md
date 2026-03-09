# MCP Security Baseline

This starter kit treats MCP-style servers/resources as **untrusted integration boundaries** by default.

## Baseline controls

- Server allowlisting via explicit `MCPServerProfile` registration.
- Trust labels per server: `trusted`, `restricted`, `untrusted`.
- Tool/resource capability allowlisting per server profile.
- Request/response schema validation at protocol boundary.
- Origin attribution in payload and audit events (`server_id`, `endpoint`, trust label).
- Timeout enforcement (`timeout_ms`) per server profile.
- Request/response size limits (`max_request_bytes`, `max_response_bytes`).
- Retry limits (`retry_limit`) with bounded retry loops.
- Protocol error handling with deny-by-default after retry exhaustion.
- Tenant-boundary enforcement between actor identity and server profile.
- Untrusted endpoints denied by default.

## Runtime enforcement path

1. Tool invocation enters `SecureToolRouter` (policy-mediated, audited, no direct execution).
2. Router executes registered MCP executor only through registry execution guard.
3. `SecureMCPGateway` validates identity, server allowlist/trust, capability allowlist, tenant boundary, schema, limits, timeout/retries.
4. Any failure triggers deny/error audit evidence and fails closed.

## Non-bypass guarantees

- MCP tools still require tool router mediation.
- MCP tools still require policy engine decisions (`tools.invoke`).
- MCP calls are auditable with explicit origin attribution.
- Unknown/untrusted endpoints never get implicit access.
