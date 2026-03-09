# Tool Capability Authorization Baseline

Sensitive tool execution must carry an explicit scoped capability token.

## Token fields

- `capability_id`
- `actor_id`
- `tool_id`
- `allowed_operations`
- `tenant_id`
- `issued_at`
- `expires_at`
- `justification`
- `policy_version`

## Enforcement rules

- Tokens are policy-governed at issuance (`tools.issue_capability`) and audited (`capability.issued`).
- Sensitive tool execution without token is denied.
- Token validation is fail-closed on parse errors.
- Token must match actor, tenant, tool, operation, policy version, and valid time window.
- Token replay is denied via one-time capability consumption.
- Over-scoped tokens are denied.

## Audit expectations

- Issuance and usage/denial events are recorded (`capability.issued`, `capability.used`, `capability.denied`).
