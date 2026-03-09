# Secrets Handling Guide

## Principles

- Never embed raw secrets in config files.
- Use secret references (`provider:name`) for all credential-bearing values.
- Fail startup when required secret references are missing or inaccessible.
- Redact secrets in logs, audit records, replay artifacts, and exception-related payloads.

## Provider patterns implemented

This starter kit includes a provider abstraction in `app/secrets.py`:
- `SecretProvider` interface
- `EnvSecretProvider` for local fallback (`env:NAME`)
- `StaticMapSecretProvider` demo provider for managed-secret reference patterns (`vault:*`, `sm:*`) used in tests/examples

Allowed reference prefixes:
- `env:<NAME>`
- `vault:<path-or-key>`
- `sm:<path-or-key>`

> `vault:` and `sm:` are **integration patterns** in this repository. They demonstrate reference shape and fail-closed behavior without binding to a specific vendor SDK.

## Startup validation behavior

`validate_secret_config(...)` enforces:
- required secret references must resolve,
- sensitive values must be references (not inline secrets),
- optional provider policy checks:
  - `require_managed_providers`
  - `allow_env_fallback`

Example (`config/settings.template.yaml`):

```yaml
secrets:
  provider_policy:
    allow_env_fallback: true
    require_managed_providers: false
  required_secret_refs:
    - env:SUPPORT_AGENT_SIGNING_KEY
  sensitive_values:
    mcp_connector_token: vault:kv/support#mcp_connector_token
    webhook_secret: sm:support/webhook_secret
```

For production-sensitive flows, set:
- `require_managed_providers: true`
- `allow_env_fallback: false`

so unresolved/unsafe env fallback is denied at startup.

## Local development

1. Keep local config references as `env:` values.
2. Export required env vars for local run.
3. Run `python main.py` to verify startup secret checks.

## Deployment integration guidance

- Resolve `vault:`/`sm:` references by wiring provider implementations to your secret manager.
- Keep provider errors redaction-safe; do not include resolved values in exceptions.
- Treat missing/inaccessible required secrets as release blockers.

## Redaction points

- Audit sink payload serialization (`telemetry/audit/sinks.py`)
- Audit sink identity auth-context serialization
- Replay timeline payload rendering (`telemetry/audit/replay.py`)
- Generic nested payload redaction utility (`app.secrets.redact_mapping`)
- Startup error rendering (`app.secrets.safe_error_message`)
