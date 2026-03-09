# Secrets Handling Guide

## Principles

- Never embed raw secrets in config files.
- Use secret references (`env:NAME`) for all credential-bearing values.
- Fail startup when required secret references are missing.
- Redact secrets in logs, audit records, replay artifacts, and exception-related payloads.

## Secret classes

- API keys
- Bearer/access tokens
- Service credentials
- Connector secrets
- Signing keys
- Webhook secrets

## Local development

1. Copy config templates and keep only references in YAML:
   - `config/settings.local.yaml`
2. Export required secret env vars (example):
   - `SUPPORT_AGENT_SIGNING_KEY`
   - `MCP_CONNECTOR_TOKEN`
   - `SUPPORT_WEBHOOK_SECRET`
3. Run startup validation (`python main.py`) before local runtime flows.

## Deployment

- Inject env secrets from your secret manager into runtime environment.
- Keep artifact storage and logs free of secret values (redaction is enabled, but avoid sending secrets in payloads).
- Treat missing secret refs as a release blocker for sensitive flows.

## Redaction points

- Audit sink payload serialization
- Audit sink identity auth-context serialization
- Replay timeline payload rendering
- Generic nested payload redaction utility (`app.secrets.redact_mapping`)
