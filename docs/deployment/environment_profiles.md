# Environment Deployment Profiles (Local / Staging / Production)

This document maps repository controls to deployment environments.

> **Important**: These are concrete architecture artifacts for this starter kit, but they are still **example architecture** unless backed by runtime evidence and launch-gate outputs.

## Source artifacts

- `config/deployments/environment_profiles.json`
- `config/deployments/topology.spec.json`
- `config/deployments/security_dependency_inventory.json`

## Environment summaries

### Local
- App runtime: single process.
- Policy delivery: local file (`policies/bundles/default/policy.json`).
- Telemetry/audit: local JSONL artifacts.
- High-risk sandbox: local subprocess demo path.
- Security guarantees: useful for development validation, **not production-hard isolation**.

### Staging
- App runtime: containerized staging service.
- Policy delivery: CI artifact path.
- Retrieval/MCP/telemetry integrations wired to staging dependencies.
- High-risk sandbox evidence required before release decisions.
- Security guarantees: pre-production quality signal with launch-gate evidence requirements.

### Production
- App runtime: hardened containerized deployment.
- Policy delivery: signed/controlled artifact distribution expected.
- Audit/replay storage: immutable retention-controlled target expected.
- High-risk tool operations must remain policy-mediated and evidence-backed.
- Security guarantees: only claims backed by artifacts and launch-gate checks should be asserted.

## Trust boundary keys (required per environment)

Each environment profile includes explicit trust boundaries for:
- `app_runtime`
- `policy_bundle_delivery`
- `retrieval_backend`
- `telemetry_sink`
- `audit_replay_storage`
- `high_risk_tool_sandbox`
- `secret_source`
- `iam_provider`

## Difference in guarantees

- Local focuses on developer-verifiable behavior and deterministic tests.
- Staging adds integration confidence and evidence collection requirements.
- Production adds stronger assumptions (artifact integrity, immutable storage, managed identity and secrets) that must be demonstrated operationally.

## Deferred / non-asserted

- This repository does not itself enforce cloud control-plane settings.
- Production readiness still depends on external deployment controls and evidence pipelines.
