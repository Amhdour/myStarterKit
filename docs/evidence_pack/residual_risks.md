# Residual Risks

This file tracks **known gaps that are not claimed as implemented guarantees**.

## How to read this file

- Items below are residual risks or deferred hardening work.
- They should not be interpreted as implemented controls.
- Release decisions should rely on launch-gate blockers/residuals plus machine evidence artifacts.

## Current residual risks

1. **Identity and authorization integration is starter-level**
   - External IdP/IAM/ABAC integration is not implemented.
2. **Artifact tamper-evidence is not implemented**
   - Evidence files are local JSON/JSONL and are not cryptographically signed.
3. **Provider-side hardening is out of scope in this baseline**
   - Secrets management, key rotation, and provider hardening patterns are not implemented end to end.
4. **Threat-model maintenance process is lightweight**
   - The repository includes threat-model docs, but not a full formal threat-model workbook process.

## Deferred items (not implemented guarantees)

- Production IAM/SSO enforcement and fine-grained RBAC/ABAC bindings.
- Immutable/signed evidence storage and provenance attestations.
- External key-management integration for runtime and artifact pipelines.
- Expanded moderation/DLP controls for model outputs.

## Risk tracking fields (for future updates)

- Risk ID
- Description
- Severity
- Mitigation plan
- Owner
- Target date

## Identity-model residual risks

- Legacy call paths that construct compatibility identities (`legacy-*`) should be removed over time to enforce fully explicit caller identity at every entrypoint.
- `auth_context` values are structurally validated but not cryptographically verified in this starter kit.
- Delegation-chain trust depends on upstream attestation quality; invalid structure is blocked, but semantic correctness of delegation reasons is policy/process-controlled.

## Delegation residual risks

- Delegation timestamps are validated for format and expiry but are not bound to signed time-attestation in this starter baseline.
- Parent authority is enforced via chain scope continuity and capability narrowing; full external principal attestation remains future work.

## MCP residual risks

- Transport security is delegated to the configured MCP transport implementation; baseline controls assume transport plugin correctness.
- Schema validation is structural and does not yet enforce cryptographic origin attestation of endpoint identity.

## Capability-token residual risks

- Capability tokens are currently JSON payloads validated structurally; signature-based token authenticity is future hardening work.
- One-time replay protection is process-local; distributed shared-state replay defense is future work.

## High-risk tool isolation residual risks

- Isolation is currently enforced as a declarative/runtime control interface; full containerized isolation execution backends are deferred work.
- Launch gate now surfaces high-risk readiness gaps, but environment-level sandbox guarantees depend on deployment/runtime integration.
