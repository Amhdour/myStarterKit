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
