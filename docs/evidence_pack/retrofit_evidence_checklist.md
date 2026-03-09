# Retrofit Evidence Checklist

Use this checklist when applying this kit to an existing weak/legacy system.

## Identity
- [ ] Actor identity includes `actor_id`, `actor_type`, `tenant_id`, `session_id`.
- [ ] Delegation evidence exists where delegated actors execute actions.
- [ ] Missing/malformed identity is denied (with audit evidence).

## Policy enforcement
- [ ] Policy decision events exist for retrieval/model/tool/integration actions.
- [ ] Deny-by-default is observable when policy state is invalid/unavailable.
- [ ] Tenant mismatch denials are visible in audit/replay.

## Retrieval boundaries
- [ ] Retrieval source allowlist exists per tenant.
- [ ] Cross-tenant retrieval attempts are denied and logged.
- [ ] Provenance/trust metadata are present in retrieval evidence.

## Tool authorization
- [ ] All sensitive tools route through tool router.
- [ ] Capability/confirmation/rate-limit evidence is present for sensitive/high-risk tools.
- [ ] Direct tool execution bypass attempts are denied.

## Telemetry
- [ ] Audit events include `trace_id`, `request_id`, actor/tenant fields.
- [ ] Secret-bearing fields are redacted in serialized events.
- [ ] Deny/fallback/error event evidence is present.

## Replay
- [ ] Replay artifacts reconstruct request lifecycle and core decisions.
- [ ] Replay includes actor/tenant/delegation context.
- [ ] Replay supports investigation of deny/error paths.

## Incident readiness
- [ ] Incident playbooks exist for required classes.
- [ ] Trigger conditions map to concrete audit/replay fields.
- [ ] Post-incident artifact checklist is used and retained.

## External integration inventory
- [ ] All external integrations have explicit inventory records.
- [ ] Unknown/undocumented integration targets are denied.
- [ ] Inventory aligns with policy allowlists and drift manifest.

## Deferred hardening (must be explicit)
- [ ] Gaps (e.g., artifact signing/IAM attestations) are recorded in residual risks.
