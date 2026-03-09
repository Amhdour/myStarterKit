# Retrofit Review Mode (Layer Retrofit Services)

This repository is both:
1. a secure starter kit implementation, and
2. a retrofit-review framework for existing agent/RAG systems.

This mode is for assessing a live or legacy system against the control surfaces implemented here.

## 1) Retrofit Assessment Workflow

### Step A — Baseline the existing system
Collect a concrete system map of:
- orchestration entrypoints
- model provider boundaries
- retrieval backends + source boundaries
- tool endpoints and direct execution paths
- MCP-like connectors
- identity/session propagation
- telemetry/audit/replay outputs

Use template: `docs/templates/retrofit_system_profile.template.json`.

### Step B — Control mapping (current vs target)
Map each current control to the target controls in this repo:
- identity model (`identity/models.py`)
- policy checkpoints (`policies/engine.py`)
- retrieval boundaries (`retrieval/service.py`)
- tool mediation (`tools/router.py`, `tools/registry.py`)
- integration inventory (`config/integration_inventory.json`)
- telemetry + replay (`telemetry/audit/*`)
- incident readiness (`docs/incident_response_playbooks.md`)

Use template: `docs/templates/retrofit_control_mapping.template.json`.

### Step C — Missing boundary analysis
For each boundary, record if controls are missing/partial/implemented:
- identity assertion boundary
- policy decision boundary
- retrieval source/tenant boundary
- tool mediation boundary
- integration egress boundary
- audit/replay evidence boundary

Track gaps and compensating controls in the mapping template.

### Step D — Phased compensating controls for live systems
Apply incrementally in production-safe phases:
1. **Observe-only**: instrument identity + audit fields and inventory external boundaries.
2. **Deny-on-critical**: fail closed on identity/policy unavailability and cross-tenant violations.
3. **Control tightening**: enforce tool/integration allowlists, capability checks, drift checks.
4. **Release gates**: require launch-gate + drift + incident-readiness artifacts before rollout.

### Step E — Launch gate in retrofit environments
`launch_gate` still applies, but with client-provided evidence artifacts and manifests:
- security guarantees manifest alignment
- integration inventory completeness
- drift manifest integrity
- incident-readiness docs and evidence

If a retrofit environment cannot produce required evidence yet, classify as blocker or explicit residual risk (never implicit pass).

## 2) Evidence-first distinctions

### Implemented in this repo
- Typed identity/delegation model and validation.
- Policy-first retrieval/tool/integration checks.
- Structured audit + replay artifacts.
- Drift detection and launch-gate blockers.

### Expected client-provided evidence (retrofit)
- Current architecture and dataflow inventory.
- Actual policy bundle(s) and allowlists in use.
- Tool/retrieval/integration registries from production.
- Audit/replay artifacts from representative runtime traces.
- Incident runbook execution evidence from tabletop or real incidents.

### Deferred production hardening (explicit)
- Cryptographic artifact signing/tamper-evidence.
- Full IAM/provider attestation integration.
- Organization-specific incident paging/auto-remediation.

## 3) Reviewer output for retrofit engagements
A retrofit review should produce:
- completed system profile template,
- completed control mapping template,
- evidence checklist (`docs/evidence_pack/retrofit_evidence_checklist.md`),
- launch-gate output with blockers/residuals,
- explicit deferred-hardening list.
