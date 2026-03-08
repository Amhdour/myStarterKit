# Trust Boundaries (Implementation-Aligned)

This document describes trust boundaries that are implemented in this repository and maps each boundary to concrete enforcement points.

## Boundary matrix

| Boundary | Primary enforcement points |
|---|---|
| User boundary | `app/orchestrator.py`, `policies/engine.py` |
| Application / orchestrator boundary | `app/orchestrator.py` |
| Model boundary | `app/orchestrator.py`, `app/modeling.py` |
| Retrieval boundary | `retrieval/service.py`, `retrieval/registry.py` |
| Source / document boundary | `retrieval/contracts.py`, `retrieval/service.py` |
| Tool boundary | `tools/router.py`, `tools/registry.py`, `tools/execution_guard.py` |
| Policy boundary | `policies/loader.py`, `policies/schema.py`, `policies/engine.py` |
| Telemetry / audit boundary | `telemetry/audit/contracts.py`, `telemetry/audit/sinks.py`, `telemetry/audit/replay.py` |
| Operator / admin boundary | `launch_gate/engine.py`, `evals/runner.py` |

---

## 1) User boundary

**What crosses it**
- `SupportAgentRequest` fields from external callers (`request_id`, session actor/tenant metadata, `user_text`).

**What can go wrong**
- Prompt injection, tenant spoofing, unsafe disclosure requests, malformed request metadata.

**What controls exist**
- Orchestrator policy gates for `retrieval.search`, `model.generate`, and `tools.route` before downstream actions.
- Blocked responses when policy denies or exceptions occur.

**What should be logged**
- `request.start`, stage `policy.decision`, `deny.event` / `fallback.event` / `error.event`, and `request.end`.

## 2) Application / orchestrator boundary

**What crosses it**
- Internal calls from orchestrator to retrieval, model, and tool routing subsystems.

**What can go wrong**
- Stage-order regressions, policy bypass, missing deny/fallback evidence.

**What controls exist**
- Explicit, ordered policy checks and stage-local deny handling in `SupportAgentOrchestrator.run(...)`.
- Context propagation (`request_id`, `trace_id`, actor, tenant) into downstream calls.

**What should be logged**
- Policy decisions for each stage, retrieval/tool decision events, and lifecycle start/end.

## 3) Model boundary

**What crosses it**
- `ModelInput` containing user text, retrieved context, and metadata.

**What can go wrong**
- Unsafe model output, over-disclosure, malicious instruction adherence.

**What controls exist**
- Policy gate before model invocation.
- Retrieval filtering/trust/provenance checks before model context is assembled.
- Security eval scenarios targeting unsafe disclosure and injection behavior.

**What should be logged**
- Model-stage `policy.decision` plus any `deny.event`/`error.event` and lifecycle events.

## 4) Retrieval boundary

**What crosses it**
- Tenant-scoped `RetrievalQuery` with requested source IDs and top-k.
- Raw documents returned by retriever backend.

**What can go wrong**
- Cross-tenant retrieval, source allowlist bypass, permissive behavior on policy/backend failure.

**What controls exist**
- Fail-closed retrieval path when policy is missing/invalid/denied.
- Policy-constrained `allowed_source_ids`, `top_k_cap`, and trust-domain filtering.
- Tenant/source checks through source registry.

**What should be logged**
- Retrieval-stage `policy.decision`, `retrieval.decision`, and deny/error events where applicable.

## 5) Source / document boundary

**What crosses it**
- Source registrations, trust metadata, provenance metadata, and document content.

**What can go wrong**
- Unknown/disabled source use, tenant/source mismatch, missing trust metadata, missing provenance.

**What controls exist**
- Registry validation and enabled-source checks.
- Trust metadata and provenance requirements retained as safe defaults.
- Document acceptance only when source + trust + provenance checks pass.

**What should be logged**
- Retrieval decisions and downstream deny/error events for blocked retrieval paths.

## 6) Tool boundary

**What crosses it**
- `ToolInvocation` (`request_id`, actor, tenant, tool/action/arguments/confirmation).

**What can go wrong**
- Unauthorized tool calls, forbidden argument abuse, direct execution bypass.

**What controls exist**
- Centralized decisioning in `SecureToolRouter.route(...)` for allow/deny/require-confirmation.
- Router-mediated execution only (`mediate_and_execute`) with runtime execution guard + registry secret checks.
- Policy-aware deny-by-default behavior when policy engine is unavailable.

**What should be logged**
- `tool.execution_attempt`, `tool.decision`, `confirmation.required`, and `deny.event`.

## 7) Policy boundary

**What crosses it**
- Policy bundle loading, validation, and action-specific policy evaluations.

**What can go wrong**
- Invalid/missing policy artifacts, unintended permissive defaults.

**What controls exist**
- Policy loader/schema validation with restrictive fallback behavior.
- Runtime policy enforcement for retrieval/tool routing/tool invocation constraints.
- Kill-switch and fallback-to-RAG controls enforced via policy decisions.

**What should be logged**
- `policy.decision` with reason/risk-tier and associated deny/fallback events.

## 8) Telemetry / audit boundary

**What crosses it**
- Structured audit events into in-memory/JSONL sinks and replay artifacts.

**What can go wrong**
- Missing lifecycle coverage, incomplete decision reconstruction, sensitive payload leakage.

**What controls exist**
- Structured `AuditEvent` contract with request/actor/tenant/trace metadata.
- JSONL sink and replay artifact generation with decision summaries + coverage flags.
- Replay payload sanitization for sensitive fields.

**What should be logged**
- Full request lifecycle and key decisions (`request.start/end`, policy/retrieval/tool decisions, deny/fallback/error).

## 9) Operator / admin boundary

**What crosses it**
- Policy/config updates, evaluation artifacts, launch readiness decisions.

**What can go wrong**
- Promotion without evidence, ignoring residual risks, misconfigured policy/evidence paths.

**What controls exist**
- Launch-gate checks over aligned eval summary+jsonl, replay artifacts, and telemetry evidence.
- Explicit blocker vs residual-risk classification in launch-gate reports.
- Security guarantees verification manifest/runner linking invariants to code/tests/evidence.

**What should be logged**
- Launch-gate report outputs, referenced evidence paths, and verification summary artifacts.

---

## Related docs

- `docs/architecture.md`
- `docs/architecture_diagrams.md`
- `docs/deployment_architecture.md`
- `docs/security_guarantees.md`
- `docs/threat_model.md`
- `docs/evidence_pack/security_guarantees_verification.md`
