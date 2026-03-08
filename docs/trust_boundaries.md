# Trust Boundaries (Implemented Runtime)

This document describes the trust boundaries that exist in the current implementation. It is aligned to the runtime code paths in `app/`, `retrieval/`, `tools/`, `policies/`, and `telemetry/audit/`.

## 1) User Boundary

**Boundary:** external requester -> application request entry (`SupportAgentRequest`).

- **What crosses it:** user text, tenant/session identifiers, and channel metadata.
- **What can go wrong:** prompt injection, unsafe disclosure requests, tenant spoofing attempts, malformed or missing context.
- **What controls exist:** request context propagation, policy checks at retrieval/model/tools stages, deny-first behavior when required context is missing.
- **What should be logged:** `request.start`, policy decisions, deny/fallback/error events, and `request.end`.

## 2) Application / Orchestrator Boundary

**Boundary:** orchestrator control plane -> model/retrieval/tool subsystems.

- **What crosses it:** normalized request context, retrieval query envelope, model input envelope, and tool proposal invocations.
- **What can go wrong:** bypassing policy gates, stage ordering regressions, silent failures that continue execution.
- **What controls exist:** explicit policy gates (`retrieval.search`, `model.generate`, `tools.route`), fail-closed blocked responses, structured orchestration trace.
- **What should be logged:** policy decisions per stage, retrieval decision summaries, tool decision summaries, deny/fallback events.

## 3) Model Boundary

**Boundary:** orchestrator/model input -> model output text.

- **What crosses it:** user text plus retrieved context and metadata (request/session/tenant/trace/risk tier).
- **What can go wrong:** unsafe responses, instruction-following from malicious input, leakage in generated output.
- **What controls exist:** policy gate before generation, retrieval trust/provenance constraints before context assembly, scenario-based security evals for injection/disclosure behavior.
- **What should be logged:** policy decision for `model.generate`, request lifecycle events, and error events if generation path fails.

## 4) Retrieval Boundary

**Boundary:** orchestrator retrieval query -> secure retrieval service -> raw retriever results.

- **What crosses it:** tenant-scoped query, source allowlist constraints, top-k constraints, retrieved documents.
- **What can go wrong:** cross-tenant retrieval, unallowlisted source usage, malformed constraints, backend exceptions.
- **What controls exist:** deny-by-default query validation, policy-constrained `allowed_source_ids`/`top_k_cap`, fail-closed behavior on policy or backend exceptions.
- **What should be logged:** retrieval policy decision, retrieval decision event with doc counts and effective source allowlist.

## 5) Source / Document Boundary

**Boundary:** raw documents -> accepted retrieval documents.

- **What crosses it:** source registration metadata, trust metadata, provenance metadata, content chunks.
- **What can go wrong:** unknown/disabled source usage, cross-tenant source mappings, missing trust metadata, missing/invalid provenance, low-trust domain inclusion.
- **What controls exist:** source registration lookup, tenant/source matching, trust-domain allowlist enforcement, required trust metadata/provenance checks, filter hooks with fail-closed exception handling.
- **What should be logged:** retrieval decision outcomes and downstream deny/error events for blocked requests.

## 6) Tool Boundary

**Boundary:** tool invocation request -> secure tool router -> registry execution.

- **What crosses it:** tool name/action/arguments plus request/actor/tenant metadata.
- **What can go wrong:** unauthorized tool usage, forbidden argument submission, direct execution bypass of router mediation, rate-limit abuse.
- **What controls exist:** centralized router checks (allow/deny/require_confirmation), policy `tools.invoke` check, forbidden tool/field checks, rate limiting, registry execution secret guard against direct execution.
- **What should be logged:** tool execution attempt summaries, tool decisions, confirmation-required events, deny events.

## 7) Policy Boundary

**Boundary:** policy artifacts -> runtime enforcement decisions.

- **What crosses it:** policy bundle JSON, environment overrides, runtime action/context tuples.
- **What can go wrong:** missing/invalid policy, permissive default behavior on load/validation failure, drift between policy and runtime checks.
- **What controls exist:** `load_policy` safe-fail to restrictive policy, runtime kill switch, explicit action-based policy evaluation feeding retrieval/tool constraints.
- **What should be logged:** policy decisions (action, allow/deny, reason, risk tier), kill-switch-driven denials, fallback activation.

## 8) Telemetry / Audit Boundary

**Boundary:** runtime decision points -> audit sink outputs (memory/JSONL/replay artifacts).

- **What crosses it:** trace/request/actor/tenant identifiers, event type, event payload metadata.
- **What can go wrong:** missing lifecycle events, weak incident reconstruction evidence, silent failures in observability path.
- **What controls exist:** centralized event creation with request identity fields, explicit event types at major decision points, replay artifact generation from timeline.
- **What should be logged:** full lifecycle (`request.start` to `request.end`) plus decision/fallback/deny/error/confirmation events.

## 9) Operator / Admin Boundary

**Boundary:** operators/admins -> policy/config/artifact controls.

- **What crosses it:** policy updates, environment selection, launch-gate execution, evidence review artifacts.
- **What can go wrong:** misconfiguration (e.g., kill switch enabled in production), weak allowlists, missing audit/eval evidence.
- **What controls exist:** launch-gate checks for policy validity, retrieval/tool enforcement configuration, eval outcome health, and audit/replay evidence readiness.
- **What should be logged:** launch-gate reports/check evidence, eval summaries, and policy artifact provenance in deployment workflows.

---

For topology visuals, see `docs/architecture_diagrams.md`. For orchestration and control-flow descriptions, see `docs/architecture.md`. For concrete threat/risk mapping, see `docs/threat_model.md`.
