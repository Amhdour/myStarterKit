# Trust Boundaries (Implementation-Aligned)

This document describes trust boundaries that **exist in the current codebase** and maps each boundary to:
- what crosses the boundary,
- what can go wrong,
- implemented controls,
- expected audit logging.

## Boundary map

| Boundary | Primary enforcement locations |
|---|---|
| User boundary | `app/orchestrator.py`, `policies/engine.py` |
| Application / orchestrator boundary | `app/orchestrator.py` |
| Model boundary | `app/orchestrator.py`, `app/modeling.py` |
| Retrieval boundary | `retrieval/service.py`, `policies/engine.py`, `retrieval/registry.py` |
| Source / document boundary | `retrieval/contracts.py`, `retrieval/service.py` |
| Tool boundary | `tools/router.py`, `tools/registry.py`, `tools/execution_guard.py`, `policies/engine.py` |
| Policy boundary | `policies/loader.py`, `policies/schema.py`, `policies/engine.py` |
| Telemetry / audit boundary | `telemetry/audit/events.py`, `telemetry/audit/sinks.py`, `telemetry/audit/replay.py` |
| Operator / admin boundary | `launch_gate/engine.py`, `verification/runner.py`, `evals/runner.py` |

---

## 1) User boundary

**What crosses it**
- External request input (`request_id`, session actor/tenant/channel metadata, `user_text`).

**What can go wrong**
- Prompt injection, tenant spoofing, malformed identity context, unsafe disclosure prompts.

**What controls exist**
- Orchestrator runs policy checks before retrieval (`retrieval.search`), generation (`model.generate`), and tools (`tools.route`).
- Fail-closed blocked response path on deny/error.

**What should be logged**
- `request.start`, `policy.decision`, `deny.event`/`fallback.event`/`error.event`, `request.end`.

## 2) Application / orchestrator boundary

**What crosses it**
- Internal hand-offs from orchestrator to retrieval service, model, tool router, and audit sink.

**What can go wrong**
- Stage bypass or reordering, missing policy checkpoints, missing deny/fallback evidence.

**What controls exist**
- Ordered stage flow in `SupportAgentOrchestrator.run(...)`.
- Explicit deny/fallback handling at each decision stage.
- Request/actor/tenant/trace context propagation to downstream systems.

**What should be logged**
- Policy decisions per stage plus retrieval/tool decision events and lifecycle start/end.

## 3) Model boundary

**What crosses it**
- `ModelInput` with user text + retrieval context + metadata.

**What can go wrong**
- Unsafe generation, disclosure, compliance with malicious instructions.

**What controls exist**
- Model generation occurs only after policy allow for `model.generate`.
- Retrieval context is pre-filtered by tenant/source/trust/provenance controls.
- Security eval scenarios exercise unsafe disclosure and injection behavior.

**What should be logged**
- `policy.decision` for model stage and any deny/error lifecycle outcomes.

## 4) Retrieval boundary

**What crosses it**
- Tenant-bound `RetrievalQuery` and backend-returned documents.

**What can go wrong**
- Cross-tenant leakage, unauthorized source access, permissive behavior when policy/backend fails.

**What controls exist**
- Fail-closed on missing/invalid query context.
- Fail-closed when policy engine is absent, policy evaluate fails, or policy denies.
- Policy-constrained source allowlists and trust-domain filtering.
- Top-k constrained by policy.

**What should be logged**
- `policy.decision` for retrieval, `retrieval.decision`, and deny/error events when blocked.

## 5) Source / document boundary

**What crosses it**
- Source registration metadata, document trust metadata, and provenance/citation metadata.

**What can go wrong**
- Unknown source use, disabled-source use, tenant/source mismatch, missing trust/provenance metadata.

**What controls exist**
- Only tenant-registered, enabled, well-formed sources are eligible.
- Source trust domain must be policy-allowed.
- Trust metadata and provenance checks are enforced for accepted documents.
- Accepted results receive source-aligned provenance attachment.

**What should be logged**
- Retrieval decisions and any upstream deny/error events for blocked retrieval paths.

## 6) Tool boundary

**What crosses it**
- `ToolInvocation` (request/actor/tenant/tool/action/arguments/confirmation).

**What can go wrong**
- Unauthorized tool use, forbidden argument attempts, direct executor invocation bypass.

**What controls exist**
- `SecureToolRouter.route(...)` is the decision point for allow/deny/require-confirmation.
- Policy (`tools.invoke`) governs forbidden tools/fields, confirmation, and rate limits.
- Execution only through `mediate_and_execute(...)`.
- Runtime call-site guard + execution-secret guard in registry/executor paths block direct invocation outside router.

**What should be logged**
- `tool.execution_attempt`, `tool.decision`, `confirmation.required`, `deny.event`.

## 7) Policy boundary

**What crosses it**
- Policy artifact loading + validation and runtime policy decisions.

**What can go wrong**
- Missing/invalid policy file, malformed schema, accidental permissive fallback.

**What controls exist**
- `load_policy(...)` returns restrictive policy on missing/unreadable/invalid policy.
- `RuntimePolicyEngine` denies unknown actions and kill-switch-enabled states.
- Policy decisions drive retrieval/tool controls and fallback behavior.

**What should be logged**
- `policy.decision` with action/allow/reason/risk tier and linked deny/fallback outcomes.

## 8) Telemetry / audit boundary

**What crosses it**
- Structured runtime events into sinks and replay artifacts.

**What can go wrong**
- Missing lifecycle events, weak replay reconstruction, incomplete actor/request attribution.

**What controls exist**
- Structured audit event contract with trace/request/actor/tenant IDs.
- JSONL and in-memory sinks.
- Replay artifact builder + completeness validation used by evals/launch-gate checks.

**What should be logged**
- Full lifecycle + decision events: `request.start/end`, policy/retrieval/tool decisions, deny/fallback/error.

## 9) Operator / admin boundary

**What crosses it**
- Policy updates, eval outputs, launch-gate inputs, verification artifacts.

**What can go wrong**
- Declaring launch readiness without real evidence, stale/missing artifact use, ignored residual risks.

**What controls exist**
- Launch gate reads concrete artifacts (policy, eval summary/jsonl, audit logs, replay artifacts).
- Readiness status derived from explicit checks, blockers, and residual risks.
- Security guarantees runner maps invariants to enforcement code/tests/artifacts.

**What should be logged / recorded**
- Launch-gate report (`checks`, `scorecard`, `blockers`, `residual_risks`).
- Security guarantees verification summary artifacts.

---

## Reviewer checklist (boundary-focused)

- Are policy checkpoints present before retrieval/model/tools?
- Are tool execution paths still router-mediated only?
- Are retrieval decisions tenant/source/trust/provenance constrained and fail-closed?
- Are deny/fallback/error decisions visible in audit logs?
- Are launch decisions traceable to real artifacts (not inferred state)?

## Identity and Trust Boundaries Added

1. **Inbound actor assertion boundary**: request/session creation must provide a valid structured actor identity.
2. **Policy subject boundary**: policy engine evaluates only against explicit `ActorIdentity` + action context.
3. **Retrieval boundary**: retrieval queries carry identity and are denied on malformed identity or tenant mismatch.
4. **Tool mediation boundary**: tool invocations include identity and are denied on invalid identity/capability mismatch.
5. **Audit boundary**: every emitted audit event stores full actor identity and delegation chain.

## Delegation trust-boundary controls

- Delegated and tool-executor actors must provide a complete delegation grant chain.
- Every hop must be parent->child continuous and scoped to the same tenant.
- Capability scope can only narrow across hops; expansion is denied as scope inflation.
- Expired grants are denied before policy or execution proceeds.

## MCP integration boundary controls

- Unknown servers are denied unless explicitly allowlisted in `MCPServerProfile`.
- Untrusted servers are denied by default; restricted/trusted profiles are explicitly scoped.
- Tenant mismatch between actor identity and MCP server profile is denied.
- Response schema and payload-size violations are denied and logged.
- Protocol retries are bounded and fail closed into deny/error events.

## High-risk tool boundary controls

- Tools are risk-classified and high-risk tools do not run under low-risk assumptions.
- High-risk tools require isolation metadata (`isolation_profile`, `isolation_boundary`).
- High-risk execution requires explicit policy approval (`high_risk_approved`).
- High-risk invocations are confirmation-gated and tightly rate-limited.
