# Trust Boundaries (Implementation-Aligned)

This document describes the trust boundaries that are **actually implemented** in this repository.
It maps each boundary to concrete controls in code so reviewers can trace enforcement points.

## Boundary map (current runtime)

1. User boundary
2. Application / orchestrator boundary
3. Model boundary
4. Retrieval boundary
5. Source / document boundary
6. Tool boundary
7. Policy boundary
8. Telemetry / audit boundary
9. Operator / admin boundary

---

## 1) User boundary

**Boundary:** external requester -> `SupportAgentRequest` handled by `SupportAgentOrchestrator`.

- **What crosses it**
  - `request_id`, actor/session/tenant metadata, channel, and `user_text`.
- **What can go wrong**
  - Prompt-injection attempts, tenant spoofing attempts, malformed context, unsafe disclosure requests.
- **What controls exist**
  - Policy checks before retrieval/model/tool stages in orchestrator flow.
  - Fail-closed blocked responses on deny/error paths.
- **What should be logged**
  - `request.start`, stage-level `policy.decision`, deny/fallback/error events, and `request.end`.

## 2) Application / orchestrator boundary

**Boundary:** `app/orchestrator.py` control plane -> retrieval, model, and tool subsystems.

- **What crosses it**
  - `RetrievalQuery`, `ModelInput`, and `ToolInvocation` proposals plus request context.
- **What can go wrong**
  - Policy bypass by stage-order regression, continuation after deny, missing audit visibility.
- **What controls exist**
  - Explicit policy gates for `retrieval.search`, `model.generate`, and `tools.route`.
  - Structured exception handling with blocked responses.
- **What should be logged**
  - Stage policy decisions, retrieval/tool decisions, deny/fallback/error events, request lifecycle.

## 3) Model boundary

**Boundary:** orchestrator -> model interface (`LanguageModel.generate`).

- **What crosses it**
  - User text + retrieved context + metadata (`request_id`, actor, tenant, risk tier, trace ID).
- **What can go wrong**
  - Unsafe output, instruction-following of malicious text, over-disclosure.
- **What controls exist**
  - Policy gate before generation.
  - Retrieval trust/provenance filtering before context assembly.
  - Security eval scenarios for unsafe disclosure/injection behavior.
- **What should be logged**
  - `policy.decision` for model stage, plus lifecycle and error events.

## 4) Retrieval boundary

**Boundary:** orchestrator retrieval request -> `SecureRetrievalService` -> raw retriever.

- **What crosses it**
  - Tenant-scoped query text, top-k constraints, allowed source IDs, raw candidate documents.
- **What can go wrong**
  - Cross-tenant retrieval, unknown/unauthorized sources, permissive fallback on metadata errors.
- **What controls exist**
  - Deny-by-default query validation.
  - Policy-constrained source allowlists/top-k caps.
  - Fail-closed behavior for policy and backend exceptions.
- **What should be logged**
  - `policy.decision` for retrieval stage and `retrieval.decision` evidence.

## 5) Source / document boundary

**Boundary:** raw documents -> accepted documents used in generation.

- **What crosses it**
  - Source registration, trust metadata, provenance metadata, document content.
- **What can go wrong**
  - Source tenant mismatch, malformed source/trust metadata, missing provenance, disallowed trust domains.
- **What controls exist**
  - Source registry checks (registered/enabled/tenant match).
  - Trust-domain allowlisting.
  - Trust/provenance validation and fail-closed filter hooks.
- **What should be logged**
  - Retrieval decision outcomes and downstream deny/error evidence when boundary checks fail.

## 6) Tool boundary

**Boundary:** tool proposals -> `SecureToolRouter` -> registry executor path.

- **What crosses it**
  - Tool name/action/arguments + request/actor/tenant context.
- **What can go wrong**
  - Unauthorized tool use, forbidden-field abuse, direct execution bypass, unsafe high-rate invocation.
- **What controls exist**
  - Centralized router enforcement (allow/deny/require_confirmation, forbidden actions/fields, policy checks, rate limits).
  - Runtime execution guard and registry secret/context checks to block non-mediated execution.
- **What should be logged**
  - `tool.execution_attempt`, `tool.decision`, `confirmation.required`, and `deny.event`.

## 7) Policy boundary

**Boundary:** policy artifact/config -> runtime policy decisions.

- **What crosses it**
  - Policy JSON bundle, environment context, action/context evaluation requests.
- **What can go wrong**
  - Invalid/missing policy, drifted or weak allowlists, unintended permissiveness.
- **What controls exist**
  - Policy loading/validation with restrictive fallback behavior.
  - Action-specific enforcement for retrieval/tools and production kill-switch.
- **What should be logged**
  - `policy.decision` with allow/deny reason and risk tier, plus linked deny/fallback events.

## 8) Telemetry / audit boundary

**Boundary:** runtime decisions -> audit sinks and persisted evidence artifacts.

- **What crosses it**
  - Event type, trace/request/actor/tenant identifiers, and structured event payload.
- **What can go wrong**
  - Incomplete lifecycle coverage, unverifiable incidents, weak replay evidence.
- **What controls exist**
  - Central audit event model and event taxonomy.
  - JSONL sinks, replay artifact generation, eval and launch-gate consumption of artifacts.
- **What should be logged**
  - End-to-end lifecycle and major decisions (`request.start/end`, policy/retrieval/tool decisions, deny/fallback/error).

## 9) Operator / admin boundary

**Boundary:** operator actions -> policy/config updates and release decisions.

- **What crosses it**
  - Policy changes, runtime/eval artifact review inputs, launch-gate execution decisions.
- **What can go wrong**
  - Promotion without evidence, ignored residual risk, misconfiguration of controls.
- **What controls exist**
  - Evidence-driven launch gate checks over policy/audit/replay/eval artifacts.
  - Explicit blocker vs residual-risk classification.
- **What should be logged**
  - Launch-gate report output, referenced artifact paths, and evaluated readiness evidence.

---

## Cross-references

- Runtime flow and control placement: `docs/architecture.md`
- Diagram view of system and controls: `docs/architecture_diagrams.md`
- Threat mapping and residual risk: `docs/threat_model.md`
- Security invariants and evidence: `docs/security_guarantees.md`
