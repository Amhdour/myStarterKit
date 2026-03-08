# Threat Model (Implementation-Aligned)

This threat model describes the **current implementation**, not aspirational controls.

## Scope

In-scope runtime/control components:
- Orchestration: `app/orchestrator.py`
- Policy loading/evaluation: `policies/loader.py`, `policies/schema.py`, `policies/engine.py`
- Retrieval boundaries: `retrieval/service.py`, `retrieval/registry.py`
- Tool mediation and execution guardrails: `tools/router.py`, `tools/registry.py`, `tools/execution_guard.py`
- Telemetry/replay: `telemetry/audit/events.py`, `telemetry/audit/sinks.py`, `telemetry/audit/replay.py`
- Runtime evals: `evals/runner.py`, `evals/runtime.py`, `evals/scenarios/security_baseline.json`
- Readiness/evidence gate: `launch_gate/engine.py`

Out of scope:
- Provider-specific IAM, key management, network-layer controls, and immutable storage guarantees.

---

## Threat register (at-a-glance)

| Threat | Affected component(s) | Primary impact |
|---|---|---|
| Prompt injection | Orchestrator + model path | Unsafe output / instruction override |
| Indirect prompt injection | Retrieval + model path | Malicious retrieved instructions influence behavior |
| Retrieval poisoning | Source/document and retrieval acceptance | Unsafe/incorrect context |
| Cross-tenant leakage | Retrieval + policy tenant constraints | Confidentiality breach |
| Unsafe tool use | Tool router + policy invoke checks | Unauthorized side effects |
| Privilege escalation through tools | Router/registry execution boundary | Elevated operations |
| Policy bypass | Orchestrator/retrieval/tool enforcement points | Unauthorized behavior |
| Sensitive information disclosure | Model/tool/telemetry outputs | Privacy/compliance failure |
| Audit/log tampering or evidence gaps | Audit sinks/replay/launch-gate evidence | Weak forensics/readiness confidence |
| Excessive agency | Tool routing + policy risk-tier/fallback controls | Unreviewed autonomous actions |

---

## Threat details

## 1) Prompt injection (direct user input)

- **Description**: User asks the system to ignore instructions/policies.
- **Affected component**: Orchestrator and model invocation path.
- **Impact**: Unsafe output, policy-inconsistent behavior.
- **Existing controls**:
  - Orchestrator gates runtime stages with policy checks (`retrieval.search`, `model.generate`, `tools.route`).
  - Fail-closed blocked response path on deny/error.
  - Security eval scenarios for direct injection behavior.
- **Remaining gaps**:
  - No dedicated output moderation/DLP pipeline on final model text.
  - Safety outcome depends partly on model behavior under adversarial prompts.

## 2) Indirect prompt injection (retrieved content)

- **Description**: Retrieved documents contain adversarial instructions.
- **Affected component**: Retrieval acceptance path and model context assembly.
- **Impact**: Malicious content can bias model behavior.
- **Existing controls**:
  - Tenant/source allowlists, source registration checks, trust-domain constraints.
  - Trust/provenance checks before document acceptance.
  - Policy-controlled retrieval constraints and fail-closed behavior.
  - Eval scenarios exercise indirect-injection cases.
- **Remaining gaps**:
  - No content-semantic sanitizer/classifier for accepted documents.
  - No automated quarantine pipeline beyond metadata/trust controls.

## 3) Retrieval poisoning

- **Description**: Malicious or compromised content enters an otherwise allowed source.
- **Affected component**: Source/document boundary and retrieval filtering.
- **Impact**: Unsafe or incorrect context passed to generation.
- **Existing controls**:
  - Reject unknown, disabled, malformed, cross-tenant, or policy-disallowed sources.
  - Require valid trust/provenance metadata for accepted documents.
  - Fail closed on policy engine failure/denial and retrieval exceptions.
- **Remaining gaps**:
  - No cryptographic content integrity chain for corpus ingestion.
  - No statistical/ML poisoning detector in baseline.

## 4) Cross-tenant leakage

- **Description**: Caller attempts to read another tenant’s content.
- **Affected component**: Retrieval + policy boundaries.
- **Impact**: Data confidentiality breach.
- **Existing controls**:
  - Tenant context required in request/query paths.
  - Source tenant must match query tenant.
  - Policy tenant/source allowlists constrain retrieval scope.
  - Tests cover cross-tenant denial behavior.
- **Remaining gaps**:
  - Correctness depends on policy artifact and source registry quality.
  - No external IAM integration in this starter baseline.

## 5) Unsafe tool use

- **Description**: Invocation attempts forbidden tools/arguments/actions.
- **Affected component**: Tool routing and policy invoke evaluation.
- **Impact**: Unauthorized side effects.
- **Existing controls**:
  - `SecureToolRouter.route(...)` is the centralized decision point.
  - Policy `tools.invoke` enforces allow/deny, forbidden tools/fields, confirmation requirements, and rate limits.
  - Deny-by-default when policy engine is missing/failing.
- **Remaining gaps**:
  - Business-specific executor-side validations are minimal in sample executors.

## 6) Privilege escalation through tools

- **Description**: Attempt to execute privileged tooling by bypassing router mediation.
- **Affected component**: Router/registry/execution-guard boundary.
- **Impact**: Elevated operations outside policy constraints.
- **Existing controls**:
  - Execution only via `SecureToolRouter.mediate_and_execute(...)`.
  - Registry execution secret + context checks.
  - Callsite assertions block direct `registry.execute(...)` and wrapped-executor invocation.
  - Tool execution path enforcement tests.
- **Remaining gaps**:
  - Provider-specific alternative registries must preserve the same guard semantics.

## 7) Policy bypass

- **Description**: Runtime actions proceed without policy checkpoints.
- **Affected component**: Orchestrator, retrieval service, tool router.
- **Impact**: Unauthorized retrieval/tool/model behavior.
- **Existing controls**:
  - Explicit policy checkpoints across retrieval/model/tool route/invoke actions.
  - Fail-closed behavior on invalid/missing policy state.
  - Policy mutation tests prove behavior changes with policy changes.
- **Remaining gaps**:
  - New future execution paths can regress without disciplined review/testing.

## 8) Sensitive information disclosure

- **Description**: Sensitive data leaks through outputs, tool fields, or evidence artifacts.
- **Affected component**: Model output, tool decisions/results, telemetry/replay artifacts.
- **Impact**: Privacy/compliance incidents.
- **Existing controls**:
  - Tool decision payloads redact argument values.
  - Replay sanitization removes common sensitive fields.
  - Audit emphasizes decisions/metadata instead of raw sensitive payloads.
- **Remaining gaps**:
  - No comprehensive PII/secret classifier over generated responses.
  - Redaction is pattern-based and not exhaustive.

## 9) Audit/log tampering or evidence gaps

- **Description**: Missing/modified logs weaken investigations and launch evidence quality.
- **Affected component**: Audit sinks, replay artifacts, launch-gate evidence checks.
- **Impact**: Lower incident confidence and readiness false positives.
- **Existing controls**:
  - Structured audit events with trace/request/actor/tenant IDs.
  - Replay artifact generation + completeness checks.
  - Launch gate validates policy/eval/audit/replay evidence and runtime-realism proof.
- **Remaining gaps**:
  - File-based evidence is mutable (no signatures/WORM/attestation chain).
  - Operational retention/immutability policy is deployment responsibility.

## 10) Excessive agency

- **Description**: Agent takes side-effecting actions without sufficient governance.
- **Affected component**: Tool route/invoke policy controls.
- **Impact**: Unreviewed operational changes.
- **Existing controls**:
  - Policy can disable tools by risk tier and enable fallback-to-RAG.
  - Confirmation-required tool flows enforced at routing.
  - Unauthorized/forbidden tool attempts denied.
- **Remaining gaps**:
  - Full multi-step human approval workflow is not implemented in baseline.

---

## Required telemetry for investigations

For representative requests, expected events include:
- `request.start`
- `policy.decision`
- `retrieval.decision`
- `tool.decision`
- `deny.event` (when denied)
- `fallback.event` (when fallback used)
- `error.event` (when runtime exception occurs)
- `request.end`

Replay artifacts should support:
- `event_type_counts`
- `coverage`
- `decision_summary`
- `timeline`

---

## Residual risk summary

Highest residual risks in current implementation:
1. **Content safety residual**: no full output moderation/DLP layer.
2. **Retrieval integrity residual**: poisoning defenses are primarily boundary/metadata-driven.
3. **Evidence integrity residual**: file artifacts are not immutable/attested by default.

## Related docs

- `docs/trust_boundaries.md`
- `docs/architecture.md`
- `docs/architecture_diagrams.md`
- `docs/security_guarantees.md`
- `docs/deployment_architecture.md`
