# Threat Model (Implementation-Aligned)

This threat model reflects the **implemented** starter-kit runtime. It does not claim controls that are not present in code/tests.

## Scope and assumptions

### In-scope components
- Orchestration: `app/orchestrator.py`
- Policy: `policies/loader.py`, `policies/schema.py`, `policies/engine.py`
- Retrieval boundaries: `retrieval/service.py`, `retrieval/registry.py`
- Tool mediation: `tools/router.py`, `tools/registry.py`, `tools/execution_guard.py`
- Telemetry/replay: `telemetry/audit/contracts.py`, `telemetry/audit/sinks.py`, `telemetry/audit/replay.py`
- Security evals: `evals/runner.py`, `evals/scenarios/security_baseline.json`
- Readiness gate: `launch_gate/engine.py`

### Trust assumptions
- User input and retrieved document content are untrusted.
- Policy artifacts are trusted control inputs **only after** schema/loader validation.
- Tool execution is high-risk and must remain router-mediated.
- File-based artifacts under `artifacts/logs/*` are evidence inputs, not tamper-proof ledgers.

---

## Threat register

| Threat | Affected components | Impact |
|---|---|---|
| Prompt injection (direct) | Orchestrator + model boundary | Unsafe/incorrect responses |
| Indirect prompt injection (retrieved content) | Retrieval + model boundary | Malicious instructions from context |
| Retrieval poisoning | Source/document acceptance path | Unsafe/inaccurate context |
| Cross-tenant leakage | Retrieval + policy boundary | Confidentiality breach |
| Unsafe tool use | Tool router boundary | Unauthorized side effects |
| Privilege escalation via tools | Tool router/registry execution boundary | Elevated operations |
| Policy bypass | Orchestrator/retrieval/router policy checkpoints | Unauthorized behavior |
| Sensitive information disclosure | Model/tool/telemetry surfaces | Privacy/compliance failure |
| Audit/log tampering or gaps | Audit sinks/replay/evidence artifacts | Weak incident response and evidence quality |
| Excessive agency | Tool-routing autonomy path | Unreviewed actions/operational risk |

---

## Threat details

## 1) Prompt injection (direct user input)

- **Description**: User input attempts to override system intent (e.g., “ignore previous instructions”).
- **Affected components**: `app/orchestrator.py`, model invocation path.
- **Impact**: Unsafe response generation, potential policy-inconsistent outputs.
- **Existing controls**:
  - Stage policy checks before retrieval, generation, and tool routing.
  - Blocked response flow on policy denial/error paths.
  - Security eval scenarios for prompt injection and unsafe disclosure.
- **Remaining gaps**:
  - No dedicated output moderation/DLP layer for generated text.
  - Model behavior remains partially dependent on prompt robustness.

## 2) Indirect prompt injection (retrieved content)

- **Description**: Adversarial instructions embedded in retrieved documents influence response generation.
- **Affected components**: `retrieval/service.py`, model context assembly in orchestrator.
- **Impact**: Unsafe instruction-following through retrieval context.
- **Existing controls**:
  - Source registration + tenant/source allowlist checks.
  - Trust-domain allowlists and trust/provenance requirements.
  - Fail-closed retrieval on missing/invalid policy/backend errors.
- **Remaining gaps**:
  - No semantic classifier/sanitizer for accepted document content.
  - No content-level quarantine pipeline beyond metadata boundary checks.

## 3) Retrieval poisoning

- **Description**: Malicious content enters an allowed source.
- **Affected components**: Source/document boundary (`retrieval/registry.py`, `retrieval/service.py`).
- **Impact**: Unsafe or incorrect model context and degraded response integrity.
- **Existing controls**:
  - Deny unknown/unregistered/disabled sources.
  - Enforce tenant match, trust-domain constraints, trust metadata, provenance.
  - Fail closed when requested sources/policy constraints are inconsistent.
- **Remaining gaps**:
  - No cryptographic content attestation chain for corpus ingestion.
  - No poisoning-detection model in baseline implementation.

## 4) Cross-tenant leakage

- **Description**: A request attempts to retrieve data from another tenant.
- **Affected components**: Retrieval and policy boundaries.
- **Impact**: Confidentiality breach across tenant partitions.
- **Existing controls**:
  - Tenant context is required in retrieval/tool invocation paths.
  - Source tenant must match query tenant.
  - Policy tenant/source allowlists constrain allowed retrieval scope.
- **Remaining gaps**:
  - Security depends on policy and source registration correctness.
  - No external IAM/ABAC integration in starter baseline.

## 5) Unsafe tool use

- **Description**: Disallowed tools/actions/arguments are requested.
- **Affected components**: `tools/router.py` decision path.
- **Impact**: Unauthorized state changes or sensitive operations.
- **Existing controls**:
  - Centralized allow/deny/require-confirmation decisions.
  - Forbidden action/field checks, argument validation, rate limits.
  - Per-invocation policy evaluation (`tools.invoke`).
- **Remaining gaps**:
  - Executor-side side-effect controls are deployment-specific and minimal in sample executors.

## 6) Privilege escalation through tools

- **Description**: Caller attempts to pivot to higher-privilege tool execution.
- **Affected components**: Router + registry execution boundary.
- **Impact**: Escalated operations outside intended policy constraints.
- **Existing controls**:
  - Policy allowlists/forbidden tools and confirmation constraints.
  - Router-mediated execution path only (`mediate_and_execute`).
  - Execution secret + context guard + callsite assertion to block direct execution bypass.
- **Remaining gaps**:
  - Fine-grained per-role authorization model is limited in baseline policy schema.

## 7) Policy bypass

- **Description**: A runtime path executes without policy evaluation.
- **Affected components**: Orchestrator, retrieval service, tool router.
- **Impact**: Unauthorized operations proceed without centralized policy control.
- **Existing controls**:
  - Explicit checkpoints for `retrieval.search`, `model.generate`, `tools.route`, `tools.invoke`.
  - Fail-closed behavior when policy engine is unavailable or evaluation fails.
  - Integration tests for tool execution bypass guardrails.
- **Remaining gaps**:
  - Future code changes could introduce new paths without policy checkpoints if not reviewed.

## 8) Sensitive information disclosure

- **Description**: Secrets/PII leak through model output, tool arguments, or telemetry artifacts.
- **Affected components**: model output surface, tool decision surfaces, telemetry/replay outputs.
- **Impact**: Confidentiality and compliance risk.
- **Existing controls**:
  - Tool decision payloads redact argument values.
  - Replay artifact sanitizes common sensitive fields.
  - Audit events focus on decision metadata over raw content.
- **Remaining gaps**:
  - No comprehensive answer-text DLP/redaction layer.
  - Redaction list in replay is pattern-based, not exhaustive classification.

## 9) Audit/log tampering or evidence gaps

- **Description**: Missing/modified logs reduce replay and investigation reliability.
- **Affected components**: telemetry sinks, replay artifacts, launch-gate evidence ingestion.
- **Impact**: Lower incident confidence and weaker launch-readiness proof.
- **Existing controls**:
  - Structured audit event schema with trace/request/actor/tenant fields.
  - Replay artifacts with timeline, decision summary, and coverage flags.
  - Launch gate validates presence/consistency of policy/audit/replay/eval evidence.
- **Remaining gaps**:
  - File-based artifacts are mutable; no immutable/WORM storage or signature chain in baseline.

## 10) Excessive agency

- **Description**: Agent behavior triggers autonomous side effects without sufficient confirmation/governance.
- **Affected components**: Tool-routing and policy controls.
- **Impact**: Operational risk and unintended actions.
- **Existing controls**:
  - Policy-driven `tools.route` + `tools.invoke` checks.
  - Confirmation-required tool support and deny-by-default behavior.
  - Risk-tier policy can disable tools; fallback-to-RAG path documented/tested.
- **Remaining gaps**:
  - Full human-in-the-loop approval orchestration remains an extension responsibility.

---

## Required telemetry for threat investigation

For practical incident review, these event types should be present for representative flows:
- `request.start`
- `policy.decision`
- `retrieval.decision`
- `tool.decision`
- `deny.event` (when denied)
- `fallback.event` (when fallback path used)
- `error.event` (when runtime errors occur)
- `request.end`

Replay artifacts should support reconstruction of lifecycle and decision paths via:
- `event_type_counts`
- `coverage` (including lifecycle and core-decision completeness)
- `decision_summary`
- `timeline`

## Residual risk summary

Highest residual risks in current baseline:
1. **Content-layer safety risk**: no full output moderation/DLP pass.
2. **Retrieval integrity risk**: poisoning defenses rely mainly on metadata and policy boundaries.
3. **Evidence integrity risk**: file-based artifacts without immutable provenance guarantees.

## Related docs

- `docs/architecture.md`
- `docs/trust_boundaries.md`
- `docs/security_guarantees.md`
- `docs/deployment_architecture.md`
- `docs/evidence_pack/security_guarantees_verification.md`
