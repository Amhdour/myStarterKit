# Threat Model (Implementation-Aligned)

This threat model reflects the **current implemented runtime** in this repository.
It documents real controls and residual risks without claiming unimplemented mitigations.

## Scope

### In-scope components
- `app/orchestrator.py` (stage gating, deny/fallback behavior)
- `policies/engine.py`, `policies/loader.py` (runtime policy decisions and policy loading)
- `retrieval/service.py`, `retrieval/registry.py` (tenant/source/trust/provenance enforcement)
- `tools/router.py`, `tools/registry.py`, `tools/execution_guard.py` (mediated tool decisions + execution guard)
- `telemetry/audit/*` (structured events, sinks, replay generation)
- `evals/*` (security scenario evidence)
- `launch_gate/engine.py` (artifact-backed release readiness)

### Trust assumptions
- User input and retrieved content are untrusted.
- Policy artifacts are sensitive control-plane inputs.
- Tool execution is high-risk and must stay router-mediated.
- Local artifact files (`artifacts/logs/*`) are evidence inputs, not tamper-proof ledgers.

---

## Threats and Controls

## 1) Prompt injection (direct user input)
- **Description:** User text attempts to override safety constraints or policy intent.
- **Affected component:** Orchestrator + model stage boundary.
- **Impact:** Unsafe responses or policy-inconsistent behavior.
- **Existing controls:**
  - Policy checks before retrieval/model/tool-routing stages.
  - Blocked response path when stage policy denies.
  - Eval scenarios for direct injection and unsafe disclosure attempts.
- **Remaining gaps:** No dedicated output moderation/DLP layer on generated text.

## 2) Indirect prompt injection (retrieved content)
- **Description:** Retrieved corpus content includes adversarial instructions that influence generation.
- **Affected component:** Retrieval acceptance path + model context assembly.
- **Impact:** Unsafe instruction-following from trusted retrieval context.
- **Existing controls:**
  - Source registration and tenant/source allowlist enforcement.
  - Trust-domain allowlisting and trust/provenance validation.
  - Fail-closed retrieval behavior on invalid policy/backend conditions.
- **Remaining gaps:** No semantic content sanitizer/classifier for accepted documents.

## 3) Retrieval poisoning
- **Description:** Malicious or low-integrity content enters allowed sources.
- **Affected component:** Source/document boundary in retrieval flow.
- **Impact:** Unsafe/inaccurate responses and decision degradation.
- **Existing controls:**
  - Unknown/unregistered/disabled sources denied.
  - Tenant match, trust-domain, trust metadata, provenance checks.
  - Mixed unauthorized source requests fail closed.
- **Remaining gaps:** No content integrity attestation or poisoning detection beyond metadata checks.

## 4) Cross-tenant leakage
- **Description:** Requests attempt to access data across tenant boundaries.
- **Affected component:** Retrieval boundary and policy gating.
- **Impact:** Confidentiality breach between tenants.
- **Existing controls:**
  - Tenant required in retrieval/tool contexts.
  - Source tenant must match query tenant.
  - Policy tenant/source allowlists enforced.
- **Remaining gaps:** Depends on correct policy/source registration; no external IAM integration in starter baseline.

## 5) Unsafe tool use
- **Description:** Invocation of disallowed tools/actions/arguments.
- **Affected component:** Tool router (`route`) policy and contract checks.
- **Impact:** Unauthorized side effects or sensitive operations.
- **Existing controls:**
  - Centralized allow/deny/require_confirmation logic.
  - Forbidden action/field checks, argument validation, rate limits.
  - `tools.invoke` policy evaluation per invocation.
- **Remaining gaps:** Executor-specific side-effect controls are sample-level and deployment-dependent.

## 6) Privilege escalation through tools
- **Description:** Actor attempts to pivot into higher-privilege tool capability.
- **Affected component:** Router + registry execution boundary.
- **Impact:** Elevated operations without intended authorization.
- **Existing controls:**
  - Policy allowlists/forbidden-tools constraints.
  - Router-mediated execution path only (`mediate_and_execute`).
  - Registry execution secret/context guard blocks direct execution bypass.
- **Remaining gaps:** Fine-grained role/attribute authorization model is limited in baseline policy schema.

## 7) Policy bypass
- **Description:** New path executes action without required policy checkpoint.
- **Affected component:** Orchestrator, retrieval service, tool router.
- **Impact:** Unauthorized actions proceed without policy enforcement.
- **Existing controls:**
  - Explicit policy checkpoints for `retrieval.search`, `model.generate`, `tools.route`, `tools.invoke`.
  - Fail-closed behavior on policy errors.
  - Integration checks for restricted tool execution call sites.
- **Remaining gaps:** Future code changes can still introduce bypasses if checkpoints are omitted.

## 8) Sensitive information disclosure
- **Description:** Secrets/PII leak via model output, tool inputs, or logs.
- **Affected component:** Model output path, tool decision surface, telemetry boundary.
- **Impact:** Confidentiality/compliance failure.
- **Existing controls:**
  - Router decision sanitizes argument values.
  - Retrieval/policy constraints reduce sensitive data exposure scope.
  - Structured audit events focus on decision metadata.
- **Remaining gaps:** No full DLP/redaction pass over generated answer text.

## 9) Audit/log tampering or evidence gaps
- **Description:** Missing or manipulated telemetry/eval artifacts reduce verifiability.
- **Affected component:** Audit sinks, replay artifacts, launch-gate evidence checks.
- **Impact:** Weak incident response and weak release-readiness confidence.
- **Existing controls:**
  - Structured `AuditEvent` with trace/request/actor/tenant identifiers.
  - Replay artifact generation from event streams.
  - Launch gate requires policy/eval/telemetry/replay evidence and reports blockers/residual risks.
- **Remaining gaps:** File-based artifacts are not immutable; no cryptographic integrity chain in baseline.

## 10) Excessive agency
- **Description:** Agent autonomy causes unreviewed side effects.
- **Affected component:** Orchestrator tool-routing path and policy controls.
- **Impact:** Unsafe automated actions and operational risk.
- **Existing controls:**
  - `tools.route` gating, per-tool confirmation requirements, and rate limits.
  - Risk-tier control can disable tools with fallback-to-RAG behavior.
  - Eval and launch-gate checks for fallback and tool-enforcement evidence.
- **Remaining gaps:** Full human-approval workflow orchestration remains an extension responsibility.

---

## Residual Risk Summary

Top residual risks in current implementation:
1. **Content-layer safety risk** (injection/disclosure) without a dedicated output moderation layer.
2. **Retrieval data integrity risk** (poisoning) without deep semantic/integrity attestation.
3. **Evidence integrity risk** due to file-based artifacts without immutable storage guarantees.

## Reviewer Use

Use this document alongside:
- `docs/trust_boundaries.md` (boundary-by-boundary crossings, controls, and logging),
- `docs/architecture.md` (runtime flow and enforcement points),
- `docs/security_guarantees.md` (implemented guarantees + limitations),
- `docs/evidence_pack/*` (release evidence summaries).
