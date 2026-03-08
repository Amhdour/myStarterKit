# Threat Model (Implementation-Aligned)

This threat model reflects the currently implemented system behavior in this repository. It focuses on concrete runtime components and existing controls rather than aspirational architecture.

## Scope

Covered components:
- `app/SupportAgentOrchestrator`
- `policies/RuntimePolicyEngine` + policy loader/schema
- `retrieval/SecureRetrievalService` + source registry
- `tools/SecureToolRouter` + tool registry/rate limiter
- `telemetry/audit` sinks + replay artifacts
- `launch_gate/SecurityLaunchGate`

Assumptions:
- User input and retrieved content are untrusted.
- Policy artifacts and runtime config are sensitive control inputs.
- Tool execution is high-risk and must remain mediated.

---

## Threats

### 1) Prompt Injection (direct user input)
- **Description:** User attempts to override system behavior (e.g., “ignore instructions”).
- **Affected component:** Orchestrator + model path.
- **Impact:** Unsafe responses or policy-violating behavior.
- **Existing controls:** Stage-level policy checks before retrieval/model/tools; deny/fallback behavior; eval scenario coverage for prompt-injection attempts.
- **Remaining gaps:** No implemented model-side content firewall/structured output guardrail; mitigation relies on policy stage gating + model behavior.

### 2) Indirect Prompt Injection (retrieved content)
- **Description:** Retrieved documents contain malicious instructions consumed by generation.
- **Affected component:** Retrieval + model boundary.
- **Impact:** Model follows malicious retrieved instructions.
- **Existing controls:** Source registration, tenant/source allowlists, trust-domain constraints, required trust/provenance checks, retrieval policy constraints.
- **Remaining gaps:** If policy allows broader trust domains, malicious content can still be surfaced; content-level sanitization/classification is not implemented.

### 3) Data / Retrieval Poisoning
- **Description:** Adversarial or corrupted knowledge source content poisons retrieval context.
- **Affected component:** Source/document boundary and retrieval service.
- **Impact:** Wrong, unsafe, or manipulative responses.
- **Existing controls:** Deny unknown/disabled/unregistered sources; tenant isolation; trust-domain allowlists; provenance/trust metadata requirements; fail-closed retrieval behavior.
- **Remaining gaps:** No integrity attestation pipeline beyond metadata presence; poisoning remains a residual risk (explicitly visible in eval expected-fail scenario).

### 4) Cross-Tenant Leakage
- **Description:** Request attempts to access another tenant’s documents/tools.
- **Affected component:** Retrieval and tool-policy boundaries.
- **Impact:** Confidentiality breach across tenants.
- **Existing controls:** Tenant required in policy/retrieval/tool checks; source tenant must match query tenant; retrieval allowlists per tenant; policy denies disallowed tenants.
- **Remaining gaps:** Depends on correct policy/registry configuration; no separate runtime IAM service in this starter kit.

### 5) Unsafe Tool Use
- **Description:** Invocation of dangerous tools/actions/arguments.
- **Affected component:** Tool router + policy engine.
- **Impact:** Unauthorized state changes or data exfiltration.
- **Existing controls:** Centralized router mediation; policy `tools.invoke`; allow/deny/require_confirmation decisions; forbidden tools/fields checks; rate limits.
- **Remaining gaps:** Tool implementations are placeholders in starter kit; production-grade side-effect controls (e.g., external approvals) are not implemented here.

### 6) Privilege Escalation Through Tools
- **Description:** User pivots to privileged tools (e.g., admin-like operations).
- **Affected component:** Tool registry/router and policy constraints.
- **Impact:** Elevated capability abuse.
- **Existing controls:** Allowlist + forbidden tools; per-invocation policy decision; tenant/actor context requirements; direct registry execution blocked without router secret.
- **Remaining gaps:** Role/attribute-based authorization beyond tenant and policy allowlists is limited in this starter kit.

### 7) Policy Bypass
- **Description:** Caller attempts to bypass policy via crafted arguments/paths.
- **Affected component:** Orchestrator, router, retrieval, policy engine.
- **Impact:** Security checks circumvented.
- **Existing controls:** Policy checkpoints at retrieval/model/tools.route/tools.invoke; router-only execution secret path; forbidden-field enforcement; fail-closed on policy errors.
- **Remaining gaps:** Misconfigured policies can still weaken posture; policy governance/change-management is process-dependent.

### 8) Sensitive Information Disclosure
- **Description:** Request attempts to extract secrets/PII from system behavior or tool arguments.
- **Affected component:** Model output path, tool decision output, audit path.
- **Impact:** Data confidentiality breach.
- **Existing controls:** Tool decision argument redaction; deny/confirmation gates; retrieval trust/provenance controls; eval coverage for unsafe disclosure attempts.
- **Remaining gaps:** No dedicated DLP/redaction pipeline for model output beyond current deterministic scenario behavior.

### 9) Audit / Log Tampering or Gaps
- **Description:** Missing/incomplete audit trail, or unverifiable evidence artifacts.
- **Affected component:** Telemetry/audit sinks and launch gate.
- **Impact:** Reduced incident response and weak compliance evidence.
- **Existing controls:** Structured event schema with trace/request/actor/tenant; JSONL sink; replay artifacts; launch-gate checks for audit/replay/eval evidence and required event types.
- **Remaining gaps:** No immutable/WORM logging backend in this starter kit; artifact integrity controls are limited to file-level checks.

### 10) Excessive Agency
- **Description:** Agent performs high-impact actions beyond intended autonomy.
- **Affected component:** Orchestrator + tool routing.
- **Impact:** Unreviewed side effects or risky operations.
- **Existing controls:** Tools are mediated by router decisions; confirmation-required policy controls; risk-tier-based tools disablement; fallback-to-RAG mode.
- **Remaining gaps:** Fine-grained task-level capability scoping and human approval workflow integration remain extension work.

---

## Residual Risk Summary

Highest residual risks in current implementation:
1. Retrieved-content poisoning/injection when trust-domain policy is broadened.
2. Model-output safety reliance without a dedicated output moderation/DLP layer.
3. Evidence integrity limits due local artifact-based telemetry/replay model.

These are visible in current eval and launch-gate patterns and should remain explicit in reviewer/operator workflows.
