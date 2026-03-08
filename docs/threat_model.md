# Threat Model (Implementation-Aligned)

This threat model is specific to the code currently present in this repository.
It focuses on implemented controls and explicit residual risk, not aspirational controls.

## Scope and Assumptions

**In scope components**
- `app/orchestrator.py` (request flow + stage gating + deny/fallback behavior)
- `policies/engine.py` and `policies/loader.py` (runtime authorization decisions)
- `retrieval/service.py` (tenant/source/trust/provenance enforcement)
- `tools/router.py` and `tools/registry.py` (mediated tool routing + execution guard)
- `telemetry/audit/*` (event schema, sinks, replay artifacts)
- `launch_gate/engine.py` (evidence-based readiness checks; see limitation below)

**Assumptions**
- User input and retrieved content are untrusted.
- Policy bundle/config is a sensitive control-plane input.
- Tool execution is high-risk and must remain mediated.

**Current branch limitation (important)**
- The repository currently contains unresolved merge-conflict markers in launch-gate and related tests, which prevents normal import/test execution for those modules. Threat statements below treat launch-gate controls as *design-implemented but currently partially blocked in this branch state*.

---

## Threat Inventory

### 1) Prompt Injection (direct user input)
- **Description:** A user attempts to override intended behavior with adversarial instructions.
- **Affected component:** Orchestrator/model boundary.
- **Impact:** Unsafe or policy-inconsistent outputs.
- **Existing controls:** Stage policy checks before retrieval, generation, and tool-routing; deny/fallback paths in orchestrator; security eval harness includes injection/disclosure scenarios.
- **Remaining gaps:** No dedicated model-output moderation or strict constrained decoding layer in current runtime.

### 2) Indirect Prompt Injection (retrieved content)
- **Description:** Retrieved documents include malicious instructions that influence model behavior.
- **Affected component:** Retrieval + model context assembly.
- **Impact:** Model follows adversarial instructions embedded in corpus content.
- **Existing controls:** Retrieval source registration, tenant/source allowlists, trust-domain constraints, and required trust/provenance metadata checks before documents are accepted.
- **Remaining gaps:** No semantic sanitizer/classifier for retrieved content; trusted-source compromise remains a residual risk.

### 3) Retrieval Poisoning
- **Description:** Adversarial or low-integrity data enters approved retrieval sources.
- **Affected component:** Source/document boundary and retrieval pipeline.
- **Impact:** Incorrect/unsafe responses and degraded operator trust.
- **Existing controls:** Unknown/disabled/unregistered sources are dropped; tenant and trust-domain checks are enforced; retrieval fails closed on invalid policy/backend exceptions.
- **Remaining gaps:** Metadata validation is not equivalent to full content integrity attestation; poisoning detection is not implemented.

### 4) Cross-Tenant Leakage
- **Description:** A request attempts to access another tenant’s data via retrieval or tool actions.
- **Affected component:** Retrieval boundary + policy/tool routing boundary.
- **Impact:** Confidentiality breach between tenants.
- **Existing controls:** Tenant required for retrieval and tool authorization; source tenant must match query tenant; policy enforces tenant allowlists and per-tenant source allowlists.
- **Remaining gaps:** Protection depends on correct policy/source configuration; no external IAM/ABAC service integration in starter kit.

### 5) Unsafe Tool Use
- **Description:** Invocation of dangerous tools/actions/arguments.
- **Affected component:** Tool router and policy evaluation for tool invocation.
- **Impact:** Unauthorized state changes, abuse, or data exposure.
- **Existing controls:** Router mediation with allowlist checks, forbidden action/field checks, argument validation, confirmation gates, and rate limits; policy `tools.invoke` evaluation per invocation.
- **Remaining gaps:** Tool executors are sample-level; production-specific out-of-band approvals and side-effect safeguards are left to implementers.

### 6) Privilege Escalation Through Tools
- **Description:** A low-privilege actor attempts to pivot into high-privilege tool capabilities.
- **Affected component:** Tool registry/router + policy constraints.
- **Impact:** Elevated operations without intended authorization.
- **Existing controls:** Policy allowlist/forbidden-tools constraints, required request/actor/tenant context, and registry execution-secret mechanism to block direct execution bypass.
- **Remaining gaps:** Fine-grained role/attribute authorization beyond policy allowlists is limited in current baseline.

### 7) Policy Bypass
- **Description:** Execution path bypasses or weakens policy checkpoints.
- **Affected component:** Orchestrator, retrieval service, and tool router.
- **Impact:** Runtime actions proceed without intended authorization controls.
- **Existing controls:** Explicit policy evaluation at `retrieval.search`, `model.generate`, `tools.route`, and `tools.invoke`; fail-closed handling on policy errors; integration test checks for non-router registry execution call sites.
- **Remaining gaps:** New code paths can still introduce bypass risk if they omit these checkpoints; policy quality/governance remains operational responsibility.

### 8) Data Exfiltration
- **Description:** Sensitive data leaves boundaries through model outputs, tool arguments, or telemetry.
- **Affected component:** Model output path, tool routing surface, telemetry payloads.
- **Impact:** Confidentiality and compliance failure.
- **Existing controls:** Tool decision objects redact argument values; retrieval and policy gates constrain available data/tools; telemetry events are structured and primarily decision metadata.
- **Remaining gaps:** No dedicated DLP/redaction enforcement for generated answer text; sink-level egress controls depend on deployment architecture.

### 9) Audit/Log Tampering or Gaps
- **Description:** Missing, incomplete, or altered audit trail reduces forensic reliability.
- **Affected component:** Audit sinks, replay artifacts, and launch-gate evidence checks.
- **Impact:** Weak incident response and weak release evidence.
- **Existing controls:** Structured `AuditEvent` schema includes trace/request/actor/tenant linkage; JSONL sink and replay artifacts support timeline reconstruction; launch-gate logic is designed to enforce evidence minimums.
- **Remaining gaps:** No immutable log backend or cryptographic integrity chain in starter kit; launch-gate verification is currently partially blocked by merge-conflict markers in this branch.

### 10) Excessive Agency
- **Description:** Agent autonomy expands into risky actions without sufficient control.
- **Affected component:** Orchestrator + tool-routing policy flow.
- **Impact:** Unreviewed side effects and operational risk.
- **Existing controls:** Tools can be disabled by risk tier, gated by policy, and forced into confirmation-required flows; fallback-to-RAG path supports no-tool operation.
- **Remaining gaps:** Human-in-the-loop approval orchestration and capability-scoping policy granularity are not fully built out in baseline implementation.

---

## Residual Risk Summary

Highest residual risks in current implementation:
1. **Content-layer model safety risk** (prompt/indirect injection and exfiltration) without a dedicated model-output DLP/moderation layer.
2. **Source integrity risk** (retrieval poisoning) beyond metadata/trust-domain checks.
3. **Evidence integrity/availability risk** where audit artifacts are file-based and not immutable; plus current branch launch-gate/test conflict state.

## Reviewer Notes

- Use this file with:
  - `docs/trust_boundaries.md` (boundary-centric view),
  - `docs/security_guarantees.md` (guarantees + evidence mapping), and
  - `docs/evidence_pack/*` (artifact summaries).
- Do not interpret this starter kit as a complete production control stack; it is a secure baseline with explicit extension points and residual risk disclosure.
