# Security Guarantees (Implementation-Aligned)

This document defines the security guarantees the current repository is intended to provide, and maps each guarantee to concrete implementation evidence.

Scope: current code in `app/`, `policies/`, `retrieval/`, `tools/`, `telemetry/audit/`, `launch_gate/`, and current tests/artifacts.

## 1) Tool execution is mediated by the tool router

**What it means**
- Runtime tool execution is only permitted through a mediated path (`SecureToolRouter.mediate_and_execute`).
- Direct execution through the tool registry is blocked.

**Where it is enforced**
- `InMemoryToolRegistry.execute(...)` requires an execution secret bound by the router; otherwise it raises `DirectToolExecutionDeniedError`.
- `SecureToolRouter.__post_init__` binds that secret, and `mediate_and_execute(...)` is the intended route-then-execute path.
- `SupportAgentOrchestrator` requests tool decisions through `tool_router.route(...)` and does not call registry execution directly.

**Evidence / tests**
- `tests/unit/test_secure_tool_router.py` verifies:
  - allowlisted execution through mediated path succeeds,
  - direct registry execution is blocked,
  - deny/confirmation/rate-limit behavior.
- `tests/integration/test_tool_execution_path_enforced.py` scans runtime code and fails if `registry.execute(...)` appears outside `tools/router.py`.

**Known limitations / residual risk**
- The integration check enforces call-site placement, not runtime import-time hardening of every future module.
- Registry enforcement is implemented in the in-memory registry; provider-specific registries must preserve the same guard semantics.

## 2) Policy governs runtime authorization decisions

**What it means**
- Runtime actions are authorized by `RuntimePolicyEngine.evaluate(...)` for retrieval and tool paths.
- Unknown/invalid policy states fail closed.

**Where it is enforced**
- `RuntimePolicyEngine` enforces decisions for `retrieval.search`, `model.generate`, `tools.route`, and `tools.invoke`.
- `SupportAgentOrchestrator` checks policy before retrieval, model generation, and tool-routing stages.
- `SecureToolRouter` evaluates policy for `tools.invoke` before allowing execution decisions.

**Evidence / tests**
- `tests/unit/test_policy_engine.py` validates allow/deny behavior, kill switch behavior, tenant/source/tool constraints, and fail-closed decisions.
- `tests/unit/test_secure_tool_router.py` includes policy-denial and policy-driven confirmation/rate-limit tool-routing coverage.

**Known limitations / residual risk**
- Policy coverage is action-based; new runtime actions must be explicitly added to policy evaluation paths.
- Misconfigured policies can still reduce functionality; the design prioritizes fail-closed behavior over availability.

## 3) Retrieval enforces tenant and source boundaries

**What it means**
- Retrieval results are filtered to tenant-matching, registered, enabled, allowlisted sources.
- Trust metadata and provenance checks gate document acceptance when required.

**Where it is enforced**
- `SecureRetrievalService.search(...)`:
  - applies policy constraints (`allowed_source_ids`, `top_k_cap`, trust/provenance requirements, trust domains),
  - rejects invalid/missing tenant/query context,
  - drops documents that fail source registration, tenant match, trust-domain, trust metadata, provenance, or filter hooks.

**Evidence / tests**
- `tests/unit/test_secure_retrieval_service.py` covers tenant/source enforcement, trust/provenance checks, policy-constrained source filtering, backend-failure fail-closed behavior, and filter-hook handling.
- `docs/evidence_pack/retrieval_security_summary.md` provides reviewer-facing retrieval control evidence mapping.

**Known limitations / residual risk**
- Security depends on accurate source registration metadata and policy allowlists.
- Retrieval backend quality/content safety is out of scope for this guarantee; this layer enforces boundary and metadata controls.

## 4) Denied actions are logged

**What it means**
- Authorization denials are emitted as structured audit events for investigation.

**Where it is enforced**
- `SupportAgentOrchestrator.run(...)` emits `deny.event` when retrieval/model/tool-route stages are denied.
- Tool-level denied decisions from the router are also emitted with stage/tool context.

**Evidence / tests**
- `tests/unit/test_audit_replay.py::test_denied_action_logging_present` verifies deny-event logging and request lifecycle closure on blocked responses.
- `telemetry/audit/contracts.py` defines explicit deny/fallback/error event types used by the runtime.

**Known limitations / residual risk**
- Current deny logging coverage is strongest in orchestrator-managed paths.
- If a future path bypasses orchestrator telemetry hooks, deny events could be missed; controls rely on maintaining centralized orchestration entrypoints.

## 5) Requests generate traceable telemetry

**What it means**
- Each request gets a unique trace identifier and emits structured lifecycle/decision events tied to request, actor, and tenant metadata.

**Where it is enforced**
- `generate_trace_id()` creates per-run trace IDs.
- `create_audit_event(...)` stamps event IDs and identity fields.
- `SupportAgentOrchestrator` emits `request.start`, policy/retrieval/tool decision events, and `request.end`.
- JSONL and in-memory sinks preserve structured records; replay artifacts can reconstruct timelines.

**Evidence / tests**
- `tests/unit/test_audit_replay.py` verifies trace ID uniqueness, JSONL emission, and replay artifact completeness.
- `tests/unit/test_audit_replay.py::test_denied_action_logging_present` additionally demonstrates lifecycle logging for blocked flows.

**Known limitations / residual risk**
- Sink durability and transport guarantees depend on deployment configuration (e.g., file-system guarantees for JSONL).
- Event payloads intentionally avoid raw sensitive content, which limits some deep forensic details by design.

## 6) Launch-gate decisions are evidence-based (**partial in current repo state**)

**What it means**
- Launch readiness decisions should be computed from machine-checkable artifacts (policy, audit logs, eval summaries, and control-file presence), not ad-hoc judgment.

**Where it is enforced**
- `SecurityLaunchGate.evaluate(...)` is designed to aggregate check results with explicit evidence payloads and classify blockers/residual risks.
- Supporting artifacts and summaries are present under `artifacts/logs/` and `docs/evidence_pack/`.

**Evidence / tests**
- `launch_gate/engine.py` contains evidence-oriented check structures and `GateCheckResult` evidence fields.
- `docs/evidence_pack/launch_gate_summary.md` describes launch-gate evidence expectations.

**Known limitations / residual risk**
- **Current implementation status is partial:** unresolved merge-conflict markers in `launch_gate/engine.py` and `tests/unit/test_launch_gate.py` prevent launch-gate module import and launch-gate test execution until resolved.
- Because of the syntax-conflict state, this guarantee is currently documented as design-intended but not continuously test-verified in the present branch.
