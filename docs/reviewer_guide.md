# Reviewer Trust Pack (Quick Guide)

This guide is for recruiters, clients, and technical reviewers who want a fast, evidence-backed view of repository credibility.

## 1) What problem this starter kit solves

This repository provides a secure baseline for support-agent systems that combine:
- policy-aware orchestration,
- retrieval-augmented generation (RAG),
- mediated tool routing,
- structured telemetry/audit,
- security evals,
- artifact-driven launch gating.

It is designed to prove controls with tests and artifacts, not just architecture claims.

## 2) Core security guarantees (implemented)

See `docs/security_guarantees.md` for full detail. In short, the baseline enforces:
- tool execution is router-mediated (no direct bypass path),
- policy governs runtime decisions for retrieval/model/tools,
- retrieval enforces tenant/source/trust/provenance boundaries,
- evals exercise runtime paths and produce inspectable artifacts,
- launch gate decisions are evidence-based,
- telemetry/replay artifacts support investigation.

## 3) Where main controls live (code map)

- Orchestration stage gates: `app/orchestrator.py`
- Retrieval boundary enforcement: `retrieval/service.py`, `retrieval/registry.py`
- Tool mediation + execution guard: `tools/router.py`, `tools/registry.py`, `tools/execution_guard.py`
- Policy loading/evaluation: `policies/loader.py`, `policies/schema.py`, `policies/engine.py`
- Audit/replay: `telemetry/audit/contracts.py`, `telemetry/audit/sinks.py`, `telemetry/audit/replay.py`
- Launch readiness checks: `launch_gate/engine.py`

## 4) Evidence artifacts produced

Primary runtime/eval evidence paths:
- `artifacts/logs/audit.jsonl`
- `artifacts/logs/replay/*.replay.json`
- `artifacts/logs/evals/*.jsonl`
- `artifacts/logs/evals/*.summary.json`

Evidence-pack summaries:
- `docs/evidence_pack/README.md`
- `docs/evidence_pack/launch_gate_summary.md`
- `docs/evidence_pack/telemetry_audit_summary.md`
- `docs/evidence_pack/security_guarantees_verification.md`

## 5) Tests that prove key invariants

High-signal tests to inspect first:
- Tool-router bypass resistance:
  - `tests/integration/test_tool_execution_path_enforced.py`
  - `tests/integration/test_tool_executor_bypass_path_enforced.py`
- Policy-governed runtime behavior:
  - `tests/unit/test_policy_engine.py`
  - `tests/unit/test_policy_mutation_runtime.py`
- Retrieval boundary enforcement:
  - `tests/unit/test_secure_retrieval_service.py`
  - `tests/unit/test_multitenant_retrieval_audit.py`
- Replay/telemetry reconstruction:
  - `tests/unit/test_audit_replay.py`
- Launch-gate evidence checks:
  - `tests/unit/test_launch_gate.py`
- Security guarantees mapping/runner:
  - `tests/integration/test_security_guarantees_verification.py`
  - `tests/unit/test_security_guarantees_runner.py`

## 6) Residual risks (honest baseline)

This starter kit intentionally does **not** claim:
- full output moderation/DLP for generated answers,
- immutable/signed artifact storage,
- deep content-integrity attestation for retrieval corpora,
- full production IAM/ABAC integration.

See:
- `docs/threat_model.md`
- `docs/evidence_pack/residual_risks.md`

## 7) How to inspect launch-gate outputs quickly

Run:

```bash
python -m launch_gate.engine
```

Review in output:
- overall status (`go`, `conditional_go`, `no_go`),
- blocker list,
- residual-risk list,
- per-check evidence references (policy/eval/replay/audit paths).

For stronger mapping validation, also run:

```bash
python -m verification.runner
```

This writes:
- `artifacts/logs/verification/security_guarantees.summary.json`
