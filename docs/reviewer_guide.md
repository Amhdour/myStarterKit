# Reviewer Trust Pack (Quick Credibility Walkthrough)

Use this when you need to quickly answer: **“Is this starter kit security-credible, and can I verify that from code + evidence?”**

## 1) What problem this repo solves

This starter kit gives a secure baseline for support-agent systems that combine:
- policy-aware orchestration,
- retrieval-augmented generation (RAG),
- mediated tool routing,
- structured telemetry + replay,
- evaluation + launch gating based on artifacts.

It is designed to make claims verifiable via tests and generated evidence artifacts.

## 2) Core guarantees (what is actually implemented)

High-level guarantees are documented in `docs/security_guarantees.md` and enforced in code/tests:
- tool execution cannot bypass centralized router mediation,
- policy governs runtime decisions,
- retrieval enforces tenant/source/trust/provenance boundaries,
- eval outputs include runtime-flow evidence,
- launch-gate decisions are artifact-backed,
- telemetry supports replay/investigation.

## 3) Where primary controls live

- Orchestrator stage/policy gates: `app/orchestrator.py`
- Retrieval boundary enforcement: `retrieval/service.py`, `retrieval/registry.py`
- Tool routing + execution guards: `tools/router.py`, `tools/registry.py`, `tools/execution_guard.py`
- Policy load/validation/evaluation: `policies/loader.py`, `policies/schema.py`, `policies/engine.py`
- Telemetry/replay: `telemetry/audit/events.py`, `telemetry/audit/sinks.py`, `telemetry/audit/replay.py`
- Launch-gate readiness checks: `launch_gate/engine.py`
- Security-guarantees mapping runner: `verification/runner.py`

## 4) Evidence artifacts you can inspect

Primary machine evidence locations:
- `artifacts/logs/audit.jsonl`
- `artifacts/logs/replay/*.replay.json`
- `artifacts/logs/evals/*.jsonl`
- `artifacts/logs/evals/*.summary.json`
- `artifacts/logs/verification/security_guarantees.summary.json`
- `artifacts/logs/verification/security_guarantees.summary.md`

Supporting reviewer docs:
- `docs/trust_boundaries.md`
- `docs/threat_model.md`
- `docs/deployment_architecture.md`

## 5) High-signal tests to run first

- Tool-router bypass resistance:
  - `tests/integration/test_tool_execution_path_enforced.py`
  - `tests/integration/test_tool_executor_bypass_path_enforced.py`
- Policy-governed behavior:
  - `tests/unit/test_policy_engine.py`
  - `tests/unit/test_policy_mutation_runtime.py`
- Retrieval boundaries:
  - `tests/unit/test_secure_retrieval_service.py`
  - `tests/unit/test_multitenant_retrieval_audit.py`
- Telemetry/replay integrity:
  - `tests/unit/test_audit_replay.py`
- Launch-gate evidence enforcement:
  - `tests/unit/test_launch_gate.py`
- Invariant mapping/verification layer:
  - `tests/integration/test_security_guarantees_verification.py`
  - `tests/unit/test_security_guarantees_runner.py`

## 6) Residual risks (explicit)

This baseline does **not** claim:
- comprehensive output moderation/DLP for model answers,
- immutable/signed artifact storage,
- deep retrieval corpus integrity attestation,
- production IAM/ABAC integration.

See `docs/threat_model.md` and `docs/evidence_pack/residual_risks.md`.

## 7) Quick reviewer workflow (5–10 minutes)

1. Run launch gate:
   ```bash
   python -m launch_gate.engine
   ```
2. Confirm:
   - overall status (`go` / `conditional_go` / `no_go`),
   - blockers,
   - residual risks,
   - per-check evidence paths.
3. Run guarantees verification:
   ```bash
   python -m verification.runner
   ```
4. Inspect generated summaries:
   - `artifacts/logs/verification/security_guarantees.summary.json`
   - `artifacts/logs/verification/security_guarantees.summary.md`
5. Spot-check high-signal tests listed above.

If these checks line up, the repo’s security claims are backed by concrete enforcement points and artifacts.
