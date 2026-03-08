# Reviewer Trust Pack (Quick Verification Path)

Use this to answer quickly: **"Are security claims traceable to code, tests, and artifacts?"**

## 1) Canonical claim source

- Release-relevant guarantees are defined in `verification/security_guarantees_manifest.json`.
- Human-readable mapping is in `docs/security_guarantees.md`.
- Machine verification output is written to:
  - `artifacts/logs/verification/security_guarantees.summary.json`
  - `artifacts/logs/verification/security_guarantees.summary.md`

## 2) Claim trace matrix (reviewer shortcut)

| Invariant ID | Enforcement | Tests | Evidence artifacts |
|---|---|---|---|
| `tool_router_cannot_be_bypassed` | `tools/execution_guard.py`, `tools/registry.py`, `tools/router.py` | `tests/integration/test_tool_execution_path_enforced.py`, `tests/integration/test_tool_executor_bypass_path_enforced.py`, `tests/unit/test_secure_tool_router.py` | `artifacts/logs/evals/*.jsonl` |
| `policy_governs_runtime_behavior` | `app/orchestrator.py`, `tools/router.py`, `retrieval/service.py`, `policies/engine.py` | `tests/unit/test_policy_engine.py`, `tests/unit/test_policy_mutation_runtime.py`, `tests/unit/test_orchestration_flow.py` | `artifacts/logs/audit.jsonl` |
| `retrieval_enforces_boundaries` | `retrieval/service.py`, `retrieval/registry.py` | `tests/unit/test_secure_retrieval_service.py`, `tests/unit/test_multitenant_retrieval_audit.py` | `artifacts/logs/audit.jsonl` |
| `evals_hit_real_flows` | `evals/runner.py`, `evals/runtime.py`, `evals/scenarios/security_baseline.json` | `tests/unit/test_eval_runner.py` | `artifacts/logs/evals/*.jsonl`, `artifacts/logs/evals/*.summary.json`, `artifacts/logs/replay/*.replay.json` |
| `launch_gate_checks_real_evidence` | `launch_gate/engine.py` | `tests/unit/test_launch_gate.py` | `artifacts/logs/evals/*.jsonl`, `artifacts/logs/evals/*.summary.json`, `artifacts/logs/replay/*.replay.json`, `artifacts/logs/audit.jsonl` |
| `telemetry_supports_replay` | `telemetry/audit/replay.py`, `telemetry/audit/contracts.py` | `tests/unit/test_audit_replay.py` | `artifacts/logs/replay/*.replay.json` |

## 3) Review this repo in 5 minutes

1. Regenerate clean evidence set:
   ```bash
   ./scripts/regenerate_core_evidence.sh
   ```
2. Inspect guarantees verification summary (`status`, failing invariants, missing evidence globs):
   - `artifacts/logs/verification/security_guarantees.summary.json`
3. Inspect launch readiness output (`status`, blockers, residual_risks):
   - `artifacts/logs/launch_gate/security-readiness-<STAMP>.json`
4. Spot-check high-signal tests:
   - `pytest -q tests/unit/test_launch_gate.py tests/unit/test_audit_replay.py tests/unit/test_secure_tool_router.py`

## 4) Interpretation

- `go` requires no blockers and no residual risks.
- Any failure in release-relevant guarantee verification should appear in `blockers` and prevent `go`.
- `conditional_go` is for residual risk only, not missing core guarantee proof.

## 5) Explicit non-claims

This baseline does **not** claim immutable artifact signing, full output DLP/moderation, or production IAM integration. See:
- `docs/threat_model.md`
- `docs/evidence_pack/residual_risks.md`


## 6) Residual risk visibility

Before accepting a trust story, check:
- `docs/evidence_pack/residual_risks.md` for current known gaps.
- `docs/threat_model.md` for threat context and assumptions.
- `docs/evidence_pack/open_issues.md` for unresolved follow-ups.
