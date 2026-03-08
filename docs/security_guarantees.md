# Security Guarantees (Traceable Claims)

This document lists **major security claims** and maps each claim to:
1) enforcement modules,
2) test coverage,
3) artifact evidence.

Source of truth for release-relevant guarantees: `verification/security_guarantees_manifest.json`.

## Release-relevant guarantee traceability

| Claim (Invariant ID) | Enforcement modules | Test files | Artifact evidence |
|---|---|---|---|
| Tool router cannot be bypassed (`tool_router_cannot_be_bypassed`) | `tools/execution_guard.py`, `tools/registry.py`, `tools/router.py` | `tests/integration/test_tool_execution_path_enforced.py`, `tests/integration/test_tool_executor_bypass_path_enforced.py`, `tests/unit/test_secure_tool_router.py` | `artifacts/logs/evals/*.jsonl` |
| Policy governs runtime behavior (`policy_governs_runtime_behavior`) | `app/orchestrator.py`, `tools/router.py`, `retrieval/service.py`, `policies/engine.py` | `tests/unit/test_policy_engine.py`, `tests/unit/test_policy_mutation_runtime.py`, `tests/unit/test_orchestration_flow.py` | `artifacts/logs/audit.jsonl` |
| Retrieval enforces boundaries (`retrieval_enforces_boundaries`) | `retrieval/service.py`, `retrieval/registry.py` | `tests/unit/test_secure_retrieval_service.py`, `tests/unit/test_multitenant_retrieval_audit.py` | `artifacts/logs/audit.jsonl` |
| Evals hit real flows (`evals_hit_real_flows`) | `evals/runner.py`, `evals/runtime.py`, `evals/scenarios/security_baseline.json` | `tests/unit/test_eval_runner.py` | `artifacts/logs/evals/*.jsonl`, `artifacts/logs/evals/*.summary.json`, `artifacts/logs/replay/*.replay.json` |
| Launch gate checks real evidence (`launch_gate_checks_real_evidence`) | `launch_gate/engine.py` | `tests/unit/test_launch_gate.py` | `artifacts/logs/evals/*.jsonl`, `artifacts/logs/evals/*.summary.json`, `artifacts/logs/replay/*.replay.json`, `artifacts/logs/audit.jsonl` |
| Telemetry supports replay (`telemetry_supports_replay`) | `telemetry/audit/replay.py`, `telemetry/audit/contracts.py` | `tests/unit/test_audit_replay.py` | `artifacts/logs/replay/*.replay.json` |

## Additional implemented claim (non-manifest)

| Claim | Enforcement modules | Test files | Artifact evidence |
|---|---|---|---|
| Denied actions are logged with request lifecycle closure | `app/orchestrator.py`, `telemetry/audit/contracts.py` | `tests/unit/test_audit_replay.py::test_denied_action_logging_present` | `artifacts/logs/audit.jsonl`, `artifacts/logs/replay/*.replay.json` |

## Reviewer quick check

1. Regenerate evidence: `./scripts/regenerate_core_evidence.sh`.
2. Verify invariant mapping report: `artifacts/logs/verification/security_guarantees.summary.json`.
3. Verify launch classification: `artifacts/logs/launch_gate/security-readiness-<STAMP>.json`.

If any release-relevant invariant is missing or non-pass in verification, launch gate should not produce `go`.


## Residual risks (read with guarantees)

These claims are bounded by known limitations in:
- `docs/evidence_pack/residual_risks.md`
- `docs/threat_model.md`
