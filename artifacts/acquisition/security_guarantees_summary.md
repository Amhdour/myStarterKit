# Security Guarantees Summary

- Source documentation: `docs/security_guarantees.md`.
- Source manifest: `verification/security_guarantees_manifest.json`.
- Manifest invariant count: **6**.

## tool_router_cannot_be_bypassed
- Enforcement locations: tools/execution_guard.py, tools/registry.py, tools/router.py
- Test coverage: tests/integration/test_tool_execution_path_enforced.py, tests/integration/test_tool_executor_bypass_path_enforced.py, tests/unit/test_secure_tool_router.py
- Artifact evidence: artifacts/logs/evals/*.jsonl

## policy_governs_runtime_behavior
- Enforcement locations: app/orchestrator.py, tools/router.py, retrieval/service.py, policies/engine.py
- Test coverage: tests/unit/test_policy_engine.py, tests/unit/test_policy_mutation_runtime.py, tests/unit/test_orchestration_flow.py
- Artifact evidence: artifacts/logs/audit.jsonl

## retrieval_enforces_boundaries
- Enforcement locations: retrieval/service.py, retrieval/registry.py
- Test coverage: tests/unit/test_secure_retrieval_service.py, tests/unit/test_multitenant_retrieval_audit.py
- Artifact evidence: artifacts/logs/audit.jsonl

## evals_hit_real_flows
- Enforcement locations: evals/runner.py, evals/runtime.py, evals/scenarios/security_baseline.json
- Test coverage: tests/unit/test_eval_runner.py
- Artifact evidence: artifacts/logs/evals/*.jsonl, artifacts/logs/evals/*.summary.json, artifacts/logs/replay/*.replay.json

## launch_gate_checks_real_evidence
- Enforcement locations: launch_gate/engine.py
- Test coverage: tests/unit/test_launch_gate.py
- Artifact evidence: artifacts/logs/evals/*.jsonl, artifacts/logs/evals/*.summary.json, artifacts/logs/replay/*.replay.json, artifacts/logs/audit.jsonl

## telemetry_supports_replay
- Enforcement locations: telemetry/audit/replay.py, telemetry/audit/contracts.py
- Test coverage: tests/unit/test_audit_replay.py
- Artifact evidence: artifacts/logs/replay/*.replay.json
