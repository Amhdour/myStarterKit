# Security Guarantees Verification Suite

This document maps core security invariants to enforcement code, test coverage, and artifact evidence.

Source of truth: `verification/security_guarantees_manifest.json`.

## Invariant coverage

1. **tool_router cannot be bypassed**
   - Enforcement: `tools/execution_guard.py`, `tools/registry.py`, `tools/router.py`
   - Tests: integration bypass-path checks + router unit checks
   - Evidence: eval JSONL scenarios include router-only and bypass attempts

2. **policy governs runtime behavior**
   - Enforcement: `app/orchestrator.py`, `tools/router.py`, `retrieval/service.py`, `policies/engine.py`
   - Tests: policy engine/runtime mutation/orchestration tests
   - Evidence: audit events include policy decisions and deny/fallback behavior

3. **retrieval enforces boundaries**
   - Enforcement: `retrieval/service.py`, `retrieval/registry.py`
   - Tests: secure retrieval and multitenant retrieval audit tests
   - Evidence: audit denial events for boundary violations

4. **evals hit real flows**
   - Enforcement: `evals/runner.py`, `evals/runtime.py`, baseline scenarios
   - Tests: eval runner tests
   - Evidence: eval JSONL/summary plus replay artifacts

5. **launch_gate checks real evidence**
   - Enforcement: `launch_gate/engine.py`
   - Tests: launch gate tests for missing/invalid/misaligned evidence
   - Evidence: aligned eval summary+jsonl, replay, and audit logs

6. **telemetry supports replay**
   - Enforcement: `telemetry/audit/replay.py`, `telemetry/audit/contracts.py`
   - Tests: audit replay tests for completeness, decision summaries, deny/fallback, and coverage flags
   - Evidence: replay artifact timeline + decision summary + coverage metadata


## Verification artifact

Generate a machine-readable guarantees summary:

```bash
python -m verification.runner
```

Artifact output:
- `artifacts/logs/verification/security_guarantees.summary.json`
