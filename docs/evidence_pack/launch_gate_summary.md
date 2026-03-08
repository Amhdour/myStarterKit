# Launch Gate Summary

## Command
```bash
python -m launch_gate.engine
```

## Outcomes
- `go`: all checks passed with concrete evidence.
- `conditional_go`: no critical blockers, but residual risks remain.
- `no_go`: one or more critical blockers detected.

## Current gate checks (traceability-oriented)
- Policy artifact validity.
- Retrieval boundary configuration integrity.
- Tool-router enforcement scenario evidence.
- Telemetry evidence (audit event coverage + identity fields).
- Replay evidence validity/coverage.
- Eval suite threshold + realism checks.
- Fallback readiness.
- Kill-switch readiness.
- Guarantees manifest contract/evidence checks.
- Security guarantees verification for release-relevant invariants.

## Release-blocking guarantee behavior

Core guarantees are release-relevant. If guarantees verification reports missing/failing release invariants, launch gate should classify as `no_go` and surface the issue in `blockers` under `security_guarantees_verification`.

## Evidence expectations

Launch gate should not produce `go` without real evidence artifacts:
- `artifacts/logs/audit.jsonl`
- `artifacts/logs/replay/*.replay.json`
- `artifacts/logs/evals/*.jsonl`
- `artifacts/logs/evals/*.summary.json`
- `artifacts/logs/verification/security_guarantees.summary.json` (when reviewer runs verification workflow)


## 60-second interpretation checklist

1. `status` is not enough: read `blockers` first.
2. If `security_guarantees_verification` is in blockers, treat release as unproven.
3. Review `residual_risks` only after blockers are empty.
