# Launch Gate Summary

## Command
```bash
python -m launch_gate.engine
```

## Outcomes
- `go`: all checks passed with concrete evidence.
- `conditional_go`: no critical blockers, but residual risks remain.
- `no_go`: one or more critical blockers detected.

## Current Gate Checks
- Mandatory control files present.
- Policy artifact present, readable, and valid.
- Retrieval boundary consistency (tenant allowlists aligned with tenant source allowlists + trust/provenance requirements).
- Tool-router enforcement evidence present in eval scenario outcomes.
- Production kill-switch state acceptable (disabled).
- Audit telemetry evidence present with required event coverage.
- Replay artifact evidence present/valid when required.
- Eval threshold and outcome health met.
- Fallback readiness verified in policy and eval outcomes.

## Evidence Expectations
Launch gate must not produce `go` without real artifacts (policy, audit, replay, eval summary, eval scenario outputs).
