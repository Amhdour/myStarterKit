# launch_gate/

Launch-gate readiness evaluator for `go` / `conditional_go` / `no_go` decisions.

## What it checks

- mandatory control presence
- policy artifact validity
- retrieval boundary configuration validity
- tool-router enforcement configuration validity
- production kill-switch readiness
- telemetry evidence (audit + replay + required event coverage)
- eval suite evidence (presence, readability, pass-rate threshold, fail/inconclusive health)
- fallback readiness

## Output shape

`python -m launch_gate.engine` prints structured JSON that includes:
- overall status (`go`, `conditional_go`, `no_go`)
- reviewer scorecard categories with `pass` / `fail` / `missing`
- blockers
- residual risks
- per-check details + concrete evidence fields

Readiness is evidence-based and does not return `go` without required policy/eval/control evidence.
