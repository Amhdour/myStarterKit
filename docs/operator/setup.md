# Operator & Developer Setup Guide

This guide focuses on practical local setup and validation for the starter kit.

## 1) Environment Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
```

## 2) Baseline Validation
```bash
pytest
./scripts/check_scaffold.sh
```

## 3) Security Eval Run
```bash
python -m evals.runner
```
Expected outputs:
- `artifacts/logs/evals/*.jsonl`
- `artifacts/logs/evals/*.summary.json`

## 4) Launch Readiness Evaluation
```bash
python -m launch_gate.engine
```
Interpretation:
- `go`: all configured checks pass.
- `conditional_go`: no blockers, but residual risks remain.
- `no_go`: critical blockers found.

## 5) Optional Audit JSONL Wiring Example
Use `telemetry.audit.sinks.JsonlAuditSink` in runtime entrypoint wiring to persist events to a file such as:
- `artifacts/logs/audit.jsonl`

## Operational Notes
- Treat missing eval/audit/policy artifacts as readiness failures.
- Keep policy bundles environment-specific and versioned.
- Do not bypass orchestrator policy checkpoints in runtime integrations.


## 6) Quick Demo Walkthrough

### Normal request
```bash
python -c "from evals.runtime import build_runtime_fixture, make_request; f=build_runtime_fixture(); r=f.orchestrator.run(make_request(request_id='ops-demo-ok', tenant_id='tenant-a', user_text='help')); print(r.status)"
```

### Guarded action (denied tool)
```bash
python -c "from evals.runtime import build_runtime_fixture, make_invocation; f=build_runtime_fixture(); d=f.tool_router.route(make_invocation(request_id='ops-demo-deny', tenant_id='tenant-a', tool_name='admin_shell', action='exec', arguments={'command':'whoami'})); print(d.status, d.reason)"
```

### Launch gate summary
```bash
python -c "from pathlib import Path; from launch_gate.engine import SecurityLaunchGate; print(SecurityLaunchGate(repo_root=Path('.')).evaluate().summary)"
```
