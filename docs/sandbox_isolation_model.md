# High-Risk Tool Sandboxing & Isolation Model

## Tool risk classes

- `low`: read-only, low-impact operations.
- `moderate`: external side effects but bounded impact.
- `high`: code execution/filesystem/network/admin impact.

## Required controls for high-risk tools

High-risk tools must define:
- `risk_class: high`
- `isolation_profile`
- `isolation_boundary`

And runtime must enforce:
- explicit policy approval (`high_risk_approved`)
- confirmation required
- tighter rate limit (max 1/min)
- deny-by-default if isolation metadata is missing

## Isolation expression today

This repository provides a declarative isolation abstraction (`tools/isolation.py`) and router enforcement checks. Full container-level isolation is not yet implemented here; this is surfaced as explicit deferred work and launch-gate readiness checks.

## Launch-gate behavior

If policy approves any high-risk tools without detectable isolation enforcement readiness evidence, launch-gate marks `high_risk_tool_isolation_readiness` as failed.
