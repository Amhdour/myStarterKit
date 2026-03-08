# launch_gate/

Evidence-driven release-readiness checks for secure support-agent launches.

Current checks validate concrete artifacts and outputs:
- Mandatory control files are present.
- Policy artifact exists, is readable JSON, and validates.
- Retrieval boundary configuration is explicit (tenant/source allowlists + trust/provenance enforcement).
- Tool-router enforcement is evidenced by required eval scenario outcomes.
- Telemetry audit output exists and contains required event coverage.
- Replay artifacts exist (when required) and contain required event counts.
- Eval summary output exists and meets threshold + outcome-health constraints.
- Fallback readiness is validated in policy and confirmed by fallback eval evidence.
- Kill-switch readiness confirms production kill-switch is disabled.

Readiness outputs:
- `go`: no blockers and no residual risks.
- `conditional_go`: no blockers, but residual risks remain.
- `no_go`: one or more blocker checks failed.
