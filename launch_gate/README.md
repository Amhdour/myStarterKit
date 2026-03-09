# launch_gate/

Evidence-driven release-readiness checks for secure support-agent launches.

The launch gate verifies launch status using **real artifacts**, not inferred assumptions:
- Policy artifact exists, parses, and validates.
- Retrieval boundary configuration is explicit (tenant/source allowlists + trust/provenance enforcement).
- Tool-router enforcement is evidenced by required eval scenario outcomes from an aligned eval summary+jsonl run.
- Telemetry evidence exists in audit logs with required event types and lifecycle identity fields.
- Replay evidence (when required) exists, has valid replay schema, and request lifecycle coverage.
- Eval summary thresholds are met and match the underlying jsonl scenario records.
- Eval jsonl records include runtime-realism evidence (`mocked=false` and required runtime components exercised for critical scenarios).
- Fallback readiness is validated in policy and confirmed by fallback eval scenario evidence.
- Kill-switch readiness confirms production kill-switch is disabled.
- IAM integration readiness evidence is present (module/docs/tests + adversarial identity scenarios).
- Secrets-manager readiness evidence is present (provider abstraction + startup policy/docs).
- Adversarial-eval coverage readiness is verified from scenario definitions and eval outcomes.
- Infrastructure boundary evidence and deployment architecture evidence are present and consistent.
- Production deployment attestation is tracked separately from framework/example readiness.
  - Attestation must include explicit `verified_controls`, `residual_risks`, and `deferred_true_production_operations` sections.

Status semantics:
- `go`: no blockers and no residual risks.
- `conditional_go`: no blockers, but residual risks remain.
- `no_go`: one or more blocker checks failed.

Run:

```bash
python -m launch_gate.engine
```

Reproducible evidence workflow (clean-state regeneration of eval/replay/verification/launch-gate outputs):

```bash
./scripts/regenerate_core_evidence.sh
```


Extended summary fields:
- `framework_complete`: core framework-level controls are complete.
- `production_example_ready`: production-realism example domains are evidenced in-repo.
- `production_deployment_ready`: external deployment attestation evidence is present (separate from framework/example readiness).
