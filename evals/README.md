# evals/

Reusable AI security eval and red-team harness.

Phase 7 adds:
- Eval runner framework (`SecurityEvalRunner`) that exercises real runtime paths.
- JSON scenario format with severity labels, execution-path labeling (`full_runtime` vs `router_only`), and explicit expectation checks.
- Baseline security scenarios covering prompt injection, retrieval abuse, tenant boundaries,
  unsafe disclosure attempts, tool misuse, policy bypass, fallback-to-RAG, and auditability.
- Regression-friendly output artifacts:
  - scenario-level JSONL
  - summary JSON with outcome counts (`pass`, `fail`, `expected_fail`, `blocked`, `inconclusive`)

Notes on realism:
- `orchestrator_request` and `audit_verification` scenarios run the real orchestrator + policy + retrieval + audit pipeline.
- `tool_execution` scenarios run real secure router mediation and registry execution.
- `router_only` scenarios are explicitly marked when orchestrator-level tool execution is not exposed in the current runtime flow.

Run example:

```bash
python -m evals.runner
```


See also: `docs/adversarial_evals.md` for explicit attack-scenario coverage and defended/deferred boundaries.
