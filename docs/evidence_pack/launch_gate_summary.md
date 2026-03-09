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


## Production-realism domains checked

- IAM integration readiness
- Secrets-manager readiness
- High-risk sandbox/isolation readiness
- Adversarial-eval coverage readiness
- Infrastructure boundary evidence
- Deployment architecture evidence
- Production deployment attestation (tracked separately as deployment-completeness signal)

Interpretation:
- Framework can be complete while production deployment attestation is still missing.
- In that case, launch gate should not claim production deployment readiness; it reports residual risk and explicit missing attestation evidence.


## Production-realism hardening summary

- IAM, secrets-manager, adversarial-coverage, infrastructure-boundary, deployment-architecture, and production-attestation domains are now explicit launch-gate checks.
- Readiness output distinguishes framework completeness from production-example readiness and production-deployment attestation status.
- Evidence expectations are enforced by machine-checkable artifacts and scenario outcomes rather than doc-only claims.


## Residual-risk summary

- Missing/incomplete production deployment attestation is a residual risk and prevents claiming full production deployment readiness.
- Repository evidence cannot directly prove external cloud control-plane settings; those controls require deployment-context evidence.


## Deferred true-production-operations summary

- External penetration testing and independently signed security attestations remain out of scope for this repository.
- Continuous SRE/SecOps operations evidence (drills, incident KPIs, long-term anomaly telemetry) is expected from production deployment pipelines.
