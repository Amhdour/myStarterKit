# Security Drift Detection

This repository includes machine-checkable drift detection to prevent silent divergence between implemented controls and security assumptions.

## Drift classes checked
- Required control file drift (`required_controls` missing from repo).
- Policy/tool surface drift (policy references tools not documented in drift manifest).
- Retrieval boundary drift (policy retrieval sources diverge from documented boundary list).
- Integration surface drift (policy/inventory/manifest integration IDs diverge).
- Eval contract drift (required security scenario IDs missing from eval scenario file).
- Telemetry/replay schema drift (required audit/replay fields no longer present in generated records/artifacts).

## Runtime connections
- Launch gate check: `drift_detection_readiness` (blocking on critical drift).
- CI script: `scripts/check_drift.sh`.
- Evidence pack check now runs drift script via `scripts/check_evidence_pack.sh`.

## Why this matters
Security hardening can silently regress as policy bundles, scenarios, or registries evolve. Drift checks force explicit updates to machine-readable manifests before release readiness returns to `go`.

## Residual risk
- Drift checks are only as complete as the manifest coverage.
- Semantic quality of controls is not fully proven by structural matching; this remains covered by evals/review.
