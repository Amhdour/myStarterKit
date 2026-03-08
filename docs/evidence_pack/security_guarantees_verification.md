# Security Guarantees Verification Suite

Purpose: provide a reviewer-friendly bridge from **security claim** → **code** → **tests** → **artifact evidence**.

Source of truth: `verification/security_guarantees_manifest.json`.

## Traceability scope

This suite verifies the following release-relevant invariants:
- `tool_router_cannot_be_bypassed`
- `policy_governs_runtime_behavior`
- `retrieval_enforces_boundaries`
- `evals_hit_real_flows`
- `launch_gate_checks_real_evidence`
- `telemetry_supports_replay`

Each invariant is checked for:
1. mapped enforcement files exist,
2. mapped test files exist,
3. mapped artifact evidence globs resolve.

## Commands

```bash
./scripts/regenerate_core_evidence.sh
python -m verification.runner
```

## Verification artifacts

- Machine-readable: `artifacts/logs/verification/security_guarantees.summary.json`
- Reviewer summary: `artifacts/logs/verification/security_guarantees.summary.md`

## What reviewers should confirm quickly

- `status` is `pass` in `security_guarantees.summary.json`.
- No missing enforcement paths or test paths.
- No missing evidence globs for release-relevant invariants.
- Launch gate output (`artifacts/logs/launch_gate/security-readiness-<STAMP>.json`) is not `go` if guarantees verification fails.
