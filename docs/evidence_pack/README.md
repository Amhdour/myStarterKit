# Evidence Pack

This folder contains reviewer-ready evidence artifacts for security review, launch review, and portfolio presentation.

## Contents
- `architecture_summary.md`
- `control_summary.md`
- `trust_boundary_summary.md`
- `threat_model_summary.md`
- `policy_summary.md`
- `retrieval_security_summary.md`
- `tool_authorization_summary.md`
- `telemetry_audit_summary.md`
- `eval_summary.md`
- `launch_gate_summary.md`
- `residual_risks.md`
- `open_issues.md`
- `incident_readiness_summary.md`
- `retrofit_evidence_checklist.md`

## How to Use
1. Regenerate core machine evidence from a clean state:
   ```bash
   ./scripts/regenerate_core_evidence.sh
   ```
   Optional deterministic override:
   ```bash
   EVIDENCE_STAMP=20260101T000000Z ./scripts/regenerate_core_evidence.sh
   ```
   The script fails closed if either:
   - security guarantees verification is not `pass`, or
   - launch-gate output status is not `go`.
2. Confirm output artifacts were generated:
   - `artifacts/logs/evals/security-redteam-<STAMP>.jsonl`
   - `artifacts/logs/evals/security-redteam-<STAMP>.summary.json`
   - `artifacts/logs/replay/security-redteam-<STAMP>-*.replay.json`
   - `artifacts/logs/verification/security_guarantees.summary.json`
   - `artifacts/logs/verification/security_guarantees.summary.md`
   - `artifacts/logs/launch_gate/security-readiness-<STAMP>.json`
3. Run `./scripts/check_evidence_pack.sh` to verify required evidence docs are present.
4. Update this pack with current outputs and observations.
5. Attach the folder (or exported PDF bundle) during security/client/portfolio review.

## Evidence Integrity Notes
- Do not claim controls that are not implemented.
- Include command outputs and artifact paths where applicable.
- Mark assumptions and limitations explicitly in `residual_risks.md` and `open_issues.md`.

## Retrofit Review Mode
- Retrofit mode guide: `docs/retrofit_mode.md`.
- System profile template: `docs/templates/retrofit_system_profile.template.json`.
- Control mapping template: `docs/templates/retrofit_control_mapping.template.json`.
- Retrofit evidence checklist: `docs/evidence_pack/retrofit_evidence_checklist.md`.
