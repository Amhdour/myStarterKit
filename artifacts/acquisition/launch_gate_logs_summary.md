# Launch-Gate Logs Summary

- Log file: `artifacts/logs/launch_gate/security-readiness-20260101T000000Z.json`
- Launch status: **no_go**
- Summary: status=no_go; checks_passed=17/22; framework_complete=False; production_example_ready=False; production_deployment_ready=True; scorecard=guarantees_manifest:fail, policy_artifacts:pass, retrieval_boundary:pass, tool_router_enforcement:pass, telemetry_evidence:missing, replay_evidence:pass, eval_suite_evidence:fail, fallback_readiness:pass, kill_switch_readiness:pass, high_risk_tool_isolation:pass, integration_inventory:pass, infrastructure_boundaries:fail, iam_integration:pass, secrets_manager:pass, adversarial_eval_coverage:pass, incident_readiness:pass, deployment_architecture:pass, production_deployment:pass, drift_detection:pass; blockers=3; residual_risks=2

## Checks not passing
- `guarantees_manifest_evidence` => fail: guarantees manifest evidence verification failed: missing required evidence artifacts or failing eval evidence
- `security_guarantees_verification` => fail: security guarantees verification failed for release-relevant invariants
- `telemetry_evidence` => missing: telemetry evidence missing: audit log missing
- `eval_suite_evidence` => fail: eval suite evidence failed threshold/outcome health or runtime-realism checks
- `infrastructure_boundary_evidence` => fail: infrastructure boundary controls incomplete

## Residual risks reported by launch gate
- guarantees_manifest_evidence: guarantees manifest evidence verification failed: missing required evidence artifacts or failing eval evidence (evidence=verification/security_guarantees_manifest.json)
- telemetry_evidence: telemetry evidence missing: audit log missing (evidence=artifacts/logs/audit.jsonl)