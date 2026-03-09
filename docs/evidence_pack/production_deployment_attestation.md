# Production Deployment Attestation

This evidence artifact is intentionally explicit about what has been implemented in-repo versus what remains external to repository controls.

## verified_controls
- [x] Launch-gate checks for policy, eval evidence, replay evidence, infrastructure boundaries, IAM integration signals, and secrets-manager readiness are wired and tested.
- [x] Adversarial security scenarios are defined and evaluated with expected outcomes for both deny-paths and expected-fail drift guardrails.
- [x] High-risk tool execution path is policy-mediated and produces sandbox evidence artifacts.

## residual_risks
- Repository checks do not directly attest cloud firewall/security-group state; those controls are expected from deployment infrastructure.
- Secrets-provider examples are integration patterns and do not include a live vendor SDK binding in this starter kit.
- IAM examples validate mapping and claims in code/tests, but trust still depends on production key management and IdP configuration.

## deferred_true_production_operations
- External penetration test execution and signed report ingestion into evidence pipeline.
- Independent attestation of production control-plane configuration (network policies, IAM trust policies, secret rotation SLAs).
- Continuous runtime anomaly detection and incident response drill metrics operated by production SRE/SecOps.
