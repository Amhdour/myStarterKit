# Adversarial Eval Coverage

This repository includes adversarial scenarios in `evals/scenarios/security_baseline.json` that run against real control surfaces in runtime modules.

## Attack scenarios implemented

- Prompt injection attempting tool bypass (`adversarial_prompt_injection_tool_bypass`)
- Cross-tenant retrieval attempt (`cross_tenant_retrieval_attempt`)
- Forged/malformed actor identity (`adversarial_forged_actor_identity`)
- Delegation-chain scope escalation (`adversarial_delegation_scope_escalation`)
- MCP response manipulation (`adversarial_mcp_response_manipulation`)
- MCP oversized payload (`adversarial_mcp_oversized_payload`)
- Capability token replay (`adversarial_capability_token_replay`)
- Unsafe high-risk tool request (`adversarial_unsafe_high_risk_tool_request`)
- Secret leakage prompt attempt (`adversarial_secret_leakage_attempt`)
- Policy drift causing unsafe allow behavior (`adversarial_policy_drift_unsafe_allow` as expected-fail guardrail)

## Real enforcement surfaces exercised

- `policies/engine.py` (tenant/capability/tool checks)
- `retrieval/service.py` (tenant/source/trust/provenance boundaries)
- `tools/router.py` + `tools/registry.py` + `tools/capabilities.py` (tool mediation, replay defense)
- `tools/mcp_security.py` (schema + payload limits + tenant/trust boundaries)
- `identity/models.py` (identity parsing and delegation-chain validation)
- `telemetry/audit/*` and replay builders (`evals/runner.py` replay evidence)

## What each scenario verifies

Scenarios include machine-checked expectations for:
- denied/blocked outcomes or expected-fail outcomes where drift is intentionally induced,
- policy/deny reason evidence,
- required audit events,
- replay reconstruction completeness for request flows.

## Deferred

- Adversarial coverage is runtime-focused; it does not replace production pen-testing, continuous fuzzing, or cryptographic attestation of all evidence artifacts.
