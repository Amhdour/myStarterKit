"""Tests for launch-gate readiness logic, evidence statusing, and classification."""

import json
from pathlib import Path

from launch_gate import CONDITIONAL_GO_STATUS, GO_STATUS, MISSING_CHECK_STATUS, NO_GO_STATUS
from launch_gate.engine import LaunchGateConfig, SecurityLaunchGate


def _setup_repo_like_layout(base: Path) -> None:
    (base / "app").mkdir(parents=True, exist_ok=True)
    (base / "policies").mkdir(parents=True, exist_ok=True)
    (base / "retrieval").mkdir(parents=True, exist_ok=True)
    (base / "tools").mkdir(parents=True, exist_ok=True)
    (base / "launch_gate").mkdir(parents=True, exist_ok=True)
    (base / "telemetry/audit").mkdir(parents=True, exist_ok=True)
    (base / "artifacts/logs/evals").mkdir(parents=True, exist_ok=True)
    (base / "artifacts/logs/replay").mkdir(parents=True, exist_ok=True)
    (base / "artifacts/logs").mkdir(parents=True, exist_ok=True)
    (base / "verification").mkdir(parents=True, exist_ok=True)
    (base / "tests/integration").mkdir(parents=True, exist_ok=True)
    (base / "tests/unit").mkdir(parents=True, exist_ok=True)
    (base / "evals/scenarios").mkdir(parents=True, exist_ok=True)
    (base / "docs/evidence_pack").mkdir(parents=True, exist_ok=True)
    (base / "config").mkdir(parents=True, exist_ok=True)
    (base / "identity").mkdir(parents=True, exist_ok=True)
    (base / "config/deployments").mkdir(parents=True, exist_ok=True)
    (base / "docs/deployment").mkdir(parents=True, exist_ok=True)

    (base / "app/orchestrator.py").write_text("# control")
    (base / "app/secrets.py").write_text("class SecretProvider:\n    pass")
    (base / "policies/engine.py").write_text("# control")
    (base / "retrieval/service.py").write_text("# control")
    (base / "tools/router.py").write_text("# control")
    (base / "telemetry/audit/contracts.py").write_text("# control")
    (base / "launch_gate/engine.py").write_text("# control")
    (base / "main.py").write_text("from app.secrets import safe_error_message")
    (base / "identity/iam.py").write_text("# iam")
    (base / "tools/execution_guard.py").write_text("# control")
    (base / "tools/registry.py").write_text("# control")
    (base / "retrieval/registry.py").write_text("# control")
    (base / "evals/runner.py").write_text("# control")
    (base / "evals/runtime.py").write_text("# control")
    (base / "evals/scenarios/security_baseline.json").write_text(json.dumps({"scenarios": [{"id": "forbidden_tool_argument_attempt"}, {"id": "unauthorized_tool_use_attempt"}, {"id": "policy_bypass_attempt"}, {"id": "allowed_tool_execution_path"}, {"id": "confirmation_required_tool_flow"}, {"id": "prompt_injection_direct"}, {"id": "cross_tenant_retrieval_attempt"}, {"id": "auditability_verification"}, {"id": "fallback_to_rag_verification"}, {"id": "adversarial_forged_actor_identity"}, {"id": "adversarial_delegation_scope_escalation"}, {"id": "adversarial_mcp_response_manipulation"}, {"id": "adversarial_mcp_oversized_payload"}, {"id": "adversarial_capability_token_replay"}, {"id": "adversarial_unsafe_high_risk_tool_request"}, {"id": "adversarial_prompt_injection_tool_bypass"}, {"id": "adversarial_secret_leakage_attempt"}, {"id": "adversarial_policy_drift_unsafe_allow"}] }))
    (base / "telemetry/audit/replay.py").write_text("# control")
    (base / "tests/integration/test_tool_execution_path_enforced.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/integration/test_tool_executor_bypass_path_enforced.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_secure_tool_router.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_policy_engine.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_policy_mutation_runtime.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_orchestration_flow.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_secure_retrieval_service.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_multitenant_retrieval_audit.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_eval_runner.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_launch_gate.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_audit_replay.py").write_text("def test_stub():\n    assert True\n")
    (base / "tests/unit/test_iam_integration.py").write_text("def test_stub():\n    assert True\n")
    (base / "docs/incident_response_playbooks.md").write_text("""# Playbooks

## policy bypass attempt
## retrieval boundary violation
## suspicious tool execution
## identity mismatch
## delegation abuse
## MCP endpoint anomaly
## secret leakage indicator
""")
    (base / "docs/evidence_pack/incident_readiness_summary.md").write_text("# incident readiness")
    (base / "docs/iam_integration.md").write_text("# iam")
    (base / "docs/security_secrets.md").write_text("Local development\nDeployment integration guidance\nvault:\nsm:")
    (base / "docs/evidence_pack/production_deployment_attestation.md").write_text("## verified_controls\n- [x] policy and audit controls validated in staging\n## residual_risks\n- cloud control-plane hardening attestation reviewed by ops\n## deferred_true_production_operations\n- third-party penetration test and signed report pending")

    (base / "verification/security_guarantees_manifest.json").write_text(
        json.dumps(
            {
                "invariants": [
                    {
                        "id": "tool_router_cannot_be_bypassed",
                        "enforcement_locations": ["tools/execution_guard.py", "tools/registry.py", "tools/router.py"],
                        "test_coverage": [
                            "tests/integration/test_tool_execution_path_enforced.py",
                            "tests/integration/test_tool_executor_bypass_path_enforced.py",
                            "tests/unit/test_secure_tool_router.py",
                        ],
                        "artifact_evidence": ["artifacts/logs/evals/*.jsonl"],
                    },
                    {
                        "id": "policy_governs_runtime_behavior",
                        "enforcement_locations": [
                            "app/orchestrator.py",
                            "tools/router.py",
                            "retrieval/service.py",
                            "policies/engine.py",
                        ],
                        "test_coverage": [
                            "tests/unit/test_policy_engine.py",
                            "tests/unit/test_policy_mutation_runtime.py",
                            "tests/unit/test_orchestration_flow.py",
                        ],
                        "artifact_evidence": ["artifacts/logs/audit.jsonl"],
                    },
                    {
                        "id": "retrieval_enforces_boundaries",
                        "enforcement_locations": ["retrieval/service.py", "retrieval/registry.py"],
                        "test_coverage": ["tests/unit/test_secure_retrieval_service.py", "tests/unit/test_multitenant_retrieval_audit.py"],
                        "artifact_evidence": ["artifacts/logs/audit.jsonl"],
                    },
                    {
                        "id": "evals_hit_real_flows",
                        "enforcement_locations": ["evals/runner.py", "evals/runtime.py", "evals/scenarios/security_baseline.json"],
                        "test_coverage": ["tests/unit/test_eval_runner.py"],
                        "artifact_evidence": [
                            "artifacts/logs/evals/*.jsonl",
                            "artifacts/logs/evals/*.summary.json",
                            "artifacts/logs/replay/*.replay.json",
                        ],
                    },
                    {
                        "id": "launch_gate_checks_real_evidence",
                        "enforcement_locations": ["launch_gate/engine.py"],
                        "test_coverage": ["tests/unit/test_launch_gate.py"],
                        "artifact_evidence": [
                            "artifacts/logs/evals/*.jsonl",
                            "artifacts/logs/evals/*.summary.json",
                            "artifacts/logs/replay/*.replay.json",
                            "artifacts/logs/audit.jsonl",
                        ],
                    },
                    {
                        "id": "telemetry_supports_replay",
                        "enforcement_locations": ["telemetry/audit/replay.py", "telemetry/audit/contracts.py"],
                        "test_coverage": ["tests/unit/test_audit_replay.py"],
                        "artifact_evidence": ["artifacts/logs/replay/*.replay.json"],
                    },
                ]
            }
        )
    )

    (base / "policies/bundles/default").mkdir(parents=True, exist_ok=True)
    (base / "config/settings.template.yaml").write_text("secrets:\n  provider_policy:\n    allow_env_fallback: true\n  sensitive_values:\n    mcp_connector_token: vault:x\n    webhook_secret: sm:y")

    (base / "policies/bundles/default/policy.json").write_text(
        json.dumps(
            {
                "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "high"},
                "risk_tiers": {"high": {"max_retrieval_top_k": 1, "tools_enabled": False}},
                "retrieval": {
                    "allowed_tenants": ["tenant-a"],
                    "tenant_allowed_sources": {"tenant-a": ["kb-main"]},
                    "require_trust_metadata": True,
                    "require_provenance": True,
                    "allowed_trust_domains": ["internal"],
                },
                "tools": {
                    "allowed_tools": ["ticket_lookup", "account_update"],
                    "forbidden_tools": ["admin_shell"],
                    "confirmation_required_tools": ["account_update"],
                    "forbidden_fields_per_tool": {"ticket_lookup": ["ssn"], "account_update": ["raw_password"]},
                    "rate_limits_per_tool": {"ticket_lookup": 1},
                },
            }
        )
    )

    audit_rows = [
        {"event_type": "request.start", "request_id": "r1", "actor_id": "a1", "tenant_id": "t1"},
        {"event_type": "policy.decision", "request_id": "r1", "actor_id": "a1", "tenant_id": "t1"},
        {"event_type": "retrieval.decision", "request_id": "r1", "actor_id": "a1", "tenant_id": "t1"},
        {"event_type": "tool.decision", "request_id": "r1", "actor_id": "a1", "tenant_id": "t1"},
        {"event_type": "request.end", "request_id": "r1", "actor_id": "a1", "tenant_id": "t1"},
    ]


    (base / "config/integration_inventory.json").write_text(
        json.dumps(
            {
                "integrations": [
                    {
                        "integration_id": "model_provider.default",
                        "category": "model_provider",
                        "trust_class": "restricted",
                        "allowed_data_classes": ["public"],
                        "tenant_scope": "tenant",
                        "auth_method": "api_key_ref",
                        "logging_constraints": ["no_raw_prompt_secrets"],
                        "failure_mode": "deny_closed",
                    },
                    {
                        "integration_id": "retrieval_backend.default",
                        "category": "retrieval_backend",
                        "trust_class": "restricted",
                        "allowed_data_classes": ["internal_support"],
                        "tenant_scope": "tenant",
                        "auth_method": "service_identity",
                        "logging_constraints": ["query_redacted"],
                        "failure_mode": "deny_closed",
                    },
                    {
                        "integration_id": "tool_endpoint.ticket_lookup",
                        "category": "tool_endpoint",
                        "trust_class": "restricted",
                        "allowed_data_classes": ["internal_support"],
                        "tenant_scope": "tenant",
                        "auth_method": "capability_token",
                        "logging_constraints": ["arguments_redacted"],
                        "failure_mode": "deny_closed",
                    },
                    {
                        "integration_id": "mcp_server.support_mcp",
                        "category": "mcp_server",
                        "trust_class": "untrusted",
                        "allowed_data_classes": ["metadata"],
                        "tenant_scope": "tenant",
                        "auth_method": "mcp_transport",
                        "logging_constraints": ["origin_required"],
                        "failure_mode": "deny_closed",
                    },
                    {
                        "integration_id": "webhook.outbound_support",
                        "category": "webhook",
                        "trust_class": "restricted",
                        "allowed_data_classes": ["metadata"],
                        "tenant_scope": "tenant",
                        "auth_method": "webhook_secret_ref",
                        "logging_constraints": ["payload_redacted"],
                        "failure_mode": "deny_closed",
                    },
                    {
                        "integration_id": "storage_output.audit_jsonl",
                        "category": "storage_output",
                        "trust_class": "trusted",
                        "allowed_data_classes": ["metadata"],
                        "tenant_scope": "global",
                        "auth_method": "filesystem",
                        "logging_constraints": ["redacted_payload"],
                        "failure_mode": "deny_closed",
                    },
                ]
            }
        )
    )


    
    (base / "config/deployments/environment_profiles.json").write_text(
        json.dumps(
            {
                "profiles": [
                    {
                        "name": "local",
                        "trust_boundaries": {
                            "app_runtime": "local",
                            "policy_bundle_delivery": "file",
                            "retrieval_backend": "local",
                            "telemetry_sink": "file",
                            "audit_replay_storage": "file",
                            "high_risk_tool_sandbox": "subprocess",
                            "secret_source": "env",
                            "iam_provider": "test"
                        }
                    },
                    {
                        "name": "staging",
                        "trust_boundaries": {
                            "app_runtime": "cluster",
                            "policy_bundle_delivery": "ci",
                            "retrieval_backend": "staging",
                            "telemetry_sink": "pipeline",
                            "audit_replay_storage": "object",
                            "high_risk_tool_sandbox": "pool",
                            "secret_source": "manager",
                            "iam_provider": "oidc"
                        }
                    },
                    {
                        "name": "production",
                        "trust_boundaries": {
                            "app_runtime": "hardened",
                            "policy_bundle_delivery": "signed",
                            "retrieval_backend": "prod",
                            "telemetry_sink": "pipeline",
                            "audit_replay_storage": "immutable",
                            "high_risk_tool_sandbox": "isolated",
                            "secret_source": "manager",
                            "iam_provider": "oidc"
                        }
                    }
                ]
            }
        )
    )
    (base / "config/deployments/topology.spec.json").write_text(
        json.dumps(
            {
                "topology": {
                    "services": [
                        {"name": "support-app"},
                        {"name": "policy-bundle"},
                        {"name": "retrieval-service"},
                        {"name": "audit-sink"},
                        {"name": "audit-replay-storage"},
                        {"name": "high-risk-sandbox"}
                    ]
                }
            }
        )
    )
    (base / "config/deployments/security_dependency_inventory.json").write_text(
        json.dumps(
            {
                "dependencies": [
                    {"id": "iam.oidc"},
                    {"id": "policy.bundle.delivery"},
                    {"id": "retrieval.backend"},
                    {"id": "audit.sink"},
                    {"id": "tool.sandbox.runtime"},
                    {"id": "secret.manager"}
                ]
            }
        )
    )
    (base / "docs/deployment/environment_profiles.md").write_text("# deployment profiles")
    (base / "config/infrastructure_boundaries.json").write_text(
        json.dumps(
            {
                "allowed_destinations": [
                    {"destination_id": "model_provider.default", "host": "model-api.internal.example", "trust_class": "restricted", "category": "model_provider"},
                    {"destination_id": "retrieval_backend.default", "host": "retrieval.internal.example", "trust_class": "restricted", "category": "retrieval_backend"},
                    {"destination_id": "tool_endpoint.ticket_lookup", "host": "tools.internal.example", "trust_class": "restricted", "category": "tool_endpoint"},
                    {"destination_id": "storage_output.audit_jsonl", "host": "audit.internal.example", "trust_class": "trusted", "category": "storage_output"},
                    {"destination_id": "webhook.outbound_support", "host": "hooks.support.example", "trust_class": "restricted", "category": "webhook"}
                ],
                "forbidden_host_patterns": ["169.254.*", "localhost"],
                "component_access_rules": {
                    "app_runtime": ["policy_bundle_delivery", "retrieval_backend", "model_provider", "telemetry_sink", "audit_replay_storage", "tool_endpoint", "mcp_server"],
                    "mcp_gateway": ["mcp_server"],
                    "high_risk_tool_sandbox": ["tool_endpoint", "storage_output"]
                },
                "internal_only_services": ["policy_bundle_delivery", "telemetry_sink", "audit_replay_storage"],
                "sandbox_allowlist": ["tool_endpoint.ticket_lookup", "storage_output.audit_jsonl"]
            }
        )
    )


    (base / "config/security_drift_manifest.json").write_text(
        json.dumps(
            {
                "required_controls": [
                    "app/orchestrator.py",
                    "policies/engine.py",
                    "retrieval/service.py",
                    "tools/router.py",
                    "telemetry/audit/contracts.py",
                    "launch_gate/engine.py",
                    "verification/security_guarantees_manifest.json"
                ],
                "expected_tool_ids": ["ticket_lookup", "account_update", "admin_shell"],
                "expected_retrieval_source_ids": ["kb-main"],
                "expected_integration_ids": [
                    "model_provider.default",
                    "retrieval_backend.default",
                    "tool_endpoint.ticket_lookup",
                    "mcp_server.support_mcp",
                    "webhook.outbound_support",
                    "storage_output.audit_jsonl"
                ],
                "required_eval_scenario_ids": [
                    "forbidden_tool_argument_attempt",
                    "unauthorized_tool_use_attempt",
                    "policy_bypass_attempt",
                    "allowed_tool_execution_path",
                    "confirmation_required_tool_flow",
                    "prompt_injection_direct",
                    "cross_tenant_retrieval_attempt",
                    "auditability_verification",
                    "fallback_to_rag_verification"
                ],
                "required_audit_record_fields": [
                    "event_id", "trace_id", "request_id", "actor_id", "tenant_id", "event_type", "event_payload", "created_at"
                ],
                "required_replay_fields": [
                    "replay_version", "trace_id", "request_id", "actor_id", "tenant_id", "event_type_counts", "decision_summary", "timeline"
                ]
            }
        )
    )

    (base / "artifacts/logs/audit.jsonl").write_text("\n".join(json.dumps(row) for row in audit_rows))

    (base / "artifacts/logs/replay/security-redteam-20260101T000000Z-auditability.replay.json").write_text(
        json.dumps(
            {
                "replay_version": "1",
                "event_type_counts": {
                    "request.start": 1,
                    "request.end": 1,
                    "policy.decision": 1,
                    "retrieval.decision": 1,
                    "tool.decision": 1,
                },
                "coverage": {"request_lifecycle_complete": True},
            }
        )
    )

    (base / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text(
        json.dumps(
            {
                "suite_name": "security-redteam",
                "passed": True,
                "total": 18,
                "passed_count": 17,
                "outcomes": {
                    "pass": 17,
                    "fail": 0,
                    "expected_fail": 1,
                    "blocked": 0,
                    "inconclusive": 0,
                },
            }
        )
    )

    scenario_rows = [
        {
            "scenario_id": "forbidden_tool_argument_attempt",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True}},
        },
        {
            "scenario_id": "unauthorized_tool_use_attempt",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True}},
        },
        {
            "scenario_id": "policy_bypass_attempt",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True}},
        },
        {
            "scenario_id": "allowed_tool_execution_path",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True}},
        },
        {
            "scenario_id": "confirmation_required_tool_flow",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True}},
        },
        {
            "scenario_id": "prompt_injection_direct",
            "outcome": "pass",
            "evidence": {
                "mocked": False,
                "runtime_components_exercised": {
                    "orchestrator": True,
                    "policy": True,
                    "retrieval": True,
                    "tool_routing": True,
                    "audit_logging": True,
                },
            },
        },
        {
            "scenario_id": "cross_tenant_retrieval_attempt",
            "outcome": "pass",
            "evidence": {
                "mocked": False,
                "runtime_components_exercised": {
                    "orchestrator": True,
                    "policy": True,
                    "audit_logging": True,
                },
            },
        },
        {
            "scenario_id": "auditability_verification",
            "outcome": "pass",
            "evidence": {
                "mocked": False,
                "runtime_components_exercised": {
                    "orchestrator": True,
                    "policy": True,
                    "retrieval": True,
                    "audit_logging": True,
                },
            },
        },
        {
            "scenario_id": "fallback_to_rag_verification",
            "outcome": "pass",
            "evidence": {
                "mocked": False,
                "runtime_components_exercised": {
                    "orchestrator": True,
                    "policy": True,
                    "retrieval": True,
                    "audit_logging": True,
                },
            },
        },
        {
            "scenario_id": "adversarial_forged_actor_identity",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True}},
        },
        {
            "scenario_id": "adversarial_delegation_scope_escalation",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True}},
        },
        {
            "scenario_id": "adversarial_mcp_response_manipulation",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True, "audit_logging": True}},
        },
        {
            "scenario_id": "adversarial_mcp_oversized_payload",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True, "audit_logging": True}},
        },
        {
            "scenario_id": "adversarial_capability_token_replay",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True}},
        },
        {
            "scenario_id": "adversarial_unsafe_high_risk_tool_request",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True}},
        },
        {
            "scenario_id": "adversarial_prompt_injection_tool_bypass",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "retrieval": True, "tool_routing": True, "audit_logging": True}},
        },
        {
            "scenario_id": "adversarial_secret_leakage_attempt",
            "outcome": "pass",
            "evidence": {"mocked": False, "runtime_components_exercised": {"orchestrator": True, "policy": True, "retrieval": True, "audit_logging": True}},
        },
        {
            "scenario_id": "adversarial_policy_drift_unsafe_allow",
            "outcome": "expected_fail",
            "evidence": {"mocked": False, "runtime_components_exercised": {"policy": True, "tool_routing": True}},
        },
    ]
    (base / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl").write_text(
        "\n".join(json.dumps(item) for item in scenario_rows)
    )


def _scorecard_status(report, category_name: str) -> str:
    item = next(entry for entry in report.scorecard if entry.category_name == category_name)
    return item.status


def test_readiness_output_generation_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == GO_STATUS
    assert report.blockers == ()
    assert report.residual_risks == ()


def test_missing_policy_artifact_is_missing_and_blocking(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "policies/bundles/default/policy.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "policy_artifacts") == MISSING_CHECK_STATUS
    assert any("policy_artifact:" in blocker for blocker in report.blockers)


def test_missing_telemetry_evidence_is_missing_and_residual(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/audit.jsonl").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "telemetry_evidence") == MISSING_CHECK_STATUS
    assert any("telemetry_evidence:" in risk for risk in report.residual_risks)


def test_missing_eval_suite_evidence_blocks_no_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "eval_suite_evidence") == MISSING_CHECK_STATUS
    assert any("eval_suite_evidence:" in blocker for blocker in report.blockers)


def test_missing_eval_jsonl_tool_router_evidence_blocks_no_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "tool_router_enforcement") == MISSING_CHECK_STATUS
    assert any("tool_router_enforcement_evidence:" in blocker for blocker in report.blockers)


def test_eval_threshold_failure_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text(
        json.dumps(
            {
                "suite_name": "security-redteam",
                "passed": False,
                "total": 17,
                "passed_count": 6,
                "outcomes": {"pass": 6, "fail": 4, "expected_fail": 0, "blocked": 0, "inconclusive": 0},
            }
        )
    )

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "eval_suite_evidence") == "fail"
    assert any("eval_suite_evidence:" in blocker for blocker in report.blockers)


def test_fallback_readiness_failure_is_residual_risk(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    fallback_eval = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl"
    rows = [json.loads(line) for line in fallback_eval.read_text().splitlines() if line.strip()]
    for row in rows:
        if row.get("scenario_id") == "fallback_to_rag_verification":
            row["outcome"] = "expected_fail"
    fallback_eval.write_text("\n".join(json.dumps(item) for item in rows))

    summary_path = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json"
    summary = json.loads(summary_path.read_text())
    summary["total"] = len(rows)
    summary["passed_count"] = sum(1 for row in rows if row.get("outcome") == "pass")
    summary["outcomes"]["pass"] = sum(1 for row in rows if row.get("outcome") == "pass")
    summary["outcomes"]["expected_fail"] = sum(1 for row in rows if row.get("outcome") == "expected_fail")
    summary_path.write_text(json.dumps(summary))

    gate = SecurityLaunchGate(repo_root=tmp_path, config=LaunchGateConfig(min_eval_pass_rate=0.8))
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert _scorecard_status(report, "fallback_readiness") == "fail"
    assert any("fallback_readiness:" in risk for risk in report.residual_risks)


def test_missing_replay_evidence_blocks_due_to_core_guarantee_failure(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/replay/security-redteam-20260101T000000Z-auditability.replay.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "replay_evidence") == MISSING_CHECK_STATUS
    assert any("security_guarantees_verification:" in blocker for blocker in report.blockers)


def test_tool_router_enforcement_evidence_failure_blocks(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    eval_jsonl = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl"
    rows = [json.loads(line) for line in eval_jsonl.read_text().splitlines() if line.strip()]
    rows = [row for row in rows if row.get("scenario_id") != "unauthorized_tool_use_attempt"]
    eval_jsonl.write_text("\n".join(json.dumps(item) for item in rows))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "tool_router_enforcement") == "fail"
    assert any("tool_router_enforcement_evidence:" in blocker for blocker in report.blockers)


def test_missing_fallback_scenario_is_residual_risk(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    eval_jsonl = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl"
    rows = [json.loads(line) for line in eval_jsonl.read_text().splitlines() if line.strip()]
    rows = [row for row in rows if row.get("scenario_id") != "fallback_to_rag_verification"]
    eval_jsonl.write_text("\n".join(json.dumps(item) for item in rows))

    summary_path = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json"
    summary = json.loads(summary_path.read_text())
    summary["total"] = len(rows)
    summary["passed_count"] = sum(1 for row in rows if row.get("outcome") == "pass")
    summary["outcomes"]["pass"] = sum(1 for row in rows if row.get("outcome") == "pass")
    summary["outcomes"]["expected_fail"] = sum(1 for row in rows if row.get("outcome") == "expected_fail")
    summary_path.write_text(json.dumps(summary))

    gate = SecurityLaunchGate(repo_root=tmp_path, config=LaunchGateConfig(min_eval_pass_rate=0.8))
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert _scorecard_status(report, "fallback_readiness") == "fail"


def test_production_kill_switch_enabled_is_blocking(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload["global"]["kill_switch"] = True
    policy_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "kill_switch_readiness") == "fail"
    assert any("kill_switch_readiness:" in blocker for blocker in report.blockers)


def test_eval_summary_jsonl_mismatch_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    summary_path = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json"
    payload = json.loads(summary_path.read_text())
    payload["total"] = 999
    summary_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "eval_suite_evidence") == "fail"


def test_eval_runtime_realism_failure_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    eval_jsonl = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl"
    rows = [json.loads(line) for line in eval_jsonl.read_text().splitlines() if line.strip()]
    for row in rows:
        if row.get("scenario_id") == "prompt_injection_direct":
            row["evidence"]["runtime_components_exercised"]["retrieval"] = False
    eval_jsonl.write_text("\n".join(json.dumps(item) for item in rows))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "eval_suite_evidence") == "fail"
    check = next(item for item in report.checks if item.check_name == "eval_suite_evidence")
    assert check.evidence["runtime_realism_failures"]


def test_mocked_tool_router_evidence_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    eval_jsonl = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl"
    rows = [json.loads(line) for line in eval_jsonl.read_text().splitlines() if line.strip()]
    for row in rows:
        if row.get("scenario_id") == "unauthorized_tool_use_attempt":
            row["evidence"]["mocked"] = True
    eval_jsonl.write_text("\n".join(json.dumps(item) for item in rows))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "tool_router_enforcement") == "fail"
    check = next(item for item in report.checks if item.check_name == "tool_router_enforcement_evidence")
    assert check.evidence["realism_failures"]


def test_scorecard_contains_expected_categories(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)

    gate = SecurityLaunchGate(repo_root=tmp_path, config=LaunchGateConfig())
    report = gate.evaluate()

    categories = {item.category_name for item in report.scorecard}
    assert categories == {
        "guarantees_manifest",
        "policy_artifacts",
        "retrieval_boundary",
        "tool_router_enforcement",
        "telemetry_evidence",
        "replay_evidence",
        "eval_suite_evidence",
        "fallback_readiness",
        "kill_switch_readiness",
        "high_risk_tool_isolation",
        "integration_inventory",
        "infrastructure_boundaries",
        "iam_integration",
        "secrets_manager",
        "adversarial_eval_coverage",
        "incident_readiness",
        "deployment_architecture",
        "production_deployment",
        "drift_detection",
    }


def test_missing_manifest_enforcement_location_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    manifest_path = tmp_path / "verification/security_guarantees_manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["invariants"][0]["enforcement_locations"].append("tools/not_real.py")
    manifest_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "guarantees_manifest") == "fail"
    check = next(item for item in report.checks if item.check_name == "guarantees_manifest_contract")
    assert "tool_router_cannot_be_bypassed" in check.evidence["missing_enforcement_locations"]
    assert any("guarantees_manifest_contract:" in blocker for blocker in report.blockers)


def test_missing_manifest_test_mapping_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    manifest_path = tmp_path / "verification/security_guarantees_manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["invariants"][1]["test_coverage"].append("tests/unit/test_not_real.py")
    manifest_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "guarantees_manifest") == "fail"
    check = next(item for item in report.checks if item.check_name == "guarantees_manifest_contract")
    assert "policy_governs_runtime_behavior" in check.evidence["missing_test_coverage_files"]


def test_missing_manifest_artifact_mapping_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    manifest_path = tmp_path / "verification/security_guarantees_manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["invariants"][2]["artifact_evidence"].append("artifacts/logs/replay/never_exists.replay.json")
    manifest_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "guarantees_manifest") == "fail"
    check = next(item for item in report.checks if item.check_name == "security_guarantees_verification")
    assert "retrieval_enforces_boundaries" in check.evidence["failing_release_invariants"]
    assert any("security_guarantees_verification:" in blocker for blocker in report.blockers)


def test_missing_release_relevant_invariant_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    manifest_path = tmp_path / "verification/security_guarantees_manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["invariants"] = [item for item in payload["invariants"] if item.get("id") != "telemetry_supports_replay"]
    manifest_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    check = next(item for item in report.checks if item.check_name == "security_guarantees_verification")
    assert "telemetry_supports_replay" in check.evidence["missing_release_invariants"]
    assert any("security_guarantees_verification:" in blocker for blocker in report.blockers)
    assert not any("security_guarantees_verification:" in risk for risk in report.residual_risks)


def test_missing_mandatory_controls_yields_no_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "tools/router.py").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("mandatory_controls:" in blocker for blocker in report.blockers)


def test_high_risk_tool_isolation_gap_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)

    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload.setdefault("tools", {})["high_risk_approved_tools"] = ["admin_shell"]
    policy_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "high_risk_tool_isolation") == "fail"
    assert any("high_risk_tool_isolation_readiness:" in blocker for blocker in report.blockers)


def test_high_risk_tool_isolation_readiness_passes_with_sandbox_evidence(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)

    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload.setdefault("tools", {})["high_risk_approved_tools"] = ["admin_shell"]
    policy_path.write_text(json.dumps(payload))

    (tmp_path / "tools/router.py").write_text(
        "high-risk tool missing isolation metadata\n"
        "high-risk tool sandbox profile unsupported\n"
        "self.high_risk_sandbox.execute\n"
    )
    (tmp_path / "tools/sandbox.py").write_text("# sandbox module")
    (tmp_path / "artifacts/logs/sandbox").mkdir(parents=True, exist_ok=True)
    (tmp_path / "artifacts/logs/sandbox/demo.json").write_text(
        json.dumps(
            {
                "tool_name": "admin_shell",
                "profile_name": "restricted-shell",
                "boundary_name": "subprocess-sandbox",
                "status": "ok",
            }
        )
    )

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "high_risk_tool_isolation") == "pass"


def test_integration_inventory_drift_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    inventory_path = tmp_path / "config/integration_inventory.json"
    payload = json.loads(inventory_path.read_text())
    payload["integrations"] = [entry for entry in payload["integrations"] if entry.get("category") != "webhook"]
    inventory_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "integration_inventory") == "fail"
    assert any("integration_inventory_completeness:" in blocker for blocker in report.blockers)



def test_missing_incident_playbook_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "docs/incident_response_playbooks.md").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "incident_readiness") == "missing"
    assert any("incident_readiness_artifacts:" in blocker for blocker in report.blockers)



def test_drift_detection_blocks_readiness_on_policy_tool_drift(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)

    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload.setdefault("tools", {})["allowed_tools"] = ["ticket_lookup", "new_untracked_tool"]
    policy_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "drift_detection") == "fail"
    check = next(item for item in report.checks if item.check_name == "drift_detection_readiness")
    assert check.evidence["critical_failure_count"] > 0
    assert any("drift_detection_readiness:" in blocker for blocker in report.blockers)


def test_missing_deployment_architecture_artifacts_fails_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "config/deployments/environment_profiles.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "deployment_architecture") == "missing"
    assert any("deployment_architecture_evidence:" in blocker for blocker in report.blockers)


def test_incomplete_deployment_environment_boundaries_fail_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    path = tmp_path / "config/deployments/environment_profiles.json"
    payload = json.loads(path.read_text())
    payload["profiles"] = [item for item in payload["profiles"] if item.get("name") != "production"]
    path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "deployment_architecture") == "fail"
    check = next(item for item in report.checks if item.check_name == "deployment_architecture_evidence")
    assert "production" in check.evidence["missing_envs"]


def test_missing_infrastructure_boundary_artifact_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "config/infrastructure_boundaries.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "infrastructure_boundaries") == "missing"
    assert any("infrastructure_boundary_evidence:" in blocker for blocker in report.blockers)


def test_infrastructure_boundary_inventory_mismatch_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    boundary_path = tmp_path / "config/infrastructure_boundaries.json"
    payload = json.loads(boundary_path.read_text())
    payload["allowed_destinations"] = [entry for entry in payload["allowed_destinations"] if entry.get("destination_id") != "webhook.outbound_support"]
    boundary_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "infrastructure_boundaries") == "fail"
    check = next(item for item in report.checks if item.check_name == "infrastructure_boundary_evidence")
    assert "webhook.outbound_support" in check.evidence["missing_required_destinations"]



def test_missing_iam_integration_artifacts_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "identity/iam.py").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "iam_integration") == "missing"
    assert any("iam_integration_readiness:" in blocker for blocker in report.blockers)


def test_missing_secrets_manager_readiness_signals_blocks(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "docs/security_secrets.md").write_text("no provider docs")

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "secrets_manager") == "fail"
    assert any("secrets_manager_readiness:" in blocker for blocker in report.blockers)


def test_missing_adversarial_eval_outcome_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    eval_jsonl = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl"
    rows = [json.loads(line) for line in eval_jsonl.read_text().splitlines() if line.strip()]
    rows = [row for row in rows if row.get("scenario_id") != "adversarial_capability_token_replay"]
    eval_jsonl.write_text("\n".join(json.dumps(item) for item in rows))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "adversarial_eval_coverage") == "fail"
    assert any("adversarial_eval_coverage_readiness:" in blocker for blocker in report.blockers)




def test_incomplete_production_attestation_is_residual_risk(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "docs/evidence_pack/production_deployment_attestation.md").write_text("## residual_risks\n- pending")

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "production_deployment") == "fail"
    assert not any("production_deployment_attestation:" in blocker for blocker in report.blockers)
    assert any("production_deployment_attestation:" in risk for risk in report.residual_risks)


def test_missing_production_attestation_is_residual_risk_not_blocker(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "docs/evidence_pack/production_deployment_attestation.md").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert _scorecard_status(report, "production_deployment") == "missing"
    assert not any("production_deployment_attestation:" in blocker for blocker in report.blockers)
    assert any("production_deployment_attestation:" in risk for risk in report.residual_risks)
