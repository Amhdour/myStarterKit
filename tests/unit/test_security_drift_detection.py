"""Tests for machine-checkable security drift detection."""

import json
from pathlib import Path

from verification.drift import run_security_drift_checks


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _minimal_repo(tmp_path: Path) -> None:
    for required in (
        "app/orchestrator.py",
        "policies/engine.py",
        "retrieval/service.py",
        "tools/router.py",
        "telemetry/audit/contracts.py",
        "launch_gate/engine.py",
        "verification/security_guarantees_manifest.json",
    ):
        target = tmp_path / required
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# control")

    _write(
        tmp_path / "config/security_drift_manifest.json",
        {
            "required_controls": [
                "app/orchestrator.py",
                "policies/engine.py",
                "retrieval/service.py",
                "tools/router.py",
                "telemetry/audit/contracts.py",
                "launch_gate/engine.py",
                "verification/security_guarantees_manifest.json",
            ],
            "expected_tool_ids": ["ticket_lookup"],
            "expected_retrieval_source_ids": ["kb-main"],
            "expected_integration_ids": ["retrieval_backend.default"],
            "required_eval_scenario_ids": ["policy_bypass_attempt"],
            "required_audit_record_fields": ["event_id", "trace_id", "request_id", "actor_id", "tenant_id", "event_type", "event_payload", "created_at"],
            "required_replay_fields": ["replay_version", "trace_id", "request_id", "actor_id", "tenant_id", "event_type_counts", "decision_summary", "timeline"],
        },
    )

    _write(
        tmp_path / "policies/bundles/default/policy.json",
        {
            "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "medium"},
            "risk_tiers": {"medium": {"max_retrieval_top_k": 5, "tools_enabled": True}},
            "retrieval": {"allowed_tenants": ["tenant-a"], "tenant_allowed_sources": {"tenant-a": ["kb-main"]}},
            "tools": {
                "allowed_tools": ["ticket_lookup"],
                "forbidden_tools": [],
                "confirmation_required_tools": [],
                "forbidden_fields_per_tool": {},
                "rate_limits_per_tool": {},
            },
            "integrations": {"allowed_integrations": ["retrieval_backend.default"]},
        },
    )

    _write(
        tmp_path / "config/integration_inventory.json",
        {
            "integrations": [
                {
                    "integration_id": "retrieval_backend.default",
                    "category": "retrieval_backend",
                    "trust_class": "restricted",
                    "allowed_data_classes": ["metadata"],
                    "tenant_scope": "tenant",
                    "auth_method": "service_identity",
                    "logging_constraints": ["query_redacted"],
                    "failure_mode": "deny_closed",
                }
            ]
        },
    )

    _write(
        tmp_path / "evals/scenarios/security_baseline.json",
        {"scenarios": [{"id": "policy_bypass_attempt", "title": "x"}]},
    )


def test_drift_detection_passes_when_surfaces_align(tmp_path) -> None:
    _minimal_repo(tmp_path)
    report = run_security_drift_checks(tmp_path)
    assert report["status"] == "pass"


def test_drift_detection_fails_on_undocumented_tool(tmp_path) -> None:
    _minimal_repo(tmp_path)
    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload["tools"]["allowed_tools"] = ["ticket_lookup", "new_tool"]
    policy_path.write_text(json.dumps(payload))

    report = run_security_drift_checks(tmp_path)

    assert report["status"] == "fail"
    tool_check = next(item for item in report["results"] if item["check_name"] == "policy_tool_registry_drift")
    assert "new_tool" in tool_check["evidence"]["undocumented_tools"]
