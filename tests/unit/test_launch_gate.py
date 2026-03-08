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
    (base / "telemetry/audit").mkdir(parents=True, exist_ok=True)
    (base / "artifacts/logs/evals").mkdir(parents=True, exist_ok=True)
    (base / "artifacts/logs").mkdir(parents=True, exist_ok=True)

    (base / "app/orchestrator.py").write_text("# control")
    (base / "policies/engine.py").write_text("# control")
    (base / "retrieval/service.py").write_text("# control")
    (base / "tools/router.py").write_text("# control")
    (base / "telemetry/audit/contracts.py").write_text("# control")

    (base / "policies/bundles/default").mkdir(parents=True, exist_ok=True)
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

    (base / "artifacts/logs/audit.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"event_type": "request.start"}),
                json.dumps({"event_type": "policy.decision"}),
                json.dumps({"event_type": "retrieval.decision"}),
                json.dumps({"event_type": "tool.decision"}),
                json.dumps({"event_type": "request.end"}),
            ]
        )
    )

    (base / "artifacts/logs/replay-20260101T000000Z.json").write_text(
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
            }
        )
    )

    (base / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text(
        json.dumps(
            {
                "total": 10,
                "passed_count": 9,
                "outcomes": {
                    "pass": 9,
                    "fail": 0,
                    "expected_fail": 1,
                    "blocked": 0,
                    "inconclusive": 0,
                },
            }
        )
    )

    scenario_rows = [
        {"scenario_id": "forbidden_tool_argument_attempt", "outcome": "pass"},
        {"scenario_id": "unauthorized_tool_use_attempt", "outcome": "pass"},
        {"scenario_id": "policy_bypass_attempt", "outcome": "pass"},
        {"scenario_id": "allowed_tool_execution_path", "outcome": "pass"},
        {"scenario_id": "confirmation_required_tool_flow", "outcome": "pass"},
        {"scenario_id": "fallback_to_rag_verification", "outcome": "pass"},
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
    assert _scorecard_status(report, "policy_artifacts") == "pass"
    assert _scorecard_status(report, "retrieval_boundary") == "pass"
    assert _scorecard_status(report, "tool_router_enforcement") == "pass"
    assert _scorecard_status(report, "telemetry_evidence") == "pass"
    assert _scorecard_status(report, "replay_evidence") == "pass"
    assert _scorecard_status(report, "eval_suite_evidence") == "pass"
    assert _scorecard_status(report, "fallback_readiness") == "pass"
    assert _scorecard_status(report, "kill_switch_readiness") == "pass"


def test_missing_policy_artifact_is_missing_and_blocking(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "policies/bundles/default/policy.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "policy_artifacts") == MISSING_CHECK_STATUS
    assert any("policy artifact missing" in blocker for blocker in report.blockers)


def test_missing_telemetry_evidence_is_missing_and_residual(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/audit.jsonl").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert _scorecard_status(report, "telemetry_evidence") == MISSING_CHECK_STATUS
    assert any("telemetry evidence missing" in risk for risk in report.residual_risks)


def test_missing_eval_suite_evidence_blocks_no_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "eval_suite_evidence") == MISSING_CHECK_STATUS
    assert any("eval suite evidence missing" in blocker for blocker in report.blockers)


def test_missing_eval_jsonl_tool_router_evidence_blocks_no_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "tool_router_enforcement") == MISSING_CHECK_STATUS
    assert any("tool-router enforcement evidence missing" in blocker for blocker in report.blockers)


def test_eval_threshold_failure_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text(
        json.dumps(
            {
                "total": 10,
                "passed_count": 6,
                "outcomes": {"pass": 6, "fail": 4, "expected_fail": 0, "blocked": 0, "inconclusive": 0},
            }
        )
    )

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert _scorecard_status(report, "eval_suite_evidence") == "fail"
    assert any("eval suite evidence failed" in blocker for blocker in report.blockers)


def test_fallback_readiness_failure_is_residual_risk(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    fallback_eval = tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.jsonl"
    rows = [json.loads(line) for line in fallback_eval.read_text().splitlines() if line.strip()]
    for row in rows:
        if row.get("scenario_id") == "fallback_to_rag_verification":
            row["outcome"] = "fail"
    fallback_eval.write_text("\n".join(json.dumps(item) for item in rows))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert _scorecard_status(report, "fallback_readiness") == "fail"
    assert any("fallback readiness not satisfied" in risk for risk in report.residual_risks)


def test_missing_replay_evidence_is_residual_risk(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/replay-20260101T000000Z.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert _scorecard_status(report, "replay_evidence") == MISSING_CHECK_STATUS
    assert any("replay evidence missing" in risk for risk in report.residual_risks)


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
    assert any("tool-router enforcement evidence" in blocker for blocker in report.blockers)


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
    assert any("kill switch enabled" in blocker for blocker in report.blockers)


def test_scorecard_contains_expected_categories(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)

    gate = SecurityLaunchGate(repo_root=tmp_path, config=LaunchGateConfig())
    report = gate.evaluate()

    categories = {item.category_name for item in report.scorecard}
    assert categories == {
        "policy_artifacts",
        "retrieval_boundary",
        "tool_router_enforcement",
        "telemetry_evidence",
        "replay_evidence",
        "eval_suite_evidence",
        "fallback_readiness",
        "kill_switch_readiness",
    }


def test_missing_mandatory_controls_yields_no_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "tools/router.py").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("missing mandatory controls" in blocker for blocker in report.blockers)
