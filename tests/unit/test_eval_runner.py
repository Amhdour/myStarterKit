"""Tests for security eval runner and scenario execution."""

import json

from evals.contracts import BLOCKED_OUTCOME, EXPECTED_FAIL_OUTCOME, FAIL_OUTCOME, PASS_OUTCOME
from evals.runner import SecurityEvalRunner
from evals.scenario import load_scenarios


def test_scenario_file_loads_with_expected_baseline_entries() -> None:
    scenarios = load_scenarios("evals/scenarios/security_baseline.json")

    assert len(scenarios) == 24
    ids = {scenario.scenario_id for scenario in scenarios}
    assert "prompt_injection_direct" in ids
    assert "auditability_verification" in ids
    assert "prompt_injection_tool_escalation_attempt" in ids
    assert "policy_bypass_tenant_spoofing_request" in ids
    assert "allowed_tool_execution_path" in ids
    assert "confirmation_required_tool_flow" in ids
    assert "adversarial_forged_actor_identity" in ids
    assert "adversarial_capability_token_replay" in ids
    assert "adversarial_policy_drift_unsafe_allow" in ids


def test_router_only_scenarios_are_explicitly_labeled_with_reason() -> None:
    scenarios = load_scenarios("evals/scenarios/security_baseline.json")

    router_only = [scenario for scenario in scenarios if scenario.execution_path == "router_only"]
    assert router_only
    assert all(scenario.limitation_reason for scenario in router_only)


def test_eval_runner_writes_outcome_rich_outputs(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-regression")

    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    assert len(result.scenario_results) == 24
    jsonl_files = list(tmp_path.glob("security-regression-*.jsonl"))
    summary_files = list(tmp_path.glob("security-regression-*.summary.json"))
    assert len(jsonl_files) == 1
    assert len(summary_files) == 1

    lines = jsonl_files[0].read_text().strip().splitlines()
    assert len(lines) == 24
    first_record = json.loads(lines[0])
    assert "scenario_id" in first_record
    assert "severity" in first_record
    assert "outcome" in first_record

    summary = json.loads(summary_files[0].read_text())
    assert summary["total"] == 24
    assert "outcomes" in summary
    assert set(summary["outcomes"].keys()) == {"pass", "fail", "expected_fail", "blocked", "inconclusive"}


def test_eval_runner_writes_replay_artifacts_for_request_flows(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-replay")
    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    replay_dir = tmp_path.parent / "replay"
    replay_files = sorted(replay_dir.glob("security-replay-*.replay.json"))
    assert replay_files

    by_id = {item.scenario_id: item for item in result.scenario_results}
    auditability = by_id["auditability_verification"]
    assert "replay_artifact_path" in auditability.evidence
    assert "replay_decision_summary" in auditability.evidence
    assert auditability.evidence["replay_decision_summary"]["request_lifecycle"]["start_seen"] is True
    assert auditability.evidence["replay_required_events_complete"] is True

    all_event_types: set[str] = set()
    for path in replay_files:
        parsed = json.loads(path.read_text())
        assert parsed["replay_version"] == "1"
        assert "event_type_counts" in parsed
        all_event_types.update(parsed["event_type_counts"].keys())

    assert "request.start" in all_event_types
    assert "request.end" in all_event_types
    assert "policy.decision" in all_event_types
    assert "retrieval.decision" in all_event_types
    assert "tool.decision" in all_event_types
    assert "deny.event" in all_event_types
    assert "fallback.event" in all_event_types


def test_security_scenarios_hit_runtime_paths_and_keep_failures_visible(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-runtime-paths")
    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    by_id = {item.scenario_id: item for item in result.scenario_results}
    assert by_id["cross_tenant_retrieval_attempt"].outcome == BLOCKED_OUTCOME
    assert by_id["forbidden_tool_argument_attempt"].outcome == PASS_OUTCOME
    assert by_id["unauthorized_tool_use_attempt"].outcome == PASS_OUTCOME
    assert by_id["fallback_to_rag_verification"].outcome == PASS_OUTCOME
    assert by_id["auditability_verification"].outcome == PASS_OUTCOME
    assert by_id["prompt_injection_tool_escalation_attempt"].outcome == FAIL_OUTCOME
    assert by_id["policy_bypass_tenant_spoofing_request"].outcome == BLOCKED_OUTCOME
    assert by_id["retrieval_poisoning_attempt"].outcome == EXPECTED_FAIL_OUTCOME
    assert by_id["allowed_tool_execution_path"].outcome == PASS_OUTCOME
    assert by_id["confirmation_required_tool_flow"].outcome == PASS_OUTCOME
    assert by_id["adversarial_prompt_injection_tool_bypass"].outcome == PASS_OUTCOME
    assert by_id["adversarial_mcp_response_manipulation"].outcome == PASS_OUTCOME
    assert by_id["adversarial_mcp_oversized_payload"].outcome == PASS_OUTCOME
    assert by_id["adversarial_capability_token_replay"].outcome == PASS_OUTCOME
    assert by_id["adversarial_unsafe_high_risk_tool_request"].outcome == PASS_OUTCOME
    assert by_id["adversarial_forged_actor_identity"].outcome == PASS_OUTCOME
    assert by_id["adversarial_delegation_scope_escalation"].outcome == PASS_OUTCOME
    assert by_id["adversarial_secret_leakage_attempt"].outcome == PASS_OUTCOME
    assert by_id["adversarial_policy_drift_unsafe_allow"].outcome == EXPECTED_FAIL_OUTCOME


def test_eval_outputs_include_decision_logs_and_concise_summaries(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-evidence")
    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    by_id = {item.scenario_id: item for item in result.scenario_results}
    prompt = by_id["prompt_injection_direct"]
    assert "decision_log" in prompt.evidence
    assert "policy_decisions" in prompt.evidence["decision_log"]
    assert "scenario_summary" in prompt.evidence

    tool_router_only = by_id["policy_bypass_attempt"]
    assert "decision_log" in tool_router_only.evidence
    assert "tool_decision" in tool_router_only.evidence["decision_log"]


def test_eval_outputs_include_runtime_realism_evidence_and_component_coverage(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-realism")
    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    by_id = {item.scenario_id: item for item in result.scenario_results}
    full_runtime = by_id["prompt_injection_direct"]
    router_only = by_id["forbidden_tool_argument_attempt"]

    assert "runtime_components" in full_runtime.evidence
    assert "simulated_dependencies" in full_runtime.evidence
    assert "realism_notes" in full_runtime.evidence
    assert full_runtime.evidence["runtime_components_exercised"]["orchestrator"] is True
    assert full_runtime.evidence["runtime_components_exercised"]["policy"] is True
    assert full_runtime.evidence["runtime_components_exercised"]["retrieval"] is True
    assert full_runtime.evidence["runtime_components_exercised"]["audit_logging"] is True

    assert router_only.evidence["runtime_components_exercised"]["orchestrator"] is False
    assert router_only.evidence["runtime_components_exercised"]["policy"] is True
    assert router_only.evidence["runtime_components_exercised"]["tool_routing"] is True


def test_tool_execution_scenarios_report_execution_state_and_results(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-tool-exec")
    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    by_id = {item.scenario_id: item for item in result.scenario_results}
    allowed = by_id["allowed_tool_execution_path"]
    denied = by_id["forbidden_tool_argument_attempt"]
    confirmation = by_id["confirmation_required_tool_flow"]
    high_risk = by_id["adversarial_unsafe_high_risk_tool_request"]

    assert allowed.evidence["execution_performed"] is True
    assert allowed.evidence["execution_result"]["status"] == "ok"
    assert denied.evidence["execution_performed"] is False
    assert confirmation.evidence["execution_performed"] is False
    assert confirmation.evidence["tool_decision_status"] == "require_confirmation"
    assert high_risk.evidence["execution_performed"] is False
    assert high_risk.evidence["tool_decision_status"] == "deny"


def test_eval_runner_supports_fixed_stamp_for_reproducible_artifact_names(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-deterministic")

    runner.run(
        "evals/scenarios/security_baseline.json",
        output_dir=tmp_path,
        stamp="20260101T000000Z",
    )

    assert (tmp_path / "security-deterministic-20260101T000000Z.jsonl").is_file()
    assert (tmp_path / "security-deterministic-20260101T000000Z.summary.json").is_file()
    replay_dir = tmp_path.parent / "replay"
    assert list(replay_dir.glob("security-deterministic-20260101T000000Z-*.replay.json"))
