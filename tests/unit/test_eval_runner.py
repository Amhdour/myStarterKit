"""Tests for security eval runner and scenario execution."""

import json

from evals.contracts import BLOCKED_OUTCOME, EXPECTED_FAIL_OUTCOME, PASS_OUTCOME
from evals.runner import SecurityEvalRunner
from evals.scenario import load_scenarios


def test_scenario_file_loads_with_expected_baseline_entries() -> None:
    scenarios = load_scenarios("evals/scenarios/security_baseline.json")

    assert len(scenarios) == 10
    ids = {scenario.scenario_id for scenario in scenarios}
    assert "prompt_injection_direct" in ids
    assert "auditability_verification" in ids


def test_router_only_scenarios_are_explicitly_labeled_with_reason() -> None:
    scenarios = load_scenarios("evals/scenarios/security_baseline.json")

    router_only = [scenario for scenario in scenarios if scenario.execution_path == "router_only"]
    assert router_only
    assert all(scenario.limitation_reason for scenario in router_only)


def test_eval_runner_writes_outcome_rich_outputs(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-regression")

    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    assert len(result.scenario_results) == 10
    jsonl_files = list(tmp_path.glob("security-regression-*.jsonl"))
    summary_files = list(tmp_path.glob("security-regression-*.summary.json"))
    assert len(jsonl_files) == 1
    assert len(summary_files) == 1

    lines = jsonl_files[0].read_text().strip().splitlines()
    assert len(lines) == 10
    first_record = json.loads(lines[0])
    assert "scenario_id" in first_record
    assert "severity" in first_record
    assert "outcome" in first_record

    summary = json.loads(summary_files[0].read_text())
    assert summary["total"] == 10
    assert "outcomes" in summary
    assert set(summary["outcomes"].keys()) == {"pass", "fail", "expected_fail", "blocked", "inconclusive"}


def test_security_scenarios_hit_runtime_paths_and_keep_failures_visible(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-runtime-paths")
    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    by_id = {item.scenario_id: item for item in result.scenario_results}
    assert by_id["cross_tenant_retrieval_attempt"].outcome == BLOCKED_OUTCOME
    assert by_id["forbidden_tool_argument_attempt"].outcome == PASS_OUTCOME
    assert by_id["unauthorized_tool_use_attempt"].outcome == PASS_OUTCOME
    assert by_id["fallback_to_rag_verification"].outcome == PASS_OUTCOME
    assert by_id["auditability_verification"].outcome == PASS_OUTCOME
    assert by_id["retrieval_poisoning_attempt"].outcome == EXPECTED_FAIL_OUTCOME
