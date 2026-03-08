"""Tests for the focused security guarantees verification runner."""

import json
from pathlib import Path

from verification.runner import run_security_guarantees_verification, write_security_guarantees_report


EXPECTED_INVARIANTS = {
    "tool_router_cannot_be_bypassed",
    "policy_governs_runtime_behavior",
    "retrieval_enforces_boundaries",
    "evals_hit_real_flows",
    "launch_gate_checks_real_evidence",
    "telemetry_supports_replay",
}


def test_runner_reports_all_invariants_with_mapping_pass_status() -> None:
    report = run_security_guarantees_verification(Path("."), require_evidence_presence=False)

    assert report["suite"] == "security_guarantees_verification"
    assert report["status"] == "pass"
    assert report["outcome_counts"]["fail"] == 0

    ids = {item["invariant_id"] for item in report["results"]}
    assert ids == EXPECTED_INVARIANTS
    assert all(item["status"] == "pass" for item in report["results"])


def test_runner_marks_missing_evidence_as_expected_fail_when_required(tmp_path) -> None:
    repo = tmp_path
    (repo / "verification").mkdir(parents=True, exist_ok=True)
    (repo / "app").mkdir(parents=True, exist_ok=True)
    (repo / "tests").mkdir(parents=True, exist_ok=True)

    (repo / "app/enforcer.py").write_text("# enforcer")
    (repo / "tests/test_enforcer.py").write_text("# test")
    (repo / "verification/mini_manifest.json").write_text(
        json.dumps(
            {
                "invariants": [
                    {
                        "id": "mini",
                        "enforcement_locations": ["app/enforcer.py"],
                        "test_coverage": ["tests/test_enforcer.py"],
                        "artifact_evidence": ["artifacts/logs/evals/*.jsonl"],
                    }
                ]
            }
        )
    )

    report = run_security_guarantees_verification(
        repo,
        manifest_path="verification/mini_manifest.json",
        require_evidence_presence=True,
    )

    assert report["status"] == "pass"
    assert report["outcome_counts"]["expected_fail"] == 1
    assert report["results"][0]["status"] == "expected_fail"
    assert report["results"][0]["missing_evidence_globs"] == ["artifacts/logs/evals/*.jsonl"]


def test_runner_output_can_be_written_as_machine_readable_artifact(tmp_path) -> None:
    report = run_security_guarantees_verification(Path("."), require_evidence_presence=False)
    output = tmp_path / "artifacts/logs/verification/security_guarantees.summary.json"

    write_security_guarantees_report(report, output)

    assert output.is_file()
    parsed = json.loads(output.read_text())
    assert parsed["suite"] == "security_guarantees_verification"
    assert isinstance(parsed["results"], list)
