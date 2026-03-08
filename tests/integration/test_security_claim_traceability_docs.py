"""Traceability checks for reviewer-facing security claim documentation."""

import json
from pathlib import Path


def test_release_relevant_invariant_ids_are_present_in_reviewer_docs() -> None:
    manifest = json.loads(Path("verification/security_guarantees_manifest.json").read_text())
    invariant_ids = [item["id"] for item in manifest.get("invariants", []) if isinstance(item, dict) and "id" in item]

    security_guarantees = Path("docs/security_guarantees.md").read_text()
    reviewer_guide = Path("docs/reviewer_guide.md").read_text()
    verification_doc = Path("docs/evidence_pack/security_guarantees_verification.md").read_text()

    for invariant_id in invariant_ids:
        assert invariant_id in security_guarantees, f"missing invariant id in docs/security_guarantees.md: {invariant_id}"
        assert invariant_id in reviewer_guide, f"missing invariant id in docs/reviewer_guide.md: {invariant_id}"
        assert invariant_id in verification_doc, (
            "missing invariant id in docs/evidence_pack/security_guarantees_verification.md: "
            f"{invariant_id}"
        )


def test_launch_gate_summary_mentions_guarantees_blocking_behavior() -> None:
    launch_summary = Path("docs/evidence_pack/launch_gate_summary.md").read_text()
    assert "security_guarantees_verification" in launch_summary
    assert "no_go" in launch_summary


def test_readme_and_reviewer_guide_include_quick_review_path_and_risk_visibility() -> None:
    readme = Path("README.md").read_text()
    reviewer_guide = Path("docs/reviewer_guide.md").read_text()
    security_guarantees = Path("docs/security_guarantees.md").read_text()

    assert "Review this repo in 5 minutes" in readme
    assert "./scripts/regenerate_core_evidence.sh" in readme
    assert "docs/evidence_pack/residual_risks.md" in readme

    assert "Review this repo in 5 minutes" in reviewer_guide
    assert "docs/evidence_pack/residual_risks.md" in reviewer_guide
    assert "docs/threat_model.md" in reviewer_guide

    assert "Residual risks (read with guarantees)" in security_guarantees
