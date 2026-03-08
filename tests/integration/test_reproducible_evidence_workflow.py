"""Integration checks for reproducible evidence regeneration workflow."""

from pathlib import Path
import subprocess


def test_regenerate_core_evidence_script_exists_and_is_executable() -> None:
    script = Path("scripts/regenerate_core_evidence.sh")
    assert script.is_file()
    assert script.stat().st_mode & 0o111


def test_regenerate_core_evidence_dry_run_includes_required_steps() -> None:
    result = subprocess.run(
        ["bash", "scripts/regenerate_core_evidence.sh", "--dry-run"],
        check=True,
        capture_output=True,
        text=True,
    )

    output = result.stdout
    assert "python -m evals.runner" in output
    assert "verification.runner" in output
    assert "python -m launch_gate.engine" in output
    assert "security guarantees verification did not pass" in output
    assert "launch gate status is not go" in output
    assert "./scripts/check_evidence_pack.sh" in output
