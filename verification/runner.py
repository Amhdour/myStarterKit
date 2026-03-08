"""Security guarantees verification runner.

Builds a machine-readable report mapping invariants to code/test/evidence coverage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

MANIFEST_PATH = "verification/security_guarantees_manifest.json"


@dataclass(frozen=True)
class InvariantVerificationResult:
    invariant_id: str
    code_mapped: bool
    tests_mapped: bool
    evidence_mapped: bool
    evidence_present: bool
    status: str
    details: str
    missing_code_paths: tuple[str, ...]
    missing_test_paths: tuple[str, ...]
    missing_evidence_globs: tuple[str, ...]
    matched_evidence_paths: tuple[str, ...]


def run_security_guarantees_verification(
    repo_root: Path,
    *,
    manifest_path: str = MANIFEST_PATH,
    require_evidence_presence: bool = False,
) -> dict[str, object]:
    payload = json.loads((repo_root / manifest_path).read_text())
    invariants = payload.get("invariants", []) if isinstance(payload, dict) else []
    results: list[InvariantVerificationResult] = []

    seen_ids: set[str] = set()
    duplicate_ids: set[str] = set()
    if isinstance(invariants, list):
        for item in invariants:
            if not isinstance(item, dict):
                continue
            invariant_id = str(item.get("id", ""))
            if not invariant_id:
                continue
            if invariant_id in seen_ids:
                duplicate_ids.add(invariant_id)
            seen_ids.add(invariant_id)

    for item in invariants:
        invariant_id = str(item.get("id", ""))
        enforcement_locations = tuple(path for path in item.get("enforcement_locations", []) if isinstance(path, str))
        test_coverage = tuple(path for path in item.get("test_coverage", []) if isinstance(path, str))
        artifact_evidence = tuple(path for path in item.get("artifact_evidence", []) if isinstance(path, str))

        missing_code_paths = tuple(path for path in enforcement_locations if not (repo_root / path).is_file())
        missing_test_paths = tuple(path for path in test_coverage if not (repo_root / path).is_file())

        missing_evidence_globs: list[str] = []
        matched_evidence_paths: list[str] = []
        evidence_present = True
        for pattern in artifact_evidence:
            matches = sorted(str(path) for path in repo_root.glob(pattern))
            if not matches:
                evidence_present = False
                missing_evidence_globs.append(pattern)
            else:
                matched_evidence_paths.extend(matches)

        code_mapped = bool(enforcement_locations) and len(missing_code_paths) == 0
        tests_mapped = bool(test_coverage) and len(missing_test_paths) == 0
        evidence_mapped = bool(artifact_evidence)

        if invariant_id in duplicate_ids:
            status = "fail"
            details = "duplicate invariant id in manifest"
        elif not code_mapped:
            status = "fail"
            details = "missing enforcement locations"
        elif not tests_mapped:
            status = "fail"
            details = "missing test coverage paths"
        elif not evidence_mapped:
            status = "fail"
            details = "missing artifact evidence mapping"
        elif require_evidence_presence and not evidence_present:
            status = "expected_fail"
            details = "artifact evidence not present in current environment"
        else:
            status = "pass"
            details = "invariant mapping complete"

        results.append(
            InvariantVerificationResult(
                invariant_id=invariant_id,
                code_mapped=code_mapped,
                tests_mapped=tests_mapped,
                evidence_mapped=evidence_mapped,
                evidence_present=evidence_present,
                status=status,
                details=details,
                missing_code_paths=missing_code_paths,
                missing_test_paths=missing_test_paths,
                missing_evidence_globs=tuple(missing_evidence_globs),
                matched_evidence_paths=tuple(matched_evidence_paths),
            )
        )

    outcome_counts = {
        "pass": sum(1 for item in results if item.status == "pass"),
        "fail": sum(1 for item in results if item.status == "fail"),
        "expected_fail": sum(1 for item in results if item.status == "expected_fail"),
    }

    return {
        "suite": "security_guarantees_verification",
        "status": "pass" if outcome_counts["fail"] == 0 else "fail",
        "require_evidence_presence": require_evidence_presence,
        "manifest_path": manifest_path,
        "invariant_count": len(results),
        "duplicate_invariant_ids": sorted(duplicate_ids),
        "outcome_counts": outcome_counts,
        "results": [
            {
                "invariant_id": item.invariant_id,
                "status": item.status,
                "details": item.details,
                "code_mapped": item.code_mapped,
                "tests_mapped": item.tests_mapped,
                "evidence_mapped": item.evidence_mapped,
                "evidence_present": item.evidence_present,
                "missing_code_paths": list(item.missing_code_paths),
                "missing_test_paths": list(item.missing_test_paths),
                "missing_evidence_globs": list(item.missing_evidence_globs),
                "matched_evidence_paths": list(item.matched_evidence_paths),
            }
            for item in results
        ],
    }


def write_security_guarantees_report(report: dict[str, object], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True))


def write_security_guarantees_markdown_summary(report: dict[str, object], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Security Guarantees Verification Summary",
        "",
        f"- Suite: `{report.get('suite', '')}`",
        f"- Status: `{report.get('status', '')}`",
        f"- Invariants: `{report.get('invariant_count', 0)}`",
        f"- Outcomes: `{json.dumps(report.get('outcome_counts', {}), sort_keys=True)}`",
        "",
        "## Invariant Results",
        "",
        "| invariant_id | status | details | mapped evidence files |",
        "|---|---|---|---|",
    ]

    for item in report.get("results", []):
        if not isinstance(item, dict):
            continue
        evidence_paths = item.get("matched_evidence_paths", [])
        evidence_display = ", ".join(str(path) for path in evidence_paths[:3])
        if isinstance(evidence_paths, list) and len(evidence_paths) > 3:
            evidence_display += f", +{len(evidence_paths) - 3} more"
        lines.append(
            f"| {item.get('invariant_id', '')} | {item.get('status', '')} | {item.get('details', '')} | {evidence_display} |"
        )

    output_path.write_text("\n".join(lines) + "\n")


def main() -> None:
    repo_root = Path(".")
    report = run_security_guarantees_verification(repo_root, require_evidence_presence=False)
    out = repo_root / "artifacts/logs/verification/security_guarantees.summary.json"
    out_md = repo_root / "artifacts/logs/verification/security_guarantees.summary.md"
    write_security_guarantees_report(report, out)
    write_security_guarantees_markdown_summary(report, out_md)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
