#!/usr/bin/env bash
set -euo pipefail

STAMP="${EVIDENCE_STAMP:-20260101T000000Z}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

run_cmd() {
  local cmd="$1"
  echo "+ $cmd"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    eval "$cmd"
  fi
}

run_cmd "mkdir -p artifacts/logs/evals artifacts/logs/replay artifacts/logs/verification artifacts/logs/launch_gate"

run_cmd "rm -f artifacts/logs/evals/security-redteam-*.jsonl artifacts/logs/evals/security-redteam-*.summary.json"
run_cmd "rm -f artifacts/logs/replay/security-redteam-*.replay.json"
run_cmd "rm -f artifacts/logs/verification/security_guarantees.summary.json artifacts/logs/verification/security_guarantees.summary.md"
run_cmd "rm -f artifacts/logs/launch_gate/security-readiness-*.json"

run_cmd "python -m evals.runner --scenario-file evals/scenarios/security_baseline.json --output-dir artifacts/logs/evals --stamp ${STAMP}"

run_cmd "python - <<'PY'
from pathlib import Path
from verification.runner import (
    run_security_guarantees_verification,
    write_security_guarantees_markdown_summary,
    write_security_guarantees_report,
)

repo_root = Path('.')
report = run_security_guarantees_verification(repo_root, require_evidence_presence=True)
write_security_guarantees_report(report, repo_root / 'artifacts/logs/verification/security_guarantees.summary.json')
write_security_guarantees_markdown_summary(report, repo_root / 'artifacts/logs/verification/security_guarantees.summary.md')
print(report['status'])
if str(report.get('status')) != 'pass':
    raise SystemExit('security guarantees verification did not pass')
PY"

run_cmd "python -m launch_gate.engine > artifacts/logs/launch_gate/security-readiness-${STAMP}.json"

run_cmd "python - <<'PY'
import json
from pathlib import Path

path = Path('artifacts/logs/launch_gate/security-readiness-${STAMP}.json')
payload = json.loads(path.read_text())
status = str(payload.get('status', 'unknown'))
print(status)
if status != 'go':
    raise SystemExit(f'launch gate status is not go: {status}')
PY"

run_cmd "./scripts/check_evidence_pack.sh"

if [[ "$DRY_RUN" -eq 0 ]]; then
  echo "Core evidence regenerated."
  echo "- artifacts/logs/evals/security-redteam-${STAMP}.jsonl"
  echo "- artifacts/logs/evals/security-redteam-${STAMP}.summary.json"
  echo "- artifacts/logs/replay/security-redteam-${STAMP}-*.replay.json"
  echo "- artifacts/logs/verification/security_guarantees.summary.json"
  echo "- artifacts/logs/verification/security_guarantees.summary.md"
  echo "- artifacts/logs/launch_gate/security-readiness-${STAMP}.json"
fi
