#!/usr/bin/env bash
set -euo pipefail

python - <<'PY'
from pathlib import Path
from verification.drift import run_security_drift_checks

report = run_security_drift_checks(Path('.'))
print(report)
if report.get('status') != 'pass':
    raise SystemExit(1)
PY

echo "Security drift check passed."
