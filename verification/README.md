# verification/

Focused security-guarantees verification assets.

- `security_guarantees_manifest.json`: invariant -> enforcement/tests/evidence mapping.
- `runner.py`: machine-readable verifier and summary artifact writer.

Run:

```bash
python -m verification.runner
```

Output artifact:
- `artifacts/logs/verification/security_guarantees.summary.json`
- `artifacts/logs/verification/security_guarantees.summary.md`
