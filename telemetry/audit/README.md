# telemetry/audit/

Structured audit telemetry, JSONL sinks, and replay artifact tooling.

Phase 6 adds:
- Trace-aware structured event contracts for investigation and trust.
- Event types for request lifecycle, policy/retrieval/tool decisions, fallback, denies, confirmations, and errors.
- JSONL output sink for launch-gate/evidence-pack consumption.
- Replay artifact generation to reconstruct execution timelines.
- Replay decision-summary projection (request lifecycle, policy/retrieval/tool/deny/fallback slices) for fast machine-readable reconstruction.
- Replay artifact event-type coverage/count metadata for machine-checkable completeness checks.
- Replay coverage flags for investigation readiness:
  - `request_lifecycle_complete`
  - `decision_replay_core_complete`

Safety notes:
- Avoid logging raw sensitive inputs; prefer decision metadata and counts.
- Replay artifact payload projection redacts common sensitive fields (e.g., `password`, `raw_password`, `token`, `ssn`).
- Denied/blocked actions and fallback transitions are logged explicitly for incident review.
