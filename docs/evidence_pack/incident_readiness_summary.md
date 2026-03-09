# Incident Readiness Evidence Summary

## What is now checked
- Incident playbook document exists: `docs/incident_response_playbooks.md`.
- Incident evidence summary exists: `docs/evidence_pack/incident_readiness_summary.md`.
- Launch gate verifies both files and confirms all required incident class sections are present.

## Incident classes mapped to telemetry evidence
1. policy bypass attempt
2. retrieval boundary violation
3. suspicious tool execution
4. identity mismatch
5. delegation abuse
6. MCP endpoint anomaly
7. secret leakage indicator

## Core telemetry fields used during incident reconstruction
- Event envelope: `event_type`, `request_id`, `trace_id`, `created_at`.
- Actor context: `actor_id`, `actor_type`, `tenant_id`, `session_id`, `delegation_chain`, `auth_context`, `trust_level`.
- Decision payloads: policy/retrieval/tool decision reasons and constraints outcomes.
- Denials/errors: `deny.event`, `error.event`, `mcp.protocol_error` payload details.
- Replay summaries: `decision_summary`, `coverage`, `timeline`.

## Explicit evidence gaps
- Tamper-evident signatures for audit/replay artifacts are not implemented.
- Automated paging/incident ticket integrations are not implemented.
