# Incident Response Playbooks (Runtime-Evidence Tied)

This document maps incident handling to concrete runtime evidence already emitted by this starter kit.

## Evidence Sources
- `artifacts/logs/audit.jsonl`
- `artifacts/logs/replay/*.replay.json`
- `artifacts/logs/evals/*.jsonl`
- `artifacts/logs/evals/*.summary.json`

---

## 1) policy bypass attempt

**Trigger conditions**
- `deny.event` with `event_payload.stage` in `{tools.route, tool.route, retrieval}` and reason containing policy denial semantics.
- Missing expected `policy.decision` before downstream decision events in replay timeline.

**Required evidence**
- `audit.jsonl`: `event_type`, `request_id`, `trace_id`, `actor_id`, `tenant_id`, `event_payload.reason`.
- Replay: `decision_summary.policy_decisions`, `decision_summary.deny_events`, `coverage.decision_replay_core_complete`.

**Immediate containment actions**
- Enable policy kill switch in policy bundle.
- Disable tool-enabled risk tiers pending triage.

**Triage steps**
- Confirm whether `policy.decision` exists for affected `request_id`.
- Compare denial reason and downstream stage for attempted bypass path.

**Investigation steps**
- Reconstruct timeline from replay by `trace_id`.
- Verify orchestrator path included `_evaluate_policy` for the action involved.

**Post-incident artifact checklist**
- Replay artifact for affected traces.
- Audit slice containing all events for `request_id`.
- Updated launch-gate report showing post-fix pass state.

---

## 2) retrieval boundary violation

**Trigger conditions**
- `deny.event` stage `retrieval` with reason `tenant mismatch`, `no allowlisted retrieval sources`, or invalid identity/delegation.
- Replay shows retrieval decisions with unexpected `allowed_source_ids` or zero-trust-domain mismatch behavior.

**Required evidence**
- `audit.jsonl`: retrieval and policy decisions with `tenant_id` and `actor_id`.
- Replay: `decision_summary.retrieval_decisions[].allowed_source_ids`.

**Immediate containment actions**
- Restrict `retrieval.allowed_tenants` and tenant source mapping in policy.
- Force fallback-to-RAG-only mode if retrieval controls are uncertain.

**Triage steps**
- Compare request tenant to source allowlist in policy snapshot.
- Verify source registry entries for the tenant.

**Investigation steps**
- Validate retrieval query identity and delegation chain consistency for the trace.
- Confirm boundary checks in secure retrieval service produced deny outcome.

**Post-incident artifact checklist**
- Policy bundle snapshot used at incident time.
- Replay artifact with retrieval decision sequence.
- Audit subset for all retrieval/policy events in trace.

---

## 3) suspicious tool execution

**Trigger conditions**
- `tool.execution_attempt` followed by `deny.event` with suspicious fields (`forbidden field`, `capability denied`, `high-risk tool missing explicit policy approval`).
- Repeated rate-limit denials for same `{tenant,actor,tool}` key.

**Required evidence**
- `audit.jsonl`: `tool.execution_attempt`, `tool.decision`, `deny.event` reason fields.
- Replay: `decision_summary.tool_decisions` and `deny_events`.

**Immediate containment actions**
- Remove target tool from `tools.allowed_tools`.
- Revoke capability issuance path by denying `tools.issue_capability` via policy updates.

**Triage steps**
- Validate tool is allowlisted and invocation action expected.
- Check capability token error details in deny events.

**Investigation steps**
- Correlate tool attempts by actor/session for burst patterns.
- Verify high-risk isolation metadata and approval controls for affected tool.

**Post-incident artifact checklist**
- Tool decision and deny event sequence for each affected trace.
- Effective policy constraints at time of execution.

---

## 4) identity mismatch

**Trigger conditions**
- Denials with reason `invalid identity` or `tenant mismatch` at policy, retrieval, or tool boundaries.

**Required evidence**
- `audit.jsonl`: `actor_id`, `actor_type`, `tenant_id`, `session_id`, `auth_context`, `trust_level`.
- Replay: top-level `actor_id`, `tenant_id`, `delegation_chain`.

**Immediate containment actions**
- Deny all requests from impacted actor/session until identity source is verified.

**Triage steps**
- Validate identity shape and required attributes against expected actor type.
- Compare tenant in request context vs runtime identity.

**Investigation steps**
- Inspect identity builder/parsing input for malformed/forged claims.
- Validate no legacy fallback caller path was used in boundary action.

**Post-incident artifact checklist**
- Raw audit rows for impacted request IDs.
- Replay reconstruction proving actor/tenant chain.

---

## 5) delegation abuse

**Trigger conditions**
- Denial reasons including `invalid delegation`, `scope inflation`, `expired delegation`, chain continuity failures.

**Required evidence**
- `audit.jsonl`: full `delegation_chain` per event.
- Replay: top-level `delegation_chain` plus deny reasons.

**Immediate containment actions**
- Disable delegated-agent execution for affected tenant.
- Shorten delegation TTL policy until issue resolved.

**Triage steps**
- Check parent/child continuity across delegation chain.
- Validate grant expiry and scope constraints for action.

**Investigation steps**
- Re-run delegation verification helpers on captured identity objects.
- Compare delegated capabilities against parent capabilities per hop.

**Post-incident artifact checklist**
- Delegation chain evidence in audit and replay.
- Verification output listing chain failures.

---

## 6) MCP endpoint anomaly

**Trigger conditions**
- `mcp.protocol_error`, `mcp.security` anomalies, or deny reasons `server is not allowlisted`, `untrusted server denied`, schema invalid, size-limit exceeded.

**Required evidence**
- `audit.jsonl`: MCP event payload including `server_id`, `endpoint`, `capability`, `origin`.
- Replay (if same trace): deny/failure progression around MCP calls.

**Immediate containment actions**
- Remove server profile from MCP allowlist.
- Set trust label to untrusted/deny in MCP profile.

**Triage steps**
- Confirm endpoint, trust label, and capability allowlist in profile.
- Validate request/response size and schema failure reason.

**Investigation steps**
- Inspect transport call failures and retry exhaustion patterns.
- Verify tenant boundary match between invocation and server profile.

**Post-incident artifact checklist**
- MCP-related audit rows by `server_id` and `trace_id`.
- Profile snapshot and policy state used during event window.

---

## 7) secret leakage indicator

**Trigger conditions**
- Any audit/replay field containing non-redacted secret-like key/value patterns (`api_key`, `token`, `raw_password`, `secret`, `ssn`) where value is not redacted marker.

**Required evidence**
- `audit.jsonl`: redacted event payload and auth context.
- Replay timeline payloads (sanitized).

**Immediate containment actions**
- Rotate potentially exposed credentials.
- Pause artifact export/sharing until redaction verification is complete.

**Triage steps**
- Confirm leakage occurred in artifact vs upstream system.
- Identify event type and payload field path where leak appeared.

**Investigation steps**
- Validate redaction utility coverage for leaked field pattern.
- Add/expand tests for the missed pattern and regenerate artifacts.

**Post-incident artifact checklist**
- Before/after artifact diff proving redaction fix.
- Rotation record for impacted secrets.

---

## Evidence insufficiency notes
- No cryptographic integrity signatures on audit/replay artifacts; tamper-evidence is deferred.
- No automated incident ticketing/escalation pipeline yet; this remains operator-runbook driven.
