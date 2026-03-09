"""Incident-readiness evidence fixtures tied to audit + replay fields."""

from identity.models import ActorType, DelegationGrant, build_identity
from telemetry.audit import DENY_EVENT, ERROR_EVENT, POLICY_DECISION_EVENT, REQUEST_END_EVENT, REQUEST_START_EVENT
from telemetry.audit.events import create_audit_event
from telemetry.audit.replay import build_replay_artifact


def _delegated_identity():
    return build_identity(
        actor_id="agent-child",
        actor_type=ActorType.DELEGATED_AGENT,
        tenant_id="tenant-a",
        session_id="sess-1",
        trust_level="medium",
        allowed_capabilities=("tools.invoke", "retrieval.search"),
        delegation_chain=(
            DelegationGrant(
                parent_actor_id="user-1",
                child_actor_id="agent-child",
                delegated_capabilities=("tools.invoke",),
                delegation_reason="subtask",
                issued_at="2026-01-01T00:00:00Z",
                expires_at="2099-01-01T00:00:00Z",
                scope_constraints={"tenant_id": "tenant-a"},
            ),
        ),
    )


def test_replay_supports_policy_bypass_and_identity_investigation_sequence() -> None:
    identity = _delegated_identity()
    events = [
        create_audit_event(
            trace_id="trace-incident-1",
            request_id="req-incident-1",
            identity=identity,
            event_type=REQUEST_START_EVENT,
            payload={"channel": "chat"},
        ),
        create_audit_event(
            trace_id="trace-incident-1",
            request_id="req-incident-1",
            identity=identity,
            event_type=POLICY_DECISION_EVENT,
            payload={"action": "tools.invoke", "allow": False, "reason": "policy denied: forbidden field", "risk_tier": "medium"},
        ),
        create_audit_event(
            trace_id="trace-incident-1",
            request_id="req-incident-1",
            identity=identity,
            event_type=DENY_EVENT,
            payload={"stage": "tool.route", "reason": "policy denied: forbidden field"},
        ),
        create_audit_event(
            trace_id="trace-incident-1",
            request_id="req-incident-1",
            identity=identity,
            event_type=REQUEST_END_EVENT,
            payload={"status": "blocked"},
        ),
    ]

    artifact = build_replay_artifact(events)

    assert artifact.actor_id == "agent-child"
    assert artifact.tenant_id == "tenant-a"
    assert len(artifact.delegation_chain) == 1
    assert artifact.decision_summary["deny_events"][0]["stage"] == "tool.route"
    assert artifact.coverage["request_lifecycle_complete"] is True


def test_replay_captures_mcp_error_and_secret_redaction_indicator_fields() -> None:
    identity = _delegated_identity()
    events = [
        create_audit_event(
            trace_id="trace-incident-2",
            request_id="req-incident-2",
            identity=identity,
            event_type=ERROR_EVENT,
            payload={"stage": "mcp.gateway", "server_id": "support-mcp", "api_key": "super-secret"},
        )
    ]

    artifact = build_replay_artifact(events)
    payload = artifact.timeline[0]["payload"]

    assert payload["api_key"] == "[redacted]"
    assert payload["server_id"] == "support-mcp"
