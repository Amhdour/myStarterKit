"""Audit event helpers."""

from uuid import uuid4

from identity.models import ActorIdentity
from telemetry.audit.contracts import AuditEvent


def generate_trace_id() -> str:
    return f"trace-{uuid4()}"


def create_audit_event(
    *,
    trace_id: str,
    request_id: str,
    event_type: str,
    payload: dict,
    identity: ActorIdentity | None = None,
    actor_id: str | None = None,
    tenant_id: str | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=f"evt-{uuid4()}",
        trace_id=trace_id,
        request_id=request_id,
        identity=identity,
        actor_id=actor_id,
        tenant_id=tenant_id,
        event_type=event_type,
        event_payload=payload,
    )
