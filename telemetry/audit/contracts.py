"""Audit contracts for structured telemetry and replay artifacts."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Protocol

from identity.models import ActorIdentity, ActorType, build_identity

REQUEST_START_EVENT = "request.start"
REQUEST_END_EVENT = "request.end"
RETRIEVAL_DECISION_EVENT = "retrieval.decision"
TOOL_DECISION_EVENT = "tool.decision"
TOOL_EXECUTION_ATTEMPT_EVENT = "tool.execution_attempt"
POLICY_DECISION_EVENT = "policy.decision"
CONFIRMATION_REQUIRED_EVENT = "confirmation.required"
DENY_EVENT = "deny.event"
FALLBACK_EVENT = "fallback.event"
ERROR_EVENT = "error.event"


@dataclass(frozen=True, init=False)
class AuditEvent:
    event_id: str
    trace_id: str
    request_id: str
    identity: ActorIdentity
    event_type: str
    event_payload: Mapping[str, object]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __init__(
        self,
        *,
        event_id: str,
        trace_id: str,
        request_id: str,
        event_type: str,
        event_payload: Mapping[str, object],
        identity: ActorIdentity | None = None,
        actor_id: str | None = None,
        tenant_id: str | None = None,
        session_id: str = "audit-session",
        created_at: str | None = None,
    ) -> None:
        if identity is None:
            if not actor_id or not tenant_id:
                raise ValueError("identity is required")
            identity = build_identity(
                actor_id=actor_id,
                actor_type=ActorType.ASSISTANT_RUNTIME,
                tenant_id=tenant_id,
                session_id=session_id,
                trust_level="medium",
                allowed_capabilities=("audit.emit",),
            )
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "trace_id", trace_id)
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "event_payload", event_payload)
        object.__setattr__(self, "created_at", created_at or datetime.now(timezone.utc).isoformat())

    @property
    def actor_id(self) -> str:
        return self.identity.actor_id

    @property
    def tenant_id(self) -> str:
        return self.identity.tenant_id


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...
