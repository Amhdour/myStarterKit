"""Structured request/response and context models for support-agent flow."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence

from identity.models import ActorIdentity, ActorType, build_identity
from retrieval.contracts import RetrievalDocument
from tools.contracts import ToolDecision


@dataclass(frozen=True, init=False)
class SessionContext:
    """Session-level metadata carried across requests."""

    identity: ActorIdentity
    channel: str = "support"
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __init__(
        self,
        *,
        identity: ActorIdentity | None = None,
        session_id: str | None = None,
        actor_id: str | None = None,
        tenant_id: str | None = None,
        channel: str = "support",
        attributes: Mapping[str, str] | None = None,
    ) -> None:
        if identity is None:
            if not session_id or not actor_id or not tenant_id:
                raise ValueError("identity is required")
            identity = build_identity(
                actor_id=actor_id,
                actor_type=ActorType.END_USER,
                tenant_id=tenant_id,
                session_id=session_id,
                trust_level="low",
                allowed_capabilities=("retrieval.search", "model.generate", "tools.route", "tools.invoke"),
            )
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "channel", channel)
        object.__setattr__(self, "attributes", attributes or {})

    @property
    def session_id(self) -> str:
        return self.identity.session_id

    @property
    def actor_id(self) -> str:
        return self.identity.actor_id

    @property
    def tenant_id(self) -> str:
        return self.identity.tenant_id


@dataclass(frozen=True)
class RequestContext:
    trace_id: str
    request_id: str
    identity: ActorIdentity
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def session_id(self) -> str:
        return self.identity.session_id

    @property
    def actor_id(self) -> str:
        return self.identity.actor_id

    @property
    def tenant_id(self) -> str:
        return self.identity.tenant_id


@dataclass(frozen=True)
class SupportAgentRequest:
    request_id: str
    user_text: str
    session: SessionContext


@dataclass(frozen=True)
class OrchestrationTrace:
    policy_checks: Sequence[str]
    retrieved_document_ids: Sequence[str]
    tool_decisions: Sequence[str]


@dataclass(frozen=True)
class SupportAgentResponse:
    request_id: str
    session_id: str
    answer_text: str
    status: str
    context: RequestContext
    retrieved_documents: Sequence[RetrievalDocument] = field(default_factory=tuple)
    tool_decisions: Sequence[ToolDecision] = field(default_factory=tuple)
    trace: OrchestrationTrace = field(default_factory=lambda: OrchestrationTrace(tuple(), tuple(), tuple()))
