"""Tool contracts for mediated, policy-ready tool routing."""

from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol, Sequence

from identity.models import ActorIdentity, ActorType, build_identity
from tools.isolation import ToolRiskClass

ALLOWED_DECISION = "allow"
DENY_DECISION = "deny"
REQUIRE_CONFIRMATION_DECISION = "require_confirmation"


class DirectToolExecutionDeniedError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    description: str
    allowed: bool
    confirmation_required: bool = False
    forbidden_actions: Sequence[str] = field(default_factory=tuple)
    forbidden_fields: Sequence[str] = field(default_factory=tuple)
    rate_limit_per_minute: int | None = None
    sensitive: bool = False
    risk_class: ToolRiskClass = ToolRiskClass.LOW
    isolation_profile: str | None = None
    isolation_boundary: str | None = None


@dataclass(frozen=True, init=False)
class ToolInvocation:
    request_id: str
    actor_id: str
    tenant_id: str
    identity: ActorIdentity
    tool_name: str
    action: str
    arguments: Mapping[str, object]
    confirmed: bool = False
    capability_token: str | None = None

    def __init__(self, *, request_id: str, tool_name: str, action: str, arguments: Mapping[str, object], confirmed: bool = False, capability_token: str | None = None, identity: ActorIdentity | None = None, actor_id: str | None = None, tenant_id: str | None = None, session_id: str = "tool-session") -> None:
        raw_actor = actor_id if actor_id is not None else (identity.actor_id if identity else "")
        raw_tenant = tenant_id if tenant_id is not None else (identity.tenant_id if identity else "")
        if identity is None and raw_actor and raw_tenant:
            identity = build_identity(actor_id=raw_actor, actor_type=ActorType.ASSISTANT_RUNTIME, tenant_id=raw_tenant, session_id=session_id, trust_level="medium", allowed_capabilities=("tools.invoke",))
        if identity is None:
            identity = build_identity(actor_id="invalid-actor", actor_type=ActorType.ASSISTANT_RUNTIME, tenant_id="invalid-tenant", session_id=session_id, trust_level="low", allowed_capabilities=tuple())
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "actor_id", raw_actor)
        object.__setattr__(self, "tenant_id", raw_tenant)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "tool_name", tool_name)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "arguments", arguments)
        object.__setattr__(self, "confirmed", confirmed)
        object.__setattr__(self, "capability_token", capability_token)


@dataclass(frozen=True)
class ToolDecision:
    status: str
    tool_name: str
    action: str
    reason: str
    sanitized_arguments: Mapping[str, object] = field(default_factory=dict)


ToolExecutor = Callable[[ToolInvocation], Mapping[str, object]]


class ToolRegistry(Protocol):
    def register(self, tool: ToolDescriptor, executor: ToolExecutor | None = None) -> None: ...
    def get(self, tool_name: str) -> ToolDescriptor | None: ...
    def list_allowlisted(self) -> Sequence[ToolDescriptor]: ...
    def list_registered(self) -> Sequence[ToolDescriptor]: ...
    def bind_execution_secret(self, secret: object) -> None: ...
    def execute(self, invocation: ToolInvocation, execution_secret: object) -> Mapping[str, object]: ...


class ToolRouter(Protocol):
    def route(self, invocation: ToolInvocation) -> ToolDecision: ...
