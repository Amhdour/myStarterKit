"""Canonical actor identity model and validation helpers."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping, Sequence


class ActorType(str, Enum):
    """Supported actor types in runtime trust model."""

    END_USER = "end_user"
    ASSISTANT_RUNTIME = "assistant_runtime"
    DELEGATED_AGENT = "delegated_agent"
    TOOL_EXECUTOR = "tool_executor"
    HUMAN_OPERATOR = "human_operator"
    TEST_HARNESS = "test_harness"


@dataclass(frozen=True)
class DelegationGrant:
    """One parent->child delegation grant in a verifiable chain."""

    parent_actor_id: str
    child_actor_id: str
    delegated_capabilities: Sequence[str]
    delegation_reason: str
    issued_at: str
    expires_at: str
    scope_constraints: Mapping[str, str]


@dataclass(frozen=True)
class ActorIdentity:
    """Canonical identity required for all sensitive flows."""

    actor_id: str
    actor_type: ActorType
    tenant_id: str
    session_id: str
    delegation_chain: Sequence[DelegationGrant] = field(default_factory=tuple)
    auth_context: Mapping[str, str] = field(default_factory=dict)
    trust_level: str = "untrusted"
    allowed_capabilities: Sequence[str] = field(default_factory=tuple)


REQUIRED_AUTH_KEYS = ("authn_method", "issuer", "credential_id")
ALLOWED_TRUST_LEVELS = {"untrusted", "low", "medium", "high", "privileged"}


class IdentityValidationError(ValueError):
    """Raised when identity payload is missing, malformed, or inconsistent."""


def parse_identity(payload: Mapping[str, object]) -> ActorIdentity:
    """Parse and strictly validate identity from untrusted payload."""

    actor_id = _as_nonempty_string(payload.get("actor_id"), "actor_id")
    actor_type_raw = _as_nonempty_string(payload.get("actor_type"), "actor_type")
    try:
        actor_type = ActorType(actor_type_raw)
    except ValueError as exc:
        raise IdentityValidationError("actor_type is invalid") from exc

    tenant_id = _as_nonempty_string(payload.get("tenant_id"), "tenant_id")
    session_id = _as_nonempty_string(payload.get("session_id"), "session_id")

    delegation_chain_raw = payload.get("delegation_chain", tuple())
    if not isinstance(delegation_chain_raw, Sequence) or isinstance(delegation_chain_raw, (str, bytes)):
        raise IdentityValidationError("delegation_chain must be an array")
    delegation_chain: list[DelegationGrant] = []
    for index, grant in enumerate(delegation_chain_raw):
        if not isinstance(grant, Mapping):
            raise IdentityValidationError(f"delegation_chain[{index}] must be an object")

        parent_actor_id = _as_nonempty_string(grant.get("parent_actor_id"), f"delegation_chain[{index}].parent_actor_id")
        child_actor_id = _as_nonempty_string(grant.get("child_actor_id"), f"delegation_chain[{index}].child_actor_id")
        delegation_reason = _as_nonempty_string(grant.get("delegation_reason"), f"delegation_chain[{index}].delegation_reason")
        issued_at = _as_nonempty_string(grant.get("issued_at"), f"delegation_chain[{index}].issued_at")
        expires_at = _as_nonempty_string(grant.get("expires_at"), f"delegation_chain[{index}].expires_at")

        delegated_raw = grant.get("delegated_capabilities", tuple())
        if not isinstance(delegated_raw, Sequence) or isinstance(delegated_raw, (str, bytes)):
            raise IdentityValidationError(f"delegation_chain[{index}].delegated_capabilities must be an array")
        delegated_capabilities: list[str] = []
        for capability in delegated_raw:
            if not isinstance(capability, str) or not capability:
                raise IdentityValidationError(f"delegation_chain[{index}].delegated_capabilities has invalid value")
            delegated_capabilities.append(capability)

        scope_constraints_raw = grant.get("scope_constraints", {})
        if not isinstance(scope_constraints_raw, Mapping):
            raise IdentityValidationError(f"delegation_chain[{index}].scope_constraints must be an object")
        scope_constraints: dict[str, str] = {}
        for key, value in scope_constraints_raw.items():
            if not isinstance(key, str) or not key:
                raise IdentityValidationError(f"delegation_chain[{index}].scope_constraints key invalid")
            if not isinstance(value, str) or not value:
                raise IdentityValidationError(f"delegation_chain[{index}].scope_constraints.{key} invalid")
            scope_constraints[key] = value

        delegation_chain.append(
            DelegationGrant(
                parent_actor_id=parent_actor_id,
                child_actor_id=child_actor_id,
                delegated_capabilities=tuple(delegated_capabilities),
                delegation_reason=delegation_reason,
                issued_at=issued_at,
                expires_at=expires_at,
                scope_constraints=scope_constraints,
            )
        )

    auth_context_raw = payload.get("auth_context", {})
    if not isinstance(auth_context_raw, Mapping):
        raise IdentityValidationError("auth_context must be an object")
    auth_context: dict[str, str] = {}
    for key, value in auth_context_raw.items():
        if not isinstance(key, str) or not key:
            raise IdentityValidationError("auth_context keys must be non-empty strings")
        if not isinstance(value, str) or not value:
            raise IdentityValidationError(f"auth_context.{key} must be a non-empty string")
        auth_context[key] = value

    for key in REQUIRED_AUTH_KEYS:
        if key not in auth_context:
            raise IdentityValidationError(f"auth_context missing required key: {key}")

    trust_level = _as_nonempty_string(payload.get("trust_level"), "trust_level")
    if trust_level not in ALLOWED_TRUST_LEVELS:
        raise IdentityValidationError("trust_level is invalid")

    allowed_capabilities_raw = payload.get("allowed_capabilities", tuple())
    if not isinstance(allowed_capabilities_raw, Sequence) or isinstance(allowed_capabilities_raw, (str, bytes)):
        raise IdentityValidationError("allowed_capabilities must be an array")
    allowed_capabilities: list[str] = []
    for item in allowed_capabilities_raw:
        if not isinstance(item, str) or not item:
            raise IdentityValidationError("allowed_capabilities must contain non-empty strings")
        allowed_capabilities.append(item)

    identity = ActorIdentity(
        actor_id=actor_id,
        actor_type=actor_type,
        tenant_id=tenant_id,
        session_id=session_id,
        delegation_chain=tuple(delegation_chain),
        auth_context=auth_context,
        trust_level=trust_level,
        allowed_capabilities=tuple(allowed_capabilities),
    )
    _validate_delegation_consistency(identity)
    return identity


def _validate_delegation_consistency(identity: ActorIdentity) -> None:
    if identity.actor_type in (ActorType.DELEGATED_AGENT, ActorType.TOOL_EXECUTOR) and len(identity.delegation_chain) == 0:
        raise IdentityValidationError("delegated/tool actors require a non-empty delegation_chain")


def _as_nonempty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IdentityValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _parse_utc(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IdentityValidationError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise IdentityValidationError(f"{field_name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def validate_delegation_chain(identity: ActorIdentity, *, action: str, now: datetime | None = None) -> None:
    """Validate delegation continuity, scope, and expiry for delegated actors."""

    if identity.actor_type not in (ActorType.DELEGATED_AGENT, ActorType.TOOL_EXECUTOR):
        return

    if len(identity.delegation_chain) == 0:
        raise IdentityValidationError("missing parent chain")

    reference_time = now or datetime.now(timezone.utc)
    previous_child: str | None = None
    previous_caps: set[str] | None = None

    for index, grant in enumerate(identity.delegation_chain):
        if previous_child is not None and grant.parent_actor_id != previous_child:
            raise IdentityValidationError("broken chain continuity")

        issued_at = _parse_utc(grant.issued_at, f"delegation_chain[{index}].issued_at")
        expires_at = _parse_utc(grant.expires_at, f"delegation_chain[{index}].expires_at")
        if issued_at >= expires_at:
            raise IdentityValidationError("expired delegation")
        if reference_time > expires_at:
            raise IdentityValidationError("expired delegation")

        scoped_tenant = grant.scope_constraints.get("tenant_id")
        if not scoped_tenant or scoped_tenant != identity.tenant_id:
            raise IdentityValidationError("delegation tenant mismatch")

        grant_caps = set(grant.delegated_capabilities)
        if action not in grant_caps:
            raise IdentityValidationError("delegation scope does not include action")

        if previous_caps is not None and not grant_caps.issubset(previous_caps):
            raise IdentityValidationError("scope inflation")

        previous_child = grant.child_actor_id
        previous_caps = grant_caps

    if previous_child != identity.actor_id:
        raise IdentityValidationError("broken chain continuity")

    if previous_caps is None or not set(identity.allowed_capabilities).issubset(previous_caps):
        raise IdentityValidationError("scope inflation")


def validate_identity(identity: ActorIdentity) -> None:
    """Validate a typed identity object using canonical rules."""

    parse_identity(
        {
            "actor_id": identity.actor_id,
            "actor_type": identity.actor_type.value,
            "tenant_id": identity.tenant_id,
            "session_id": identity.session_id,
            "delegation_chain": [
                {
                    "parent_actor_id": step.parent_actor_id,
                    "child_actor_id": step.child_actor_id,
                    "delegated_capabilities": list(step.delegated_capabilities),
                    "delegation_reason": step.delegation_reason,
                    "issued_at": step.issued_at,
                    "expires_at": step.expires_at,
                    "scope_constraints": dict(step.scope_constraints),
                }
                for step in identity.delegation_chain
            ],
            "auth_context": dict(identity.auth_context),
            "trust_level": identity.trust_level,
            "allowed_capabilities": list(identity.allowed_capabilities),
        }
    )


def build_identity(
    *,
    actor_id: str,
    actor_type: ActorType,
    tenant_id: str,
    session_id: str,
    delegation_chain: Sequence[DelegationGrant] = tuple(),
    auth_context: Mapping[str, str] | None = None,
    trust_level: str = "low",
    allowed_capabilities: Sequence[str] = tuple(),
) -> ActorIdentity:
    """Construct identity with strict defaults for required fields."""

    context = dict(auth_context or {})
    context.setdefault("authn_method", "asserted")
    context.setdefault("issuer", "starter-kit")
    context.setdefault("credential_id", "legacy")
    return parse_identity(
        {
            "actor_id": actor_id,
            "actor_type": actor_type.value,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "delegation_chain": [
                {
                    "parent_actor_id": step.parent_actor_id,
                    "child_actor_id": step.child_actor_id,
                    "delegated_capabilities": list(step.delegated_capabilities),
                    "delegation_reason": step.delegation_reason,
                    "issued_at": step.issued_at,
                    "expires_at": step.expires_at,
                    "scope_constraints": dict(step.scope_constraints),
                }
                for step in delegation_chain
            ],
            "auth_context": context,
            "trust_level": trust_level,
            "allowed_capabilities": list(allowed_capabilities),
        }
    )


def verify_delegation_evidence(identity: ActorIdentity, *, action: str) -> tuple[bool, tuple[str, ...]]:
    """Return verification diagnostics for delegation evidence quality."""

    issues: list[str] = []
    if identity.actor_type in (ActorType.DELEGATED_AGENT, ActorType.TOOL_EXECUTOR) and len(identity.delegation_chain) == 0:
        issues.append("missing parent chain")

    try:
        validate_delegation_chain(identity, action=action)
    except IdentityValidationError as exc:
        message = str(exc)
        if message in {"broken chain continuity", "scope inflation", "expired delegation", "missing parent chain"}:
            issues.append(message)
        elif "tenant mismatch" in message:
            issues.append("broken chain continuity")
        else:
            issues.append(message)

    deduped = tuple(dict.fromkeys(issues))
    return len(deduped) == 0, deduped
