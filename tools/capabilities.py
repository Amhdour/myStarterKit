"""Scoped capability-token model for sensitive tool execution."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Mapping, Sequence
from uuid import uuid4

from telemetry.audit.contracts import AuditSink
from telemetry.audit.events import create_audit_event


CAPABILITY_ISSUED_EVENT = "capability.issued"
CAPABILITY_USED_EVENT = "capability.used"
CAPABILITY_DENIED_EVENT = "capability.denied"


class CapabilityTokenError(ValueError):
    pass


@dataclass(frozen=True)
class CapabilityToken:
    capability_id: str
    actor_id: str
    tool_id: str
    allowed_operations: Sequence[str]
    tenant_id: str
    issued_at: str
    expires_at: str
    justification: str
    policy_version: str


class CapabilityIssuer:
    """Issues policy-governed scoped capability tokens and records audit evidence."""

    def __init__(self, *, policy_engine, audit_sink: AuditSink, policy_version: str) -> None:
        self.policy_engine = policy_engine
        self.audit_sink = audit_sink
        self.policy_version = policy_version

    def issue(
        self,
        *,
        request_id: str,
        identity,
        tool_id: str,
        allowed_operations: Sequence[str],
        ttl_seconds: int,
        justification: str,
    ) -> str:
        if self.policy_engine is None:
            raise CapabilityTokenError("policy engine unavailable")
        decision = self.policy_engine.evaluate(
            request_id=request_id,
            action="tools.issue_capability",
            identity=identity,
            context={
                "tenant_id": identity.tenant_id,
                "tool_name": tool_id,
                "allowed_operations": list(allowed_operations),
                "ttl_seconds": ttl_seconds,
                "justification": justification,
            },
        )
        if not decision.allow:
            raise CapabilityTokenError(f"capability issuance denied: {decision.reason}")

        issued = datetime.now(timezone.utc)
        expires = issued.timestamp() + ttl_seconds
        token = CapabilityToken(
            capability_id=f"cap-{uuid4()}",
            actor_id=identity.actor_id,
            tool_id=tool_id,
            allowed_operations=tuple(allowed_operations),
            tenant_id=identity.tenant_id,
            issued_at=issued.isoformat(),
            expires_at=datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(),
            justification=justification,
            policy_version=self.policy_version,
        )
        serialized = serialize_capability_token(token)
        self.audit_sink.emit(
            create_audit_event(
                trace_id=f"trace-{request_id}",
                request_id=request_id,
                identity=identity,
                event_type=CAPABILITY_ISSUED_EVENT,
                payload={
                    "capability_id": token.capability_id,
                    "tool_id": token.tool_id,
                    "allowed_operations": list(token.allowed_operations),
                    "policy_version": token.policy_version,
                },
            )
        )
        return serialized


class CapabilityValidator:
    """Validates token scope and enforces one-time usage semantics."""

    def __init__(self, *, expected_policy_version: str) -> None:
        self.expected_policy_version = expected_policy_version
        self._consumed_capabilities: set[str] = set()

    def validate_for_invocation(self, *, token: str, invocation, sensitive: bool) -> CapabilityToken:
        if not sensitive:
            raise CapabilityTokenError("insensitive tools do not require capability token")

        parsed = parse_capability_token(token)
        now = datetime.now(timezone.utc)
        if datetime.fromisoformat(parsed.expires_at.replace("Z", "+00:00")) < now:
            raise CapabilityTokenError("capability expired")
        if parsed.capability_id in self._consumed_capabilities:
            raise CapabilityTokenError("capability replayed")
        if parsed.policy_version != self.expected_policy_version:
            raise CapabilityTokenError("policy version mismatch")
        if parsed.actor_id != invocation.actor_id:
            raise CapabilityTokenError("actor mismatch")
        if parsed.tenant_id != invocation.tenant_id:
            raise CapabilityTokenError("tenant mismatch")
        if parsed.tool_id != invocation.tool_name:
            raise CapabilityTokenError("tool mismatch")
        if invocation.action not in set(parsed.allowed_operations):
            raise CapabilityTokenError("operation not allowed")
        if len(parsed.allowed_operations) > 5:
            raise CapabilityTokenError("over-scoped capability")

        self._consumed_capabilities.add(parsed.capability_id)
        return parsed


def serialize_capability_token(token: CapabilityToken) -> str:
    return json.dumps(
        {
            "capability_id": token.capability_id,
            "actor_id": token.actor_id,
            "tool_id": token.tool_id,
            "allowed_operations": list(token.allowed_operations),
            "tenant_id": token.tenant_id,
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
            "justification": token.justification,
            "policy_version": token.policy_version,
        },
        sort_keys=True,
    )


def parse_capability_token(raw: str) -> CapabilityToken:
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise CapabilityTokenError("token parsing failed") from exc
    if not isinstance(payload, Mapping):
        raise CapabilityTokenError("token parsing failed")

    try:
        capability_id = _required_str(payload, "capability_id")
        actor_id = _required_str(payload, "actor_id")
        tool_id = _required_str(payload, "tool_id")
        tenant_id = _required_str(payload, "tenant_id")
        issued_at = _required_str(payload, "issued_at")
        expires_at = _required_str(payload, "expires_at")
        justification = _required_str(payload, "justification")
        policy_version = _required_str(payload, "policy_version")
    except CapabilityTokenError:
        raise

    ops = payload.get("allowed_operations")
    if not isinstance(ops, list) or any(not isinstance(item, str) or not item for item in ops):
        raise CapabilityTokenError("token parsing failed")

    return CapabilityToken(
        capability_id=capability_id,
        actor_id=actor_id,
        tool_id=tool_id,
        allowed_operations=tuple(ops),
        tenant_id=tenant_id,
        issued_at=issued_at,
        expires_at=expires_at,
        justification=justification,
        policy_version=policy_version,
    )


def _required_str(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise CapabilityTokenError("token parsing failed")
    return value
