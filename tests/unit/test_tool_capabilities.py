from telemetry.audit.sinks import InMemoryAuditSink
from identity.models import ActorType, build_identity
from tools.capabilities import CapabilityIssuer, CapabilityTokenError, CapabilityValidator
from tools.contracts import ToolDescriptor, ToolInvocation
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


class CapabilityPolicy:
    def evaluate(self, request_id: str, action: str, context: dict, identity=None):
        from policies.contracts import PolicyDecision

        if action == "tools.issue_capability":
            return PolicyDecision(request_id=request_id, allow=True, reason="issue ok")
        if action == "tools.invoke":
            return PolicyDecision(request_id=request_id, allow=True, reason="invoke ok")
        return PolicyDecision(request_id=request_id, allow=False, reason="deny")


class DenyIssuePolicy(CapabilityPolicy):
    def evaluate(self, request_id: str, action: str, context: dict, identity=None):
        from policies.contracts import PolicyDecision

        if action == "tools.issue_capability":
            return PolicyDecision(request_id=request_id, allow=False, reason="blocked")
        return super().evaluate(request_id, action, context, identity)


def _identity() -> object:
    return build_identity(
        actor_id="actor-a",
        actor_type=ActorType.END_USER,
        tenant_id="tenant-a",
        session_id="sess-a",
        allowed_capabilities=("tools.invoke", "tools.issue_capability"),
    )


def test_sensitive_tool_requires_valid_capability_token() -> None:
    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True, sensitive=True), executor=lambda inv: {"ok": True})
    audit = InMemoryAuditSink()
    issuer = CapabilityIssuer(policy_engine=CapabilityPolicy(), audit_sink=audit, policy_version="v1")
    token = issuer.issue(
        request_id="req-1",
        identity=_identity(),
        tool_id="ticket_lookup",
        allowed_operations=("lookup",),
        ttl_seconds=60,
        justification="support action",
    )

    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=CapabilityPolicy(),
        capability_validator=CapabilityValidator(expected_policy_version="v1"),
        audit_sink=audit,
    )
    decision, result = router.mediate_and_execute(
        ToolInvocation(
            request_id="req-1",
            identity=_identity(),
            actor_id="actor-a",
            tenant_id="tenant-a",
            tool_name="ticket_lookup",
            action="lookup",
            arguments={"ticket_id": "T1"},
            capability_token=token,
        )
    )

    assert decision.status == "allow"
    assert result == {"ok": True}
    event_types = [event.event_type for event in audit.events]
    assert "capability.issued" in event_types
    assert "capability.used" in event_types


def test_replayed_capability_denied() -> None:
    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True, sensitive=True), executor=lambda inv: {"ok": True})
    audit = InMemoryAuditSink()
    issuer = CapabilityIssuer(policy_engine=CapabilityPolicy(), audit_sink=audit, policy_version="v1")
    token = issuer.issue(request_id="req-1", identity=_identity(), tool_id="ticket_lookup", allowed_operations=("lookup",), ttl_seconds=60, justification="support")
    validator = CapabilityValidator(expected_policy_version="v1")
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=CapabilityPolicy(), capability_validator=validator, audit_sink=audit)

    first = ToolInvocation(request_id="req-1", identity=_identity(), actor_id="actor-a", tenant_id="tenant-a", tool_name="ticket_lookup", action="lookup", arguments={}, capability_token=token)
    second = ToolInvocation(request_id="req-2", identity=_identity(), actor_id="actor-a", tenant_id="tenant-a", tool_name="ticket_lookup", action="lookup", arguments={}, capability_token=token)

    decision1, _ = router.mediate_and_execute(first)
    decision2, _ = router.mediate_and_execute(second)

    assert decision1.status == "allow"
    assert decision2.status == "deny"
    assert "replayed" in decision2.reason


def test_expired_over_scoped_and_policy_version_mismatch_denied() -> None:
    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True, sensitive=True), executor=lambda inv: {"ok": True})
    identity = _identity()

    bad_expired = '{"capability_id":"cap-x","actor_id":"actor-a","tool_id":"ticket_lookup","allowed_operations":["lookup"],"tenant_id":"tenant-a","issued_at":"2020-01-01T00:00:00+00:00","expires_at":"2020-01-01T00:00:01+00:00","justification":"x","policy_version":"v1"}'
    over_scoped = '{"capability_id":"cap-y","actor_id":"actor-a","tool_id":"ticket_lookup","allowed_operations":["a","b","c","d","e","f"],"tenant_id":"tenant-a","issued_at":"2099-01-01T00:00:00+00:00","expires_at":"2099-01-01T00:10:00+00:00","justification":"x","policy_version":"v1"}'
    mismatch = '{"capability_id":"cap-z","actor_id":"actor-a","tool_id":"ticket_lookup","allowed_operations":["lookup"],"tenant_id":"tenant-a","issued_at":"2099-01-01T00:00:00+00:00","expires_at":"2099-01-01T00:10:00+00:00","justification":"x","policy_version":"v2"}'

    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=CapabilityPolicy(), capability_validator=CapabilityValidator(expected_policy_version="v1"))

    for token in (bad_expired, over_scoped, mismatch):
        decision, _ = router.mediate_and_execute(ToolInvocation(request_id="req-x", identity=identity, actor_id="actor-a", tenant_id="tenant-a", tool_name="ticket_lookup", action="lookup", arguments={}, capability_token=token))
        assert decision.status == "deny"


def test_mismatched_tenant_actor_tool_denied_and_issuance_policy_enforced() -> None:
    audit = InMemoryAuditSink()
    denied_issuer = CapabilityIssuer(policy_engine=DenyIssuePolicy(), audit_sink=audit, policy_version="v1")
    try:
        denied_issuer.issue(request_id="r", identity=_identity(), tool_id="ticket_lookup", allowed_operations=("lookup",), ttl_seconds=60, justification="x")
    except CapabilityTokenError:
        pass
    else:
        raise AssertionError("expected issuance denial")

    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True, sensitive=True), executor=lambda inv: {"ok": True})
    issuer = CapabilityIssuer(policy_engine=CapabilityPolicy(), audit_sink=audit, policy_version="v1")
    token = issuer.issue(request_id="req", identity=_identity(), tool_id="ticket_lookup", allowed_operations=("lookup",), ttl_seconds=60, justification="x")

    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=CapabilityPolicy(), capability_validator=CapabilityValidator(expected_policy_version="v1"), audit_sink=audit)
    mismatch_actor = ToolInvocation(request_id="r2", identity=_identity(), actor_id="other", tenant_id="tenant-a", tool_name="ticket_lookup", action="lookup", arguments={}, capability_token=token)
    mismatch_tenant = ToolInvocation(request_id="r3", identity=_identity(), actor_id="actor-a", tenant_id="tenant-b", tool_name="ticket_lookup", action="lookup", arguments={}, capability_token=token)
    mismatch_tool = ToolInvocation(request_id="r4", identity=_identity(), actor_id="actor-a", tenant_id="tenant-a", tool_name="other_tool", action="lookup", arguments={}, capability_token=token)

    for inv in (mismatch_actor, mismatch_tenant, mismatch_tool):
        decision, _ = router.mediate_and_execute(inv)
        assert decision.status == "deny"
