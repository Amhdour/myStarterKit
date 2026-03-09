from dataclasses import dataclass

from identity.models import ActorType, build_identity
from telemetry.audit.sinks import InMemoryAuditSink
from tools.mcp_security import MCPPolicyError, MCPServerProfile, MCPTrustLabel, SecureMCPGateway
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter
from tools.contracts import ToolDescriptor, ToolInvocation


@dataclass
class AllowPolicy:
    def evaluate(self, request_id: str, action: str, context: dict, identity=None):
        from policies.contracts import PolicyDecision

        return PolicyDecision(request_id=request_id, allow=True, reason="allowed", constraints={})


class FakeTransport:
    def __init__(self, response: dict | None = None, raise_error: bool = False) -> None:
        self.response = response or {"status": "ok", "data": {"value": "done"}, "origin": {"server_id": "mcp-a", "endpoint": "https://mcp-a"}}
        self.raise_error = raise_error
        self.calls = 0

    def call(self, *, endpoint: str, payload: dict, timeout_ms: int):
        self.calls += 1
        if self.raise_error:
            raise RuntimeError("network")
        return self.response


def _identity(tenant_id: str = "tenant-a"):
    return build_identity(
        actor_id="user-1",
        actor_type=ActorType.END_USER,
        tenant_id=tenant_id,
        session_id="s-1",
        allowed_capabilities=("tools.invoke",),
    )


def _invocation(identity):
    return ToolInvocation(
        request_id="req-1",
        identity=identity,
        actor_id=identity.actor_id,
        tenant_id=identity.tenant_id,
        tool_name="mcp_ticket_lookup",
        action="lookup",
        arguments={"ticket_id": "T-1"},
    )


def _setup(transport: FakeTransport, profile: MCPServerProfile):
    audit = InMemoryAuditSink()
    gateway = SecureMCPGateway(audit_sink=audit, transport=transport, servers={profile.server_id: profile})
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="mcp_ticket_lookup", description="mcp", allowed=True),
        executor=gateway.build_tool_executor(server_id=profile.server_id, capability="tickets.read"),
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=AllowPolicy())
    return audit, router


def test_mcp_allowlisted_server_happy_path_with_audit_origin() -> None:
    profile = MCPServerProfile(
        server_id="mcp-a",
        endpoint="https://mcp-a",
        tenant_id="tenant-a",
        trust_label=MCPTrustLabel.TRUSTED,
        allowed_tool_capabilities=("tickets.read",),
    )
    audit, router = _setup(FakeTransport(), profile)

    decision, result = router.mediate_and_execute(_invocation(_identity()))

    assert decision.status == "allow"
    assert result is not None and result["status"] == "ok"
    assert any(e.event_type == "mcp.security" for e in audit.events)
    sec = [e for e in audit.events if e.event_type == "mcp.security"][0]
    assert sec.event_payload["origin"]["server_id"] == "mcp-a"


def test_mcp_malformed_response_denied_and_logged() -> None:
    profile = MCPServerProfile(
        server_id="mcp-a",
        endpoint="https://mcp-a",
        tenant_id="tenant-a",
        trust_label=MCPTrustLabel.TRUSTED,
        allowed_tool_capabilities=("tickets.read",),
    )
    bad = FakeTransport(response={"unexpected": True})
    audit, router = _setup(bad, profile)

    decision, result = router.mediate_and_execute(_invocation(_identity()))

    assert decision.status == "deny"
    assert result is None
    assert any(e.event_type == "deny.event" for e in audit.events)


def test_mcp_oversized_response_denied() -> None:
    profile = MCPServerProfile(
        server_id="mcp-a",
        endpoint="https://mcp-a",
        tenant_id="tenant-a",
        trust_label=MCPTrustLabel.TRUSTED,
        allowed_tool_capabilities=("tickets.read",),
        max_response_bytes=64,
    )
    huge = FakeTransport(response={"status": "ok", "data": {"blob": "x" * 1000}, "origin": {"server_id": "mcp-a", "endpoint": "https://mcp-a"}})
    audit, router = _setup(huge, profile)

    decision, result = router.mediate_and_execute(_invocation(_identity()))

    assert decision.status == "deny"
    assert result is None


def test_mcp_allowlist_violation_unknown_server_denied() -> None:
    audit = InMemoryAuditSink()
    gateway = SecureMCPGateway(audit_sink=audit, transport=FakeTransport(), servers={})
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="mcp_ticket_lookup", description="mcp", allowed=True),
        executor=gateway.build_tool_executor(server_id="unknown", capability="tickets.read"),
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=AllowPolicy())

    decision, result = router.mediate_and_execute(_invocation(_identity()))

    assert decision.status == "deny"
    assert result is None


def test_mcp_untrusted_server_denied() -> None:
    profile = MCPServerProfile(
        server_id="mcp-u",
        endpoint="https://evil",
        tenant_id="tenant-a",
        trust_label=MCPTrustLabel.UNTRUSTED,
        allowed_tool_capabilities=("tickets.read",),
    )
    audit, router = _setup(FakeTransport(), profile)

    decision, result = router.mediate_and_execute(_invocation(_identity()))

    assert decision.status == "deny"
    assert result is None


def test_mcp_tenant_boundary_violation_denied() -> None:
    profile = MCPServerProfile(
        server_id="mcp-a",
        endpoint="https://mcp-a",
        tenant_id="tenant-a",
        trust_label=MCPTrustLabel.TRUSTED,
        allowed_tool_capabilities=("tickets.read",),
    )
    audit, router = _setup(FakeTransport(), profile)

    decision, result = router.mediate_and_execute(_invocation(_identity("tenant-b")))

    assert decision.status == "deny"
    assert result is None
