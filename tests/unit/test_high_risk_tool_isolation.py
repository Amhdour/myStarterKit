from tools.contracts import ToolDescriptor, ToolInvocation
from tools.isolation import ToolRiskClass
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


class ApproveHighRiskPolicy:
    def __init__(self, approved: bool) -> None:
        self.approved = approved

    def evaluate(self, request_id: str, action: str, context: dict, identity=None):
        from policies.contracts import PolicyDecision

        return PolicyDecision(
            request_id=request_id,
            allow=True,
            reason="ok",
            constraints={
                "confirmation_required": True,
                "rate_limit_per_minute": 10,
                "high_risk_approved": self.approved,
            },
        )


def _invocation(confirmed: bool = True):
    return ToolInvocation(
        request_id="req-1",
        actor_id="actor-a",
        tenant_id="tenant-a",
        tool_name="admin_shell",
        action="exec",
        arguments={"command": "id"},
        confirmed=confirmed,
    )


def test_high_risk_tool_without_isolation_metadata_is_blocked() -> None:
    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="admin_shell", description="shell", allowed=True, risk_class=ToolRiskClass.HIGH), executor=lambda inv: {"ok": True})
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=ApproveHighRiskPolicy(approved=True))

    decision, result = router.mediate_and_execute(_invocation())

    assert decision.status == "deny"
    assert "missing isolation metadata" in decision.reason
    assert result is None


def test_high_risk_tool_policy_denial_without_explicit_approval_is_blocked() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(
            name="admin_shell",
            description="shell",
            allowed=True,
            risk_class=ToolRiskClass.HIGH,
            isolation_profile="restricted-shell",
            isolation_boundary="subprocess-sandbox",
        ),
        executor=lambda inv: {"ok": True},
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=ApproveHighRiskPolicy(approved=False))

    decision, result = router.mediate_and_execute(_invocation())

    assert decision.status == "deny"
    assert "explicit policy approval" in decision.reason
    assert result is None


def test_high_risk_tool_enforces_confirmation_and_tight_rate_limit() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(
            name="admin_shell",
            description="shell",
            allowed=True,
            risk_class=ToolRiskClass.HIGH,
            isolation_profile="restricted-shell",
            isolation_boundary="subprocess-sandbox",
        ),
        executor=lambda inv: {"ok": True},
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=ApproveHighRiskPolicy(approved=True))

    decision_unconfirmed, _ = router.mediate_and_execute(_invocation(confirmed=False))
    decision_first, result_first = router.mediate_and_execute(_invocation(confirmed=True))
    decision_second, _ = router.mediate_and_execute(_invocation(confirmed=True))

    assert decision_unconfirmed.status == "require_confirmation"
    assert decision_first.status == "allow"
    assert result_first == {"ok": True}
    assert decision_second.status == "deny"
    assert "rate limit" in decision_second.reason
