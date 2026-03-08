"""Tests for secure tool routing decisions and enforcement."""

import pytest

from tools.contracts import (
    ALLOWED_DECISION,
    DENY_DECISION,
    REQUIRE_CONFIRMATION_DECISION,
    DirectToolExecutionDeniedError,
    ToolDescriptor,
    ToolInvocation,
)
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


class AllowInvokePolicyEngine:
    class _Decision:
        def __init__(self, *, confirmation_required: bool = False, rate_limit_per_minute: int | None = None):
            self.allow = True
            self.reason = "allowed"
            constraints: dict[str, object] = {"confirmation_required": confirmation_required}
            if rate_limit_per_minute is not None:
                constraints["rate_limit_per_minute"] = rate_limit_per_minute
            self.constraints = constraints

    def __init__(self, *, confirmation_required: bool = False, rate_limit_per_minute: int | None = None):
        self.confirmation_required = confirmation_required
        self.rate_limit_per_minute = rate_limit_per_minute

    def evaluate(self, request_id: str, action: str, context: dict):
        return self._Decision(
            confirmation_required=self.confirmation_required,
            rate_limit_per_minute=self.rate_limit_per_minute,
        )


class DenyInvokePolicyEngine:
    class _Decision:
        def __init__(self, reason: str = "tool denied by policy"):
            self.allow = False
            self.reason = reason
            self.constraints = {}

    def __init__(self, *, reason: str = "tool denied by policy") -> None:
        self.reason = reason

    def evaluate(self, request_id: str, action: str, context: dict):
        return self._Decision(reason=self.reason)


def _router_with_tool(tool: ToolDescriptor, executor=None, policy_engine=None) -> SecureToolRouter:
    registry = InMemoryToolRegistry()
    registry.register(tool, executor=executor)
    return SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=policy_engine or AllowInvokePolicyEngine(),
    )


def _invocation(*, tool_name: str, arguments: dict[str, object] | None = None, confirmed: bool = False):
    return ToolInvocation(
        request_id="req-1",
        actor_id="user-1",
        tenant_id="tenant-a",
        tool_name=tool_name,
        action="lookup",
        arguments=arguments or {"ticket_id": "T-1"},
        confirmed=confirmed,
    )


def test_allowlisted_tool_execution() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

    assert decision.status == ALLOWED_DECISION
    assert result == {"ok": True}


def test_direct_registry_execution_is_blocked_loudly() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )

    with pytest.raises(DirectToolExecutionDeniedError):
        registry.execute(_invocation(tool_name="ticket_lookup"), execution_secret=object())


def test_registry_execution_with_router_secret_still_fails_outside_router_context() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter())

    with pytest.raises(DirectToolExecutionDeniedError):
        registry.execute(_invocation(tool_name="ticket_lookup"), execution_secret=router._execution_secret)


def test_direct_executor_invocation_from_registry_internals_is_blocked() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )
    _ = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter())

    executor = registry._executors["ticket_lookup"]

    with pytest.raises(DirectToolExecutionDeniedError):
        executor(_invocation(tool_name="ticket_lookup"))



def test_cannot_force_execution_by_manually_entering_router_context() -> None:
    from tools.execution_guard import enter_router_execution_context

    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter())

    with pytest.raises(DirectToolExecutionDeniedError):
        _ = enter_router_execution_context(router._execution_secret)


def test_cannot_bypass_router_by_forging_execution_context_and_secret() -> None:
    from tools.execution_guard import _ROUTER_EXECUTION_CONTEXT

    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter())

    token = _ROUTER_EXECUTION_CONTEXT.set(router._execution_secret)
    try:
        with pytest.raises(DirectToolExecutionDeniedError):
            registry.execute(_invocation(tool_name="ticket_lookup"), execution_secret=router._execution_secret)
    finally:
        _ROUTER_EXECUTION_CONTEXT.reset(token)

def test_tool_router_fails_closed_when_policy_engine_missing() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=None)

    decision = router.route(_invocation(tool_name="ticket_lookup"))

    assert decision.status == DENY_DECISION
    assert "policy engine unavailable" in decision.reason


def test_forbidden_tool_denial() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        policy_engine=DenyInvokePolicyEngine(reason="tool forbidden"),
    )

    decision = router.route(_invocation(tool_name="ticket_lookup"))

    assert decision.status == DENY_DECISION
    assert "policy denied: tool forbidden" == decision.reason




def test_denied_tool_decision_contains_audit_context() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        policy_engine=DenyInvokePolicyEngine(reason="tool forbidden"),
    )

    decision = router.route(_invocation(tool_name="ticket_lookup"))

    assert decision.status == DENY_DECISION
    assert decision.tool_name == "ticket_lookup"
    assert decision.action == "lookup"
    assert decision.reason

def test_forbidden_field_blocking() -> None:
    class ForbiddenFieldPolicyEngine:
        class _Decision:
            def __init__(self, allow: bool, reason: str):
                self.allow = allow
                self.reason = reason
                self.constraints = {}

        def evaluate(self, request_id: str, action: str, context: dict):
            if "ssn" in context.get("arguments", {}):
                return self._Decision(allow=False, reason="forbidden field in arguments: ssn")
            return self._Decision(allow=True, reason="allowed")

    router = _router_with_tool(
        ToolDescriptor(
            name="ticket_lookup",
            description="lookup",
            allowed=True,
        ),
        policy_engine=ForbiddenFieldPolicyEngine(),
    )

    decision = router.route(_invocation(tool_name="ticket_lookup", arguments={"ticket_id": "T-1", "ssn": "1"}))

    assert decision.status == DENY_DECISION
    assert "policy denied: forbidden field in arguments: ssn" == decision.reason


def test_confirmation_required_flow() -> None:
    router = _router_with_tool(
        ToolDescriptor(
            name="account_update",
            description="update",
            allowed=True,
        ),
        policy_engine=AllowInvokePolicyEngine(confirmation_required=True),
    )

    unconfirmed = router.route(_invocation(tool_name="account_update", confirmed=False))
    confirmed = router.route(_invocation(tool_name="account_update", confirmed=True))

    assert unconfirmed.status == REQUIRE_CONFIRMATION_DECISION
    assert confirmed.status == ALLOWED_DECISION


def test_rate_limit_enforcement() -> None:
    router = _router_with_tool(
        ToolDescriptor(
            name="ticket_lookup",
            description="lookup",
            allowed=True,
        ),
        policy_engine=AllowInvokePolicyEngine(rate_limit_per_minute=1),
    )

    first = router.route(_invocation(tool_name="ticket_lookup"))
    second = router.route(_invocation(tool_name="ticket_lookup"))

    assert first.status == ALLOWED_DECISION
    assert second.status == DENY_DECISION
    assert "rate limit" in second.reason


def test_tool_router_denies_missing_actor_or_tenant_context() -> None:
    router = _router_with_tool(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True))

    decision = router.route(
        ToolInvocation(
            request_id="req-1",
            actor_id="",
            tenant_id="tenant-a",
            tool_name="ticket_lookup",
            action="lookup",
            arguments={"ticket_id": "T-1"},
        )
    )

    assert decision.status == DENY_DECISION
    assert "missing request, actor, or tenant context" in decision.reason


def test_tool_router_redacts_argument_values_in_decisions() -> None:
    router = _router_with_tool(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True))

    decision = router.route(_invocation(tool_name="ticket_lookup", arguments={"ticket_id": "T-1", "email": "a@b.com"}))

    assert decision.status == ALLOWED_DECISION
    assert decision.sanitized_arguments == {"ticket_id": "[redacted]", "email": "[redacted]"}


def test_router_executes_registered_executor_once_for_allowed_calls() -> None:
    calls: list[str] = []

    def _executor(invocation: ToolInvocation):
        calls.append(invocation.tool_name)
        return {"status": "ok"}

    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=_executor,
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

    assert decision.status == ALLOWED_DECISION
    assert result == {"status": "ok"}
    assert calls == ["ticket_lookup"]


def test_tool_denial_by_policy_blocks_execution() -> None:
    calls: list[str] = []

    def _executor(invocation: ToolInvocation):
        calls.append(invocation.tool_name)
        return {"ok": True}

    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=_executor,
    )
    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=DenyInvokePolicyEngine(),
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

    assert decision.status == DENY_DECISION
    assert "policy denied" in decision.reason
    assert result is None
    assert calls == []
