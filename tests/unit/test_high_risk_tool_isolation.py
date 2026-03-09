import os

from app.infrastructure_boundaries import InfrastructureBoundaryPolicy
from tools.contracts import ToolDescriptor, ToolInvocation
from tools.isolation import ToolRiskClass
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter
from tools.sandbox import LocalSubprocessSandbox, SandboxExecutionProfile


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
                "confirmation_required": False,
                "rate_limit_per_minute": 10,
                "high_risk_approved": self.approved,
            },
        )


def _invocation(command: list[str], *, confirmed: bool = True):
    return ToolInvocation(
        request_id="req-1",
        actor_id="actor-a",
        tenant_id="tenant-a",
        tool_name="admin_shell",
        action="exec",
        arguments={"command": command},
        confirmed=confirmed,
    )


def _sandbox(tmp_path, *, timeout_seconds: int = 3) -> LocalSubprocessSandbox:
    return LocalSubprocessSandbox(
        profiles={
            "restricted-shell": SandboxExecutionProfile(
                profile_name="restricted-shell",
                boundary_name="subprocess-sandbox",
                timeout_seconds=timeout_seconds,
                network_policy="disabled",
                allowed_commands=("/bin/echo", "python3"),
                allowed_env_keys=("PATH", "LANG", "LC_ALL", "SAFE_KEY"),
                evidence_dir="artifacts/logs/sandbox",
            )
        },
        repo_root=tmp_path,
    )


def test_high_risk_tool_without_isolation_metadata_is_blocked(tmp_path) -> None:
    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="admin_shell", description="shell", allowed=True, risk_class=ToolRiskClass.HIGH), executor=lambda inv: {"ok": True})
    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=ApproveHighRiskPolicy(approved=True),
        high_risk_sandbox=_sandbox(tmp_path),
    )

    decision, result = router.mediate_and_execute(_invocation(["/bin/echo", "hello"]))

    assert decision.status == "deny"
    assert "missing isolation metadata" in decision.reason
    assert result is None


def test_high_risk_tool_executed_in_sandbox_path(tmp_path) -> None:
    registry = InMemoryToolRegistry()
    called = {"executor_called": False}

    def _executor(invocation):
        called["executor_called"] = True
        return {"ok": True}

    registry.register(
        ToolDescriptor(
            name="admin_shell",
            description="shell",
            allowed=True,
            risk_class=ToolRiskClass.HIGH,
            isolation_profile="restricted-shell",
            isolation_boundary="subprocess-sandbox",
        ),
        executor=_executor,
    )
    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=ApproveHighRiskPolicy(approved=True),
        high_risk_sandbox=_sandbox(tmp_path),
    )

    decision, result = router.mediate_and_execute(_invocation(["/bin/echo", "sandbox-ok"]))

    assert decision.status == "allow"
    assert result is not None
    assert result["status"] == "ok"
    assert "sandbox-ok" in result["stdout"]
    assert called["executor_called"] is False
    evidence_path = tmp_path / result["sandbox"]["evidence_path"]
    assert evidence_path.is_file()


def test_high_risk_tool_timeout_is_handled(tmp_path) -> None:
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
    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=ApproveHighRiskPolicy(approved=True),
        high_risk_sandbox=_sandbox(tmp_path, timeout_seconds=1),
    )

    decision, result = router.mediate_and_execute(_invocation(["python3", "-c", "import time; time.sleep(2)"]))

    assert decision.status == "allow"
    assert result is not None
    assert result["status"] == "timeout"
    assert result["timed_out"] is True


def test_high_risk_sandbox_blocks_environment_exposure(tmp_path) -> None:
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
    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=ApproveHighRiskPolicy(approved=True),
        high_risk_sandbox=_sandbox(tmp_path),
    )

    os.environ["SECRET_TOKEN"] = "top-secret"
    os.environ["SAFE_KEY"] = "allowed"
    decision, result = router.mediate_and_execute(
        _invocation(["python3", "-c", 'import os; print("SECRET_TOKEN" in os.environ, "SAFE_KEY" in os.environ)'])
    )

    assert decision.status == "allow"
    assert result is not None
    assert "False True" in result["stdout"]


def test_high_risk_tool_direct_registry_execution_path_is_blocked(tmp_path) -> None:
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
    _ = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=ApproveHighRiskPolicy(approved=True),
        high_risk_sandbox=_sandbox(tmp_path),
    )

    try:
        registry.execute(_invocation(["/bin/echo", "bad"]), execution_secret=object())
    except Exception as exc:
        assert "direct tool execution is blocked" in str(exc)
        return
    raise AssertionError("expected high-risk direct execution to fail")


def test_high_risk_tool_policy_denial_without_explicit_approval_is_blocked(tmp_path) -> None:
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
    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=ApproveHighRiskPolicy(approved=False),
        high_risk_sandbox=_sandbox(tmp_path),
    )

    decision, result = router.mediate_and_execute(_invocation(["/bin/echo", "hello"]))

    assert decision.status == "deny"
    assert "explicit policy approval" in decision.reason
    assert result is None


def test_high_risk_sandbox_requesting_forbidden_egress_is_denied(tmp_path) -> None:
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

    infra = InfrastructureBoundaryPolicy.from_payload(
        {
            "allowed_destinations": [
                {"destination_id": "tool_endpoint.ticket_lookup", "host": "tools.internal.example", "trust_class": "restricted", "category": "tool_endpoint"}
            ],
            "forbidden_host_patterns": ["169.254.*"],
            "component_access_rules": {"high_risk_tool_sandbox": ["tool_endpoint"]},
            "internal_only_services": [],
            "sandbox_allowlist": ["tool_endpoint.ticket_lookup"],
        }
    )

    sandbox = LocalSubprocessSandbox(
        profiles={
            "restricted-shell": SandboxExecutionProfile(
                profile_name="restricted-shell",
                boundary_name="subprocess-sandbox",
                timeout_seconds=2,
                network_policy="allow",
                allowed_commands=("/bin/echo",),
            )
        },
        repo_root=tmp_path,
        infrastructure_policy=infra,
    )

    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=ApproveHighRiskPolicy(approved=True),
        high_risk_sandbox=sandbox,
    )

    decision2, result2 = router.mediate_and_execute(
        ToolInvocation(
            request_id="req-2",
            actor_id="actor-a",
            tenant_id="tenant-a",
            tool_name="admin_shell",
            action="exec",
            arguments={"command": ["/bin/echo", "hello"], "egress_destination": "storage_output.audit_jsonl"},
            confirmed=True,
        )
    )

    assert decision2.status == "deny"
    assert "sandbox execution failed" in decision2.reason
    assert result2 is None
