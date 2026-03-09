"""Secure tool router that mediates all tool invocations."""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:
    from policies.contracts import PolicyEngine
from identity.models import validate_delegation_chain, validate_identity
from telemetry.audit.contracts import AuditSink
from telemetry.audit.events import create_audit_event
from tools.capabilities import (
    CAPABILITY_DENIED_EVENT,
    CAPABILITY_USED_EVENT,
    CapabilityTokenError,
    CapabilityValidator,
)
from tools.contracts import (
    ALLOWED_DECISION,
    DENY_DECISION,
    REQUIRE_CONFIRMATION_DECISION,
    ToolDecision,
    ToolInvocation,
    ToolRegistry,
)
from tools.execution_guard import enter_router_execution_context, exit_router_execution_context
from tools.isolation import ToolRiskClass
from tools.sandbox import HighRiskSandbox, LocalSubprocessSandbox, SandboxExecutionProfile
from tools.rate_limit import ToolRateLimiter


@dataclass
class SecureToolRouter:
    """Allowlist- and validation-driven tool router."""

    registry: ToolRegistry
    rate_limiter: ToolRateLimiter
    policy_engine: "PolicyEngine | None" = None
    capability_validator: CapabilityValidator = field(default_factory=lambda: CapabilityValidator(expected_policy_version="v1"))
    audit_sink: AuditSink | None = None
    high_risk_sandbox: HighRiskSandbox = field(
        default_factory=lambda: LocalSubprocessSandbox(
            profiles={
                "restricted-shell": SandboxExecutionProfile(
                    profile_name="restricted-shell",
                    boundary_name="subprocess-sandbox",
                    timeout_seconds=5,
                    network_policy="disabled",
                    allowed_commands=("/bin/echo", "python3"),
                    allowed_env_keys=("PATH", "LANG", "LC_ALL"),
                )
            },
            repo_root=Path.cwd(),
        )
    )
    _execution_secret: object = field(default_factory=object, init=False, repr=False)

    def __post_init__(self) -> None:
        self.registry.bind_execution_secret(self._execution_secret)

    def route(self, invocation: ToolInvocation) -> ToolDecision:
        if not invocation.request_id or not invocation.actor_id or not invocation.tenant_id:
            return self._deny(invocation, "missing request, actor, or tenant context")

        try:
            validate_identity(invocation.identity)
        except Exception:
            return self._deny(invocation, "invalid identity")

        if not invocation.tool_name or not invocation.action:
            return self._deny(invocation, "missing tool name or action")

        try:
            validate_delegation_chain(invocation.identity, action="tools.invoke")
        except Exception as exc:
            return self._deny(invocation, f"invalid delegation: {exc}")

        descriptor = self.registry.get(invocation.tool_name)
        if descriptor is None:
            return self._deny(invocation, "tool is not registered")

        if invocation.action in descriptor.forbidden_actions:
            return self._deny(invocation, "action is forbidden for this tool")

        if not self._valid_arguments(invocation.arguments):
            return self._deny(invocation, "tool arguments failed validation")

        if descriptor.risk_class == ToolRiskClass.HIGH:
            if not descriptor.isolation_profile or not descriptor.isolation_boundary:
                return self._deny(invocation, "high-risk tool missing isolation metadata")
            if not self.high_risk_sandbox.supports(descriptor):
                return self._deny(invocation, "high-risk tool sandbox profile unsupported")


        if descriptor.sensitive:
            if not invocation.capability_token:
                self._audit_capability_event(invocation, CAPABILITY_DENIED_EVENT, "missing capability token")
                return self._deny(invocation, "missing capability token")
            try:
                token = self.capability_validator.validate_for_invocation(
                    token=invocation.capability_token,
                    invocation=invocation,
                    sensitive=descriptor.sensitive,
                )
                self._audit_capability_event(invocation, CAPABILITY_USED_EVENT, token.capability_id)
            except CapabilityTokenError as exc:
                self._audit_capability_event(invocation, CAPABILITY_DENIED_EVENT, str(exc))
                return self._deny(invocation, f"capability denied: {exc}")

        if self.policy_engine is None:
            return self._deny(invocation, "policy engine unavailable")

        if self.policy_engine is not None:
            try:
                try:
                    policy_decision = self.policy_engine.evaluate(
                        request_id=invocation.request_id,
                        action="tools.invoke",
                        identity=invocation.identity,
                        context={
                            "tenant_id": invocation.tenant_id,
                            "tool_name": invocation.tool_name,
                            "action": invocation.action,
                            "arguments": dict(invocation.arguments),
                            "risk_class": descriptor.risk_class.value,
                            "isolation_profile": descriptor.isolation_profile,
                            "isolation_boundary": descriptor.isolation_boundary,
                        },
                    )
                except TypeError:
                    policy_decision = self.policy_engine.evaluate(
                        request_id=invocation.request_id,
                        action="tools.invoke",
                        context={
                            "tenant_id": invocation.tenant_id,
                            "tool_name": invocation.tool_name,
                            "action": invocation.action,
                            "arguments": dict(invocation.arguments),
                            "risk_class": descriptor.risk_class.value,
                            "isolation_profile": descriptor.isolation_profile,
                            "isolation_boundary": descriptor.isolation_boundary,
                        },
                    )
            except Exception:
                return self._deny(invocation, "policy evaluation failed")

            if not policy_decision.allow:
                return self._deny(invocation, f"policy denied: {policy_decision.reason}")

            if descriptor.risk_class == ToolRiskClass.HIGH and not bool(policy_decision.constraints.get("high_risk_approved", False)):
                return self._deny(invocation, "high-risk tool missing explicit policy approval")

            confirmation_required = bool(policy_decision.constraints.get("confirmation_required", False)) or descriptor.risk_class == ToolRiskClass.HIGH
            if confirmation_required and not invocation.confirmed:
                return ToolDecision(
                    status=REQUIRE_CONFIRMATION_DECISION,
                    tool_name=invocation.tool_name,
                    action=invocation.action,
                    reason="tool use requires explicit confirmation",
                    sanitized_arguments=self._sanitize_arguments(invocation.arguments),
                )

            policy_rate_limit = policy_decision.constraints.get("rate_limit_per_minute")
            if descriptor.risk_class == ToolRiskClass.HIGH:
                policy_rate_limit = 1 if not isinstance(policy_rate_limit, int) else min(policy_rate_limit, 1)

            if isinstance(policy_rate_limit, int) and policy_rate_limit > 0:
                key = f"{invocation.tenant_id}:{invocation.actor_id}:{invocation.tool_name}"
                if not self.rate_limiter.allow(key, policy_rate_limit):
                    return self._deny(invocation, "rate limit exceeded")

        return ToolDecision(
            status=ALLOWED_DECISION,
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="tool invocation allowed",
            sanitized_arguments=self._sanitize_arguments(invocation.arguments),
        )

    def mediate_and_execute(
        self,
        invocation: ToolInvocation,
    ) -> tuple[ToolDecision, Mapping[str, object] | None]:
        """Route first, then execute only if allowed via the centralized registry."""

        decision = self.route(invocation)
        if decision.status != ALLOWED_DECISION:
            return decision, None

        descriptor = self.registry.get(invocation.tool_name)
        if descriptor is None:
            return self._deny(invocation, "tool is not registered"), None

        if descriptor.risk_class == ToolRiskClass.HIGH:
            try:
                return decision, self.high_risk_sandbox.execute(invocation, descriptor)
            except Exception as exc:
                return self._deny(invocation, f"sandbox execution failed: {type(exc).__name__}"), None

        token = enter_router_execution_context(self._execution_secret)
        try:
            try:
                return decision, self.registry.execute(invocation, execution_secret=self._execution_secret)
            except Exception as exc:
                return self._deny(invocation, f"tool execution failed: {type(exc).__name__}"), None
        finally:
            exit_router_execution_context(token)

    def _deny(self, invocation: ToolInvocation, reason: str) -> ToolDecision:
        return ToolDecision(
            status=DENY_DECISION,
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason=reason,
            sanitized_arguments={},
        )

    def _valid_arguments(self, arguments: Mapping[str, object]) -> bool:
        for key in arguments:
            if not isinstance(key, str) or not key:
                return False
        try:
            json.dumps(arguments)
        except (TypeError, ValueError):
            return False
        return True

    def _sanitize_arguments(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        return {key: "[redacted]" for key in arguments.keys()}

    def _audit_capability_event(self, invocation: ToolInvocation, event_type: str, detail: str) -> None:
        if self.audit_sink is None:
            return
        self.audit_sink.emit(
            create_audit_event(
                trace_id=f"trace-{invocation.request_id}",
                request_id=invocation.request_id,
                identity=invocation.identity,
                event_type=event_type,
                payload={
                    "tool_name": invocation.tool_name,
                    "action": invocation.action,
                    "detail": detail,
                },
            )
        )
