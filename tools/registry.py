"""Centralized tool registry implementation."""

from dataclasses import dataclass, field
from typing import Mapping

from tools.contracts import (
    DirectToolExecutionDeniedError,
    ToolDescriptor,
    ToolExecutor,
    ToolInvocation,
    ToolRegistry,
)
from tools.execution_guard import (
    assert_registry_execute_callsite,
    assert_wrapped_executor_callsite,
    current_router_execution_secret,
)
from tools.isolation import ToolRiskClass


@dataclass
class InMemoryToolRegistry(ToolRegistry):
    """Simple centralized tool registry for local usage and tests."""

    _tools: dict[str, ToolDescriptor] = field(default_factory=dict)
    _executors: dict[str, ToolExecutor] = field(default_factory=dict)
    _execution_secret: object | None = None

    def register(self, tool: ToolDescriptor, executor: ToolExecutor | None = None) -> None:
        self._tools[tool.name] = tool
        if executor is not None:
            self._executors[tool.name] = self._wrap_executor(tool_name=tool.name, executor=executor)

    def get(self, tool_name: str) -> ToolDescriptor | None:
        return self._tools.get(tool_name)

    def list_allowlisted(self):
        return tuple(tool for tool in self._tools.values() if tool.allowed)

    def list_registered(self):
        return tuple(self._tools.values())

    def bind_execution_secret(self, secret: object) -> None:
        self._execution_secret = secret

    def execute(self, invocation: ToolInvocation, execution_secret: object) -> Mapping[str, object]:
        assert_registry_execute_callsite()
        router_context_secret = current_router_execution_secret()
        if (
            self._execution_secret is None
            or execution_secret is not self._execution_secret
            or router_context_secret is not self._execution_secret
        ):
            raise DirectToolExecutionDeniedError(
                "direct tool execution is blocked: use SecureToolRouter.mediate_and_execute"
            )

        descriptor = self._tools.get(invocation.tool_name)
        if descriptor is not None and descriptor.risk_class == ToolRiskClass.HIGH:
            raise DirectToolExecutionDeniedError(
                "high-risk tool direct execution is blocked: use SecureToolRouter sandbox path"
            )

        executor = self._executors.get(invocation.tool_name)
        if executor is None:
            raise DirectToolExecutionDeniedError(
                f"tool '{invocation.tool_name}' has no registered executor"
            )

        return executor(invocation)

    def _wrap_executor(self, *, tool_name: str, executor: ToolExecutor) -> ToolExecutor:
        def _guarded_executor(invocation: ToolInvocation) -> Mapping[str, object]:
            assert_wrapped_executor_callsite()
            if current_router_execution_secret() is not self._execution_secret:
                raise DirectToolExecutionDeniedError(
                    "direct tool execution is blocked: use SecureToolRouter.mediate_and_execute"
                )
            if invocation.tool_name != tool_name:
                raise DirectToolExecutionDeniedError(
                    f"tool executor mismatch: expected '{tool_name}', got '{invocation.tool_name}'"
                )
            return executor(invocation)

        return _guarded_executor
