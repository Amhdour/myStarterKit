"""Runtime execution guard for router-mediated tool execution."""

import inspect
from contextvars import ContextVar, Token

from tools.contracts import DirectToolExecutionDeniedError

_ROUTER_EXECUTION_CONTEXT: ContextVar[object | None] = ContextVar(
    "tool_router_execution_context",
    default=None,
)


def _frame_details(frame) -> tuple[object | None, str | None, str | None]:
    module_name = frame.f_globals.get("__name__") if frame is not None else None
    function_name = frame.f_code.co_name if frame is not None else None
    caller_self = frame.f_locals.get("self") if frame is not None else None
    class_name = type(caller_self).__name__ if caller_self is not None else None
    return module_name, function_name, class_name


def _assert_router_mediation_callsite() -> None:
    frame = inspect.currentframe()
    if frame is None or frame.f_back is None or frame.f_back.f_back is None:
        raise DirectToolExecutionDeniedError(
            "direct tool execution is blocked: execution context can only be opened by SecureToolRouter.mediate_and_execute"
        )

    caller_module, caller_name, caller_class = _frame_details(frame.f_back.f_back)
    if not (
        caller_module == "tools.router"
        and caller_name == "mediate_and_execute"
        and caller_class == "SecureToolRouter"
    ):
        raise DirectToolExecutionDeniedError(
            "direct tool execution is blocked: execution context can only be opened by SecureToolRouter.mediate_and_execute"
        )


def assert_registry_execute_callsite() -> None:
    """Allow registry execution only when called from the centralized router."""

    frame = inspect.currentframe()
    if frame is None or frame.f_back is None or frame.f_back.f_back is None:
        raise DirectToolExecutionDeniedError(
            "direct tool execution is blocked: registry execution can only be invoked by SecureToolRouter.mediate_and_execute"
        )

    caller_module, caller_name, caller_class = _frame_details(frame.f_back.f_back)
    if not (
        caller_module == "tools.router"
        and caller_name == "mediate_and_execute"
        and caller_class == "SecureToolRouter"
    ):
        raise DirectToolExecutionDeniedError(
            "direct tool execution is blocked: registry execution can only be invoked by SecureToolRouter.mediate_and_execute"
        )


def assert_wrapped_executor_callsite() -> None:
    """Allow wrapped executors to run only through the registry execute path."""

    frame = inspect.currentframe()
    if frame is None or frame.f_back is None or frame.f_back.f_back is None:
        raise DirectToolExecutionDeniedError(
            "direct tool execution is blocked: executor can only be invoked by InMemoryToolRegistry.execute"
        )

    caller_module, caller_name, caller_class = _frame_details(frame.f_back.f_back)
    if not (
        caller_module == "tools.registry"
        and caller_name == "execute"
        and caller_class == "InMemoryToolRegistry"
    ):
        raise DirectToolExecutionDeniedError(
            "direct tool execution is blocked: executor can only be invoked by InMemoryToolRegistry.execute"
        )


def current_router_execution_secret() -> object | None:
    """Return the currently active router execution secret, if any."""

    return _ROUTER_EXECUTION_CONTEXT.get()


def enter_router_execution_context(secret: object) -> Token:
    """Mark the current context as an active router-mediated execution."""

    _assert_router_mediation_callsite()
    return _ROUTER_EXECUTION_CONTEXT.set(secret)


def exit_router_execution_context(token: Token) -> None:
    """Reset router execution context to the previous value."""

    _ROUTER_EXECUTION_CONTEXT.reset(token)
