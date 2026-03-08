"""Runtime execution guard for router-mediated tool execution."""

import inspect
from contextvars import ContextVar, Token

from tools.contracts import DirectToolExecutionDeniedError

_ROUTER_EXECUTION_CONTEXT: ContextVar[object | None] = ContextVar(
    "tool_router_execution_context",
    default=None,
)


def _assert_router_mediation_callsite() -> None:
    frame = inspect.currentframe()
    if frame is None or frame.f_back is None or frame.f_back.f_back is None:
        raise DirectToolExecutionDeniedError(
            "direct tool execution is blocked: execution context can only be opened by SecureToolRouter.mediate_and_execute"
        )

    caller = frame.f_back.f_back
    caller_module = caller.f_globals.get("__name__")
    caller_name = caller.f_code.co_name
    caller_self = caller.f_locals.get("self")
    caller_class = type(caller_self).__name__ if caller_self is not None else None

    if not (
        caller_module == "tools.router"
        and caller_name == "mediate_and_execute"
        and caller_class == "SecureToolRouter"
    ):
        raise DirectToolExecutionDeniedError(
            "direct tool execution is blocked: execution context can only be opened by SecureToolRouter.mediate_and_execute"
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
