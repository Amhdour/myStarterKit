"""Runtime execution guard for router-mediated tool execution."""

from contextvars import ContextVar, Token

_ROUTER_EXECUTION_CONTEXT: ContextVar[object | None] = ContextVar(
    "tool_router_execution_context",
    default=None,
)


def current_router_execution_secret() -> object | None:
    """Return the currently active router execution secret, if any."""

    return _ROUTER_EXECUTION_CONTEXT.get()


def enter_router_execution_context(secret: object) -> Token:
    """Mark the current context as an active router-mediated execution."""

    return _ROUTER_EXECUTION_CONTEXT.set(secret)


def exit_router_execution_context(token: Token) -> None:
    """Reset router execution context to the previous value."""

    _ROUTER_EXECUTION_CONTEXT.reset(token)
