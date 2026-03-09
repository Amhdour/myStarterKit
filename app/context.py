"""Context helpers for request/session propagation."""

from app.models import RequestContext, SessionContext, SupportAgentRequest


def build_request_context(request: SupportAgentRequest, *, trace_id: str) -> RequestContext:
    """Construct request-scoped context from normalized request envelope."""

    session: SessionContext = request.session
    return RequestContext(
        trace_id=trace_id,
        request_id=request.request_id,
        identity=session.identity,
    )
