"""Policy mutation tests proving runtime behavior changes when policy inputs change."""

from app.modeling import ModelInput
from app.models import SessionContext, SupportAgentRequest
from app.orchestrator import SupportAgentOrchestrator
from policies.engine import RuntimePolicyEngine
from policies.schema import build_runtime_policy
from retrieval.contracts import (
    DocumentProvenance,
    RetrievalDocument,
    RetrievalQuery,
    SourceRegistration,
    SourceTrustMetadata,
)
from retrieval.registry import InMemorySourceRegistry
from retrieval.service import SecureRetrievalService
from tools.contracts import ALLOWED_DECISION, DENY_DECISION, REQUIRE_CONFIRMATION_DECISION, ToolDescriptor, ToolInvocation
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


class FakeRawRetriever:
    def search(self, query: RetrievalQuery):
        return (
            RetrievalDocument(
                document_id="doc-1",
                content="KB answer",
                trust=SourceTrustMetadata(
                    source_id="kb-main",
                    tenant_id=query.tenant_id,
                    checksum="h1",
                    ingested_at="2026-01-01T00:00:00Z",
                ),
                provenance=DocumentProvenance(
                    citation_id="cite-1",
                    source_id="kb-main",
                    document_uri="kb://doc-1",
                    chunk_id="chunk-1",
                ),
                attributes={},
            ),
        )


class FakeModel:
    def __init__(self) -> None:
        self.inputs: list[ModelInput] = []

    def generate(self, model_input: ModelInput) -> str:
        self.inputs.append(model_input)
        return "draft"


class FakeAuditSink:
    def __init__(self) -> None:
        self.events = []

    def emit(self, event):
        self.events.append(event)


class FakeToolRegistry:
    def __init__(self, tool_name: str = "ticket_lookup") -> None:
        self.tool_name = tool_name

    def list_allowlisted(self):
        return (ToolDescriptor(name=self.tool_name, description="lookup", allowed=True),)


class FakeDenyToolRouter:
    def route(self, invocation):
        from tools.contracts import ToolDecision

        return ToolDecision(
            status=DENY_DECISION,
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="policy denied",
            sanitized_arguments={},
        )


def _policy_payload(*, fallback_to_rag: bool = True, kill_switch: bool = False) -> dict:
    return {
        "global": {"kill_switch": kill_switch, "fallback_to_rag": fallback_to_rag, "default_risk_tier": "medium"},
        "risk_tiers": {
            "medium": {"max_retrieval_top_k": 3, "tools_enabled": True},
            "high": {"max_retrieval_top_k": 1, "tools_enabled": False},
        },
        "retrieval": {
            "allowed_tenants": ["tenant-a"],
            "tenant_allowed_sources": {"tenant-a": ["kb-main"]},
            "require_trust_metadata": True,
            "require_provenance": True,
            "allowed_trust_domains": ["internal"],
        },
        "tools": {
            "allowed_tools": ["ticket_lookup"],
            "forbidden_tools": ["admin_shell"],
            "confirmation_required_tools": [],
            "forbidden_fields_per_tool": {"ticket_lookup": ["ssn"]},
            "rate_limits_per_tool": {"ticket_lookup": 3},
        },
    }


def test_policy_mutation_allowed_tool_vs_denied_tool_changes_router_decision() -> None:
    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True), executor=lambda _: {"ok": True})

    allow_payload = _policy_payload()
    allow_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=allow_payload))
    allow_router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=allow_engine)

    deny_payload = _policy_payload()
    deny_payload["tools"]["allowed_tools"] = ["account_update"]
    deny_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=deny_payload))
    deny_router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=deny_engine)

    invocation = ToolInvocation(
        request_id="req-1",
        actor_id="user-1",
        tenant_id="tenant-a",
        tool_name="ticket_lookup",
        action="lookup",
        arguments={"ticket_id": "T-1"},
        confirmed=True,
    )

    assert allow_router.route(invocation).status == ALLOWED_DECISION
    assert deny_router.route(invocation).status == DENY_DECISION


def test_policy_mutation_confirmation_required_vs_direct_allow_changes_router_decision() -> None:
    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="account_update", description="update", allowed=True), executor=lambda _: {"ok": True})

    direct_payload = _policy_payload()
    direct_payload["tools"]["allowed_tools"] = ["account_update"]
    direct_payload["tools"]["forbidden_fields_per_tool"] = {"account_update": []}
    direct_payload["tools"]["rate_limits_per_tool"] = {"account_update": 3}
    direct_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=direct_payload))
    direct_router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=direct_engine)

    confirm_payload = _policy_payload()
    confirm_payload["tools"]["allowed_tools"] = ["account_update"]
    confirm_payload["tools"]["confirmation_required_tools"] = ["account_update"]
    confirm_payload["tools"]["forbidden_fields_per_tool"] = {"account_update": []}
    confirm_payload["tools"]["rate_limits_per_tool"] = {"account_update": 3}
    confirm_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=confirm_payload))
    confirm_router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=confirm_engine)

    invocation = ToolInvocation(
        request_id="req-2",
        actor_id="user-1",
        tenant_id="tenant-a",
        tool_name="account_update",
        action="update",
        arguments={"field": "email"},
        confirmed=False,
    )

    assert direct_router.route(invocation).status == ALLOWED_DECISION
    assert confirm_router.route(invocation).status == REQUIRE_CONFIRMATION_DECISION


def test_policy_mutation_retrieval_source_allowed_vs_denied_changes_results() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="KB", enabled=True))

    allowed_payload = _policy_payload()
    allowed_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=allowed_payload))
    allowed_service = SecureRetrievalService(source_registry=registry, raw_retriever=FakeRawRetriever(), policy_engine=allowed_engine)

    denied_payload = _policy_payload()
    denied_payload["retrieval"]["tenant_allowed_sources"] = {"tenant-a": ["kb-other"]}
    denied_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=denied_payload))
    denied_service = SecureRetrievalService(source_registry=registry, raw_retriever=FakeRawRetriever(), policy_engine=denied_engine)

    query = RetrievalQuery(
        request_id="req-3",
        tenant_id="tenant-a",
        query_text="reset",
        top_k=5,
        allowed_source_ids=("kb-main",),
    )

    assert len(allowed_service.search(query)) == 1
    assert denied_service.search(query) == ()


def test_policy_mutation_kill_switch_off_vs_on_changes_request_outcome() -> None:
    model = FakeModel()

    off_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=_policy_payload(kill_switch=False)))
    off_orchestrator = SupportAgentOrchestrator(
        policy_engine=off_engine,
        retriever=FakeRawRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=FakeDenyToolRouter(),
        audit_sink=FakeAuditSink(),
    )

    on_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=_policy_payload(kill_switch=True)))
    on_orchestrator = SupportAgentOrchestrator(
        policy_engine=on_engine,
        retriever=FakeRawRetriever(),
        model=FakeModel(),
        tool_registry=FakeToolRegistry(),
        tool_router=FakeDenyToolRouter(),
        audit_sink=FakeAuditSink(),
    )

    request = SupportAgentRequest(
        request_id="req-kill-toggle",
        user_text="help",
        session=SessionContext(session_id="s", actor_id="a", tenant_id="tenant-a", channel="chat"),
    )

    assert off_orchestrator.run(request).status == "ok"
    assert on_orchestrator.run(request).status == "blocked"


def test_policy_mutation_fallback_disabled_vs_enabled_changes_tools_route_behavior() -> None:
    fallback_enabled_payload = _policy_payload(fallback_to_rag=True)
    fallback_enabled_payload["risk_tiers"]["medium"]["tools_enabled"] = False
    fallback_enabled_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=fallback_enabled_payload))
    fallback_enabled_audit = FakeAuditSink()
    fallback_enabled_orchestrator = SupportAgentOrchestrator(
        policy_engine=fallback_enabled_engine,
        retriever=FakeRawRetriever(),
        model=FakeModel(),
        tool_registry=FakeToolRegistry(),
        tool_router=FakeDenyToolRouter(),
        audit_sink=fallback_enabled_audit,
    )

    fallback_disabled_payload = _policy_payload(fallback_to_rag=False)
    fallback_disabled_payload["risk_tiers"]["medium"]["tools_enabled"] = False
    fallback_disabled_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=fallback_disabled_payload))
    fallback_disabled_audit = FakeAuditSink()
    fallback_disabled_orchestrator = SupportAgentOrchestrator(
        policy_engine=fallback_disabled_engine,
        retriever=FakeRawRetriever(),
        model=FakeModel(),
        tool_registry=FakeToolRegistry(),
        tool_router=FakeDenyToolRouter(),
        audit_sink=fallback_disabled_audit,
    )

    request = SupportAgentRequest(
        request_id="req-fallback-toggle",
        user_text="help",
        session=SessionContext(session_id="s", actor_id="a", tenant_id="tenant-a", channel="chat"),
    )

    enabled_response = fallback_enabled_orchestrator.run(request)
    disabled_response = fallback_disabled_orchestrator.run(request)

    assert enabled_response.status == "ok"
    assert disabled_response.status == "blocked"

    enabled_events = [event.event_type for event in fallback_enabled_audit.events]
    disabled_events = [event.event_type for event in fallback_disabled_audit.events]
    assert "fallback.event" in enabled_events
    assert "fallback.event" not in disabled_events
    assert "deny.event" in disabled_events
