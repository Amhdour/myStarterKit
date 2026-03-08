"""Tests proving policy governs runtime behavior and fails safely."""

from app.models import SessionContext, SupportAgentRequest
from app.orchestrator import SupportAgentOrchestrator
from app.modeling import ModelInput
from policies.engine import RuntimePolicyEngine
from policies.loader import load_policy
from policies.schema import build_runtime_policy
from retrieval.contracts import DocumentProvenance, RetrievalDocument, RetrievalQuery, SourceRegistration, SourceTrustMetadata
from retrieval.registry import InMemorySourceRegistry
from retrieval.service import SecureRetrievalService
from tools.contracts import DENY_DECISION, REQUIRE_CONFIRMATION_DECISION, ToolDescriptor, ToolInvocation
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


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
            "forbidden_tools": ["payments_export"],
            "confirmation_required_tools": ["account_update"],
            "forbidden_fields_per_tool": {"ticket_lookup": ["ssn"]},
            "rate_limits_per_tool": {"ticket_lookup": 1},
        },
    }


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
    def list_allowlisted(self):
        return (ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),)


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


def test_invalid_policy_safe_fail(tmp_path) -> None:
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("{ not-json")

    loaded = load_policy(invalid_file, environment="development")

    assert loaded.valid is False
    assert loaded.kill_switch is True


def test_missing_policy_safe_fail(tmp_path) -> None:
    loaded = load_policy(tmp_path / "missing.json", environment="development")

    assert loaded.valid is False
    assert loaded.kill_switch is True


def test_retrieval_denial_by_policy() -> None:
    payload = _policy_payload()
    payload["retrieval"]["allowed_tenants"] = ["tenant-b"]
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=payload))

    decision = engine.evaluate("req-1", "retrieval.search", {"tenant_id": "tenant-a"})

    assert decision.allow is False
    assert "tenant" in decision.reason


def test_tool_denial_by_policy() -> None:
    policy = build_runtime_policy(environment="dev", payload=_policy_payload())
    engine = RuntimePolicyEngine(policy=policy)

    decision = engine.evaluate(
        "req-1",
        "tools.invoke",
        {"tenant_id": "tenant-a", "tool_name": "payments_export", "action": "export", "arguments": {}},
    )

    assert decision.allow is False
    assert "forbidden" in decision.reason


def test_policy_changes_tool_runtime_behavior() -> None:
    registry = InMemoryToolRegistry()
    registry.register(ToolDescriptor(name="account_update", description="update", allowed=True), executor=lambda _: {"ok": True})

    restrictive_payload = _policy_payload()
    restrictive_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=restrictive_payload))
    restrictive_router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=restrictive_engine)

    permissive_payload = _policy_payload()
    permissive_payload["tools"]["allowed_tools"] = ["account_update"]
    permissive_payload["tools"]["confirmation_required_tools"] = ["account_update"]
    permissive_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=permissive_payload))
    permissive_router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=permissive_engine)

    invocation = ToolInvocation(
        request_id="req-1",
        actor_id="user-1",
        tenant_id="tenant-a",
        tool_name="account_update",
        action="update",
        arguments={"field": "email"},
        confirmed=False,
    )

    denied = restrictive_router.route(invocation)
    confirmation_required = permissive_router.route(invocation)

    assert denied.status == DENY_DECISION
    assert confirmation_required.status == REQUIRE_CONFIRMATION_DECISION


def test_policy_changes_retrieval_runtime_behavior() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="kb", enabled=True))

    restrictive_payload = _policy_payload()
    restrictive_payload["retrieval"]["tenant_allowed_sources"] = {"tenant-a": ["kb-other"]}
    restrictive_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=restrictive_payload))

    permissive_payload = _policy_payload()
    permissive_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=permissive_payload))

    query = RetrievalQuery(
        request_id="req-1",
        tenant_id="tenant-a",
        query_text="reset",
        top_k=5,
        allowed_source_ids=("kb-main",),
    )

    denied_service = SecureRetrievalService(source_registry=registry, raw_retriever=FakeRawRetriever(), policy_engine=restrictive_engine)
    allowed_service = SecureRetrievalService(source_registry=registry, raw_retriever=FakeRawRetriever(), policy_engine=permissive_engine)

    assert denied_service.search(query) == ()
    assert len(allowed_service.search(query)) == 1


def test_retrieval_metadata_requirements_are_fail_closed_even_when_policy_relaxes_them() -> None:
    class MissingTrustRawRetriever:
        def search(self, query: RetrievalQuery):
            return (
                RetrievalDocument(
                    document_id="doc-1",
                    content="KB answer",
                    trust=SourceTrustMetadata(
                        source_id="kb-main",
                        tenant_id=query.tenant_id,
                        checksum="",
                        ingested_at="",
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

    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="kb", enabled=True))

    relaxed_payload = _policy_payload()
    relaxed_payload["retrieval"]["require_trust_metadata"] = False
    relaxed_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=relaxed_payload))

    query = RetrievalQuery(
        request_id="req-1",
        tenant_id="tenant-a",
        query_text="reset",
        top_k=5,
        allowed_source_ids=("kb-main",),
    )

    relaxed_service = SecureRetrievalService(source_registry=registry, raw_retriever=MissingTrustRawRetriever(), policy_engine=relaxed_engine)

    assert relaxed_service.search(query) == ()


def test_tools_invoke_denied_when_risk_tier_disables_tools() -> None:
    payload = _policy_payload()
    payload["risk_tiers"]["high"]["tools_enabled"] = False
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=payload))

    decision = engine.evaluate(
        "req-1",
        "tools.invoke",
        {
            "tenant_id": "tenant-a",
            "tool_name": "ticket_lookup",
            "action": "lookup",
            "arguments": {},
            "risk_tier": "high",
        },
    )

    assert decision.allow is False
    assert "tools disabled for risk tier" in decision.reason


def test_kill_switch_behavior_blocks_request() -> None:
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=_policy_payload(kill_switch=True)))
    model = FakeModel()
    audit = FakeAuditSink()

    orchestrator = SupportAgentOrchestrator(
        policy_engine=engine,
        retriever=FakeRawRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=FakeDenyToolRouter(),
        audit_sink=audit,
    )

    response = orchestrator.run(
        SupportAgentRequest(
            request_id="req-kill",
            user_text="help",
            session=SessionContext(session_id="s", actor_id="a", tenant_id="tenant-a", channel="chat"),
        )
    )

    assert response.status == "blocked"
    assert model.inputs == []


def test_fallback_to_rag_activation() -> None:
    payload = _policy_payload(fallback_to_rag=True)
    payload["risk_tiers"]["medium"]["tools_enabled"] = False
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=payload))
    model = FakeModel()
    audit = FakeAuditSink()

    orchestrator = SupportAgentOrchestrator(
        policy_engine=engine,
        retriever=FakeRawRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=FakeDenyToolRouter(),
        audit_sink=audit,
    )

    response = orchestrator.run(
        SupportAgentRequest(
            request_id="req-fallback",
            user_text="help",
            session=SessionContext(session_id="s", actor_id="a", tenant_id="tenant-a", channel="chat"),
        )
    )

    assert response.status == "ok"
    assert response.tool_decisions == ()
    assert any(event.event_type == "fallback.event" for event in audit.events)


def test_missing_policy_loaded_into_runtime_denies_retrieval_and_tools(tmp_path) -> None:
    runtime_policy = load_policy(tmp_path / "missing-policy.json", environment="development")
    engine = RuntimePolicyEngine(policy=runtime_policy)

    retrieval_decision = engine.evaluate("req-missing", "retrieval.search", {"tenant_id": "tenant-a"})
    tool_decision = engine.evaluate(
        "req-missing",
        "tools.invoke",
        {"tenant_id": "tenant-a", "tool_name": "ticket_lookup", "action": "lookup", "arguments": {}},
    )

    assert retrieval_decision.allow is False
    assert tool_decision.allow is False
    assert "invalid policy" in retrieval_decision.reason


def test_invalid_policy_loaded_into_runtime_denies_retrieval_and_tools(tmp_path) -> None:
    invalid_file = tmp_path / "invalid-policy.json"
    invalid_file.write_text("{not-json")

    runtime_policy = load_policy(invalid_file, environment="development")
    engine = RuntimePolicyEngine(policy=runtime_policy)

    retrieval_decision = engine.evaluate("req-invalid", "retrieval.search", {"tenant_id": "tenant-a"})
    tool_decision = engine.evaluate(
        "req-invalid",
        "tools.invoke",
        {"tenant_id": "tenant-a", "tool_name": "ticket_lookup", "action": "lookup", "arguments": {}},
    )

    assert retrieval_decision.allow is False
    assert tool_decision.allow is False
    assert "invalid policy" in retrieval_decision.reason
