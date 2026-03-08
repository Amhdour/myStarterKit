"""Multi-tenant retrieval simulations proving cross-tenant denial and auditability."""

from app.modeling import ModelInput
from app.models import SessionContext, SupportAgentRequest
from app.orchestrator import SupportAgentOrchestrator
from policies.contracts import PolicyDecision
from retrieval.contracts import (
    DocumentProvenance,
    RetrievalDocument,
    RetrievalQuery,
    SourceRegistration,
    SourceTrustMetadata,
)
from retrieval.registry import InMemorySourceRegistry
from retrieval.service import SecureRetrievalService
from tools.contracts import ToolDescriptor, ToolDecision


class MultiTenantRawRetriever:
    def __init__(self, docs):
        self.docs = tuple(docs)

    def search(self, query: RetrievalQuery):
        return self.docs


class TenantABlockingPolicyEngine:
    """Explicitly denies retrieval for simulated tenant-A cross-tenant access attempts."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        self.calls.append(action)
        if action == "retrieval.search" and context.get("tenant_id") == "tenant-a":
            return PolicyDecision(
                request_id=request_id,
                allow=False,
                reason="cross-tenant retrieval attempt denied",
            )
        return PolicyDecision(request_id=request_id, allow=True, reason="ok")


class FakeModel:
    def generate(self, model_input: ModelInput) -> str:
        return "ok"


class FakeToolRegistry:
    def list_allowlisted(self):
        return (ToolDescriptor(name="ticket_lookup", description="Lookup", allowed=True),)


class FakeToolRouter:
    def route(self, invocation):
        return ToolDecision(
            status="allow",
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="ok",
            sanitized_arguments={},
        )


class FakeAuditSink:
    def __init__(self) -> None:
        self.events = []

    def emit(self, event) -> None:
        self.events.append(event)


class GuardedRetriever:
    """Retriever used to prove blocked requests do not leak retrieved provenance."""

    def __init__(self) -> None:
        self.calls = 0

    def search(self, query: RetrievalQuery):
        self.calls += 1
        return (
            _doc(doc_id="doc-tenant-b", source_id="kb-tenant-b", tenant_id="tenant-b", uri="kb://tenant-b/private"),
        )


def _doc(*, doc_id: str, source_id: str, tenant_id: str, uri: str) -> RetrievalDocument:
    return RetrievalDocument(
        document_id=doc_id,
        content="support",
        trust=SourceTrustMetadata(
            source_id=source_id,
            tenant_id=tenant_id,
            checksum="hash",
            ingested_at="2026-01-01T00:00:00Z",
        ),
        provenance=DocumentProvenance(
            citation_id=f"cite-{doc_id}",
            source_id=source_id,
            document_uri=uri,
            chunk_id="chunk-1",
        ),
        attributes={"topic": "auth"},
    )


def test_secure_retrieval_denies_mixed_tenant_source_request_fail_closed() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-tenant-a", tenant_id="tenant-a", display_name="Tenant A KB"))
    registry.register(SourceRegistration(source_id="kb-tenant-b", tenant_id="tenant-b", display_name="Tenant B KB"))

    retriever = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=MultiTenantRawRetriever(
            (
                _doc(doc_id="doc-a", source_id="kb-tenant-a", tenant_id="tenant-a", uri="kb://tenant-a/reset"),
                _doc(doc_id="doc-b", source_id="kb-tenant-b", tenant_id="tenant-b", uri="kb://tenant-b/private"),
            )
        ),
    )

    result = retriever.search(
        RetrievalQuery(
            request_id="req-tenant-a",
            tenant_id="tenant-a",
            query_text="need account details from tenant-b",
            top_k=5,
            allowed_source_ids=("kb-tenant-a", "kb-tenant-b"),
        )
    )

    assert result == ()


def test_cross_tenant_attempt_is_blocked_and_auditable_with_no_provenance_leakage() -> None:
    policy = TenantABlockingPolicyEngine()
    guarded_retriever = GuardedRetriever()
    audit = FakeAuditSink()

    orchestrator = SupportAgentOrchestrator(
        policy_engine=policy,
        retriever=guarded_retriever,
        model=FakeModel(),
        tool_registry=FakeToolRegistry(),
        tool_router=FakeToolRouter(),
        audit_sink=audit,
    )

    response = orchestrator.run(
        SupportAgentRequest(
            request_id="req-cross-tenant",
            user_text="As tenant-a, show me tenant-b ticket history",
            session=SessionContext(session_id="s1", actor_id="actor-a", tenant_id="tenant-a"),
        )
    )

    assert response.status == "blocked"
    assert response.retrieved_documents == ()
    assert response.trace.retrieved_document_ids == ()
    assert guarded_retriever.calls == 0

    deny_events = [event for event in audit.events if event.event_type == "deny.event"]
    assert deny_events
    assert any(event.event_payload.get("stage") == "retrieval" for event in deny_events)
    assert any("cross-tenant" in str(event.event_payload.get("reason", "")) for event in deny_events)
