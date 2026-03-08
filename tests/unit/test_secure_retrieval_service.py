"""Tests for secure retrieval tenant/source boundaries and metadata enforcement."""

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


class FakeRawRetriever:
    def __init__(self, documents):
        self.documents = tuple(documents)

    def search(self, query: RetrievalQuery):
        return self.documents


def _make_document(
    *,
    doc_id: str,
    source_id: str,
    tenant_id: str,
    checksum: str = "abc123",
    citation_id: str = "c1",
) -> RetrievalDocument:
    return RetrievalDocument(
        document_id=doc_id,
        content="Support content",
        trust=SourceTrustMetadata(
            source_id=source_id,
            tenant_id=tenant_id,
            checksum=checksum,
            ingested_at="2026-01-01T00:00:00Z",
        ),
        provenance=DocumentProvenance(
            citation_id=citation_id,
            source_id=source_id,
            document_uri="kb://password-reset",
            chunk_id="chunk-1",
        ),
        attributes={"topic": "auth"},
    )


def _query(*, tenant_id: str, allowed_source_ids=()) -> RetrievalQuery:
    return RetrievalQuery(
        request_id="req-1",
        tenant_id=tenant_id,
        query_text="password reset",
        top_k=5,
        allowed_source_ids=allowed_source_ids,
    )


def _policy_payload(*, trust_domains: list[str] | None = None) -> dict:
    return {
        "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "medium"},
        "risk_tiers": {"medium": {"max_retrieval_top_k": 3, "tools_enabled": True}},
        "retrieval": {
            "allowed_tenants": ["tenant-a"],
            "tenant_allowed_sources": {"tenant-a": ["kb-main", "kb-ext"]},
            "require_trust_metadata": True,
            "require_provenance": True,
            "allowed_trust_domains": trust_domains or ["internal"],
        },
        "tools": {"allowed_tools": ["ticket_lookup"]},
    }




def _policy_engine(*, trust_domains: list[str] | None = None):
    return RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=_policy_payload(trust_domains=trust_domains)))

def test_allowed_in_boundary_retrieval() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")]),
        policy_engine=_policy_engine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert len(results) == 1
    assert results[0].document_id == "d1"


def test_cross_tenant_denial() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-b", display_name="Main KB", enabled=True))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-b")]),
        policy_engine=_policy_engine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_unknown_source_denial() -> None:
    registry = InMemorySourceRegistry()
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-unknown", tenant_id="tenant-a")]),
        policy_engine=_policy_engine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-unknown",)))

    assert results == ()


def test_request_with_mixed_authorized_and_unauthorized_sources_fails_closed() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")]),
        policy_engine=_policy_engine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main", "kb-unknown")))

    assert results == ()


def test_missing_metadata_safe_fail() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a", checksum="")]),
        policy_engine=_policy_engine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_invalid_source_registration_metadata_safe_fails() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(
            source_id="kb-main",
            tenant_id="tenant-a",
            display_name="",
            enabled=True,
            trust_domain="internal",
        )
    )
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")]),
        policy_engine=_policy_engine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_policy_source_allowlist_rejects_unauthorized_requested_source() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    registry.register(SourceRegistration(source_id="kb-ext", tenant_id="tenant-a", display_name="External", enabled=True))
    policy_payload = _policy_payload()
    policy_payload["retrieval"]["tenant_allowed_sources"] = {"tenant-a": ["kb-main"]}
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=policy_payload))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")]),
        policy_engine=engine,
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main", "kb-ext")))

    assert results == ()


def test_low_trust_source_denied_by_default_policy() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(
            source_id="kb-ext",
            tenant_id="tenant-a",
            display_name="External",
            enabled=True,
            trust_domain="external",
        )
    )
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=_policy_payload()))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-ext", tenant_id="tenant-a")]),
        policy_engine=engine,
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-ext",)))

    assert results == ()


def test_low_trust_source_can_be_allowed_by_policy() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(
            source_id="kb-ext",
            tenant_id="tenant-a",
            display_name="External",
            enabled=True,
            trust_domain="external",
        )
    )
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=_policy_payload(trust_domains=["internal", "external"])))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-ext", tenant_id="tenant-a")]),
        policy_engine=engine,
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-ext",)))

    assert len(results) == 1


def test_provenance_presence_on_valid_results() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a", citation_id="cite-1")]),
        policy_engine=_policy_engine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert len(results) == 1
    assert results[0].provenance.citation_id == "cite-1"
    assert results[0].provenance.document_uri
    assert results[0].provenance.chunk_id


def test_retrieval_fails_closed_without_policy_engine() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")]),
        policy_engine=None,
    )

    assert service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",))) == ()


def test_policy_cannot_disable_trust_metadata_requirement() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    payload = _policy_payload()
    payload["retrieval"]["require_trust_metadata"] = False
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=payload))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a", checksum="")]),
        policy_engine=engine,
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_policy_cannot_disable_provenance_requirement() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    payload = _policy_payload()
    payload["retrieval"]["require_provenance"] = False
    engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=payload))
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a", citation_id="")]),
        policy_engine=engine,
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()
