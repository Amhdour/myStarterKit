"""Security-focused end-to-end orchestration coverage."""

from __future__ import annotations

from dataclasses import dataclass

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
from retrieval.service import RawRetriever, SecureRetrievalService
from telemetry.audit import (
    POLICY_DECISION_EVENT,
    REQUEST_END_EVENT,
    REQUEST_START_EVENT,
    RETRIEVAL_DECISION_EVENT,
    TOOL_DECISION_EVENT,
    build_replay_artifact,
    validate_replay_completeness,
)
from telemetry.audit.sinks import InMemoryAuditSink
from tools.contracts import ToolDescriptor
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


class DeterministicModel:
    def generate(self, model_input: ModelInput) -> str:
        return f"answer-for:{model_input.request_id}"


class DeterministicRawRetriever(RawRetriever):
    def search(self, query: RetrievalQuery):
        return (
            RetrievalDocument(
                document_id="doc-secure-1",
                content="Use verified reset flow.",
                trust=SourceTrustMetadata(
                    source_id="kb-main",
                    tenant_id=query.tenant_id,
                    checksum="sha256:doc-1",
                    ingested_at="2026-01-01T00:00:00Z",
                ),
                provenance=DocumentProvenance(
                    citation_id="cite-1",
                    source_id="kb-main",
                    document_uri="kb://security/reset",
                    chunk_id="chunk-1",
                ),
                attributes={"topic": "security"},
            ),
        )


@dataclass
class RuntimeFixture:
    orchestrator: SupportAgentOrchestrator
    audit_sink: InMemoryAuditSink


def _build_runtime_fixture(*, forbidden_tool_fields: list[str], allowed_tenants: list[str]) -> RuntimeFixture:
    policy = build_runtime_policy(
        environment="production",
        payload={
            "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "medium"},
            "risk_tiers": {"medium": {"max_retrieval_top_k": 3, "tools_enabled": True}},
            "retrieval": {
                "allowed_tenants": allowed_tenants,
                "tenant_allowed_sources": {tenant: ["kb-main"] for tenant in allowed_tenants},
                "require_trust_metadata": True,
                "require_provenance": True,
                "allowed_trust_domains": ["internal"],
            },
            "tools": {
                "allowed_tools": ["ticket_lookup"],
                "forbidden_tools": ["admin_shell"],
                "confirmation_required_tools": [],
                "forbidden_fields_per_tool": {"ticket_lookup": forbidden_tool_fields},
                "rate_limits_per_tool": {"ticket_lookup": 5},
            },
        },
    )
    policy_engine = RuntimePolicyEngine(policy=policy)

    source_registry = InMemorySourceRegistry()
    for tenant in allowed_tenants:
        source_registry.register(
            SourceRegistration(
                source_id="kb-main",
                tenant_id=tenant,
                display_name="Security KB",
                enabled=True,
                trust_domain="internal",
            )
        )

    retriever = SecureRetrievalService(
        source_registry=source_registry,
        raw_retriever=DeterministicRawRetriever(),
        policy_engine=policy_engine,
    )

    tool_registry = InMemoryToolRegistry()
    tool_registry.register(ToolDescriptor(name="ticket_lookup", description="Ticket metadata lookup", allowed=True))
    tool_router = SecureToolRouter(
        registry=tool_registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=policy_engine,
    )

    audit_sink = InMemoryAuditSink()
    orchestrator = SupportAgentOrchestrator(
        policy_engine=policy_engine,
        retriever=retriever,
        model=DeterministicModel(),
        tool_registry=tool_registry,
        tool_router=tool_router,
        audit_sink=audit_sink,
    )
    return RuntimeFixture(orchestrator=orchestrator, audit_sink=audit_sink)


def _run_request(fixture: RuntimeFixture, *, request_id: str, tenant_id: str) -> tuple:
    response = fixture.orchestrator.run(
        SupportAgentRequest(
            request_id=request_id,
            user_text="Reset password and validate account",
            session=SessionContext(session_id="sess-e2e", actor_id="actor-e2e", tenant_id=tenant_id, channel="chat"),
        )
    )
    events = tuple(fixture.audit_sink.events)
    return response, events


def test_e2e_allowed_tool_flow_through_runtime_paths(monkeypatch) -> None:
    fixture = _build_runtime_fixture(forbidden_tool_fields=[], allowed_tenants=["tenant-a"])
    monkeypatch.setattr("app.orchestrator.generate_trace_id", lambda: "trace-e2e-allow")

    response, events = _run_request(fixture, request_id="req-e2e-allow", tenant_id="tenant-a")

    assert response.status == "ok"
    assert len(response.retrieved_documents) == 1
    assert [decision.status for decision in response.tool_decisions] == ["allow"]
    event_types = [event.event_type for event in events]
    assert REQUEST_START_EVENT in event_types
    assert POLICY_DECISION_EVENT in event_types
    assert RETRIEVAL_DECISION_EVENT in event_types
    assert TOOL_DECISION_EVENT in event_types
    assert REQUEST_END_EVENT in event_types


def test_e2e_guarded_tool_flow_denies_forbidden_argument(monkeypatch) -> None:
    fixture = _build_runtime_fixture(forbidden_tool_fields=["draft_answer_preview_length"], allowed_tenants=["tenant-a"])
    monkeypatch.setattr("app.orchestrator.generate_trace_id", lambda: "trace-e2e-deny-tool")

    response, events = _run_request(fixture, request_id="req-e2e-deny-tool", tenant_id="tenant-a")

    assert response.status == "ok"
    assert [decision.status for decision in response.tool_decisions] == ["deny"]
    deny_events = [event for event in events if event.event_type == "deny.event"]
    assert deny_events
    assert deny_events[0].event_payload["stage"] == "tool.route"


def test_e2e_retrieval_boundary_blocks_disallowed_tenant(monkeypatch) -> None:
    fixture = _build_runtime_fixture(forbidden_tool_fields=[], allowed_tenants=["tenant-a"])
    monkeypatch.setattr("app.orchestrator.generate_trace_id", lambda: "trace-e2e-tenant-block")

    response, events = _run_request(fixture, request_id="req-e2e-tenant-block", tenant_id="tenant-b")

    assert response.status == "blocked"
    assert response.retrieved_documents == ()
    deny_events = [event for event in events if event.event_type == "deny.event"]
    assert deny_events
    assert deny_events[0].event_payload["stage"] == "retrieval"


def test_e2e_generates_replayable_telemetry_from_runtime_flow(monkeypatch) -> None:
    fixture = _build_runtime_fixture(forbidden_tool_fields=[], allowed_tenants=["tenant-a"])
    monkeypatch.setattr("app.orchestrator.generate_trace_id", lambda: "trace-e2e-replay")

    _, events = _run_request(fixture, request_id="req-e2e-replay", tenant_id="tenant-a")

    artifact = build_replay_artifact(events)
    complete, missing = validate_replay_completeness(
        artifact,
        required_event_types=(
            REQUEST_START_EVENT,
            REQUEST_END_EVENT,
            POLICY_DECISION_EVENT,
            RETRIEVAL_DECISION_EVENT,
            TOOL_DECISION_EVENT,
        ),
    )

    assert complete is True
    assert missing == ()
    assert artifact.coverage["request_lifecycle_complete"] is True
    assert artifact.coverage["decision_replay_core_complete"] is True
