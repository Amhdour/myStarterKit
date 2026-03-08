"""Tests for trace generation, audit events, denied logging, and replay artifacts."""

import json

from app.modeling import ModelInput
from app.models import SessionContext, SupportAgentRequest
from app.orchestrator import SupportAgentOrchestrator
from policies.contracts import PolicyDecision
from retrieval.contracts import DocumentProvenance, RetrievalDocument, SourceTrustMetadata
from telemetry.audit import (
    DENY_EVENT,
    REQUEST_END_EVENT,
    REQUEST_START_EVENT,
    build_replay_artifact,
    create_audit_event,
    generate_trace_id,
    validate_replay_completeness,
    write_replay_artifact,
)
from telemetry.audit.sinks import InMemoryAuditSink, JsonlAuditSink
from tools.contracts import ToolDescriptor


class DenyRetrievalPolicyEngine:
    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        if action == "retrieval.search":
            return PolicyDecision(request_id=request_id, allow=False, reason="retrieval denied")
        return PolicyDecision(request_id=request_id, allow=True, reason="ok")


class FakeRetriever:
    def search(self, query):
        return (
            RetrievalDocument(
                document_id="doc-1",
                content="Reset via profile page.",
                trust=SourceTrustMetadata(
                    source_id="kb",
                    tenant_id="tenant-a",
                    checksum="hash-1",
                    ingested_at="2026-01-01T00:00:00Z",
                ),
                provenance=DocumentProvenance(
                    citation_id="cite-1",
                    source_id="kb",
                    document_uri="kb://reset",
                    chunk_id="chunk-1",
                ),
                attributes={"topic": "password"},
            ),
        )


class FakeModel:
    def __init__(self) -> None:
        self.inputs: list[ModelInput] = []

    def generate(self, model_input: ModelInput) -> str:
        self.inputs.append(model_input)
        return "answer"


class FakeToolRegistry:
    def list_allowlisted(self):
        return (ToolDescriptor(name="ticket_lookup", description="Lookup", allowed=True),)


class FakeToolRouter:
    def route(self, invocation):
        from tools.contracts import ToolDecision

        return ToolDecision(
            status="allow",
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="ok",
            sanitized_arguments={},
        )


def test_trace_generation_unique() -> None:
    trace_1 = generate_trace_id()
    trace_2 = generate_trace_id()

    assert trace_1.startswith("trace-")
    assert trace_2.startswith("trace-")
    assert trace_1 != trace_2


def test_event_creation_and_jsonl_output(tmp_path) -> None:
    event = create_audit_event(
        trace_id="trace-1",
        request_id="req-1",
        actor_id="actor-1",
        tenant_id="tenant-a",
        event_type=REQUEST_START_EVENT,
        payload={"channel": "chat"},
    )
    sink = JsonlAuditSink(output_path=tmp_path / "audit.jsonl")
    sink.emit(event)

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["trace_id"] == "trace-1"
    assert parsed["event_type"] == REQUEST_START_EVENT


def test_denied_action_logging_present() -> None:
    sink = InMemoryAuditSink()
    orchestrator = SupportAgentOrchestrator(
        policy_engine=DenyRetrievalPolicyEngine(),
        retriever=FakeRetriever(),
        model=FakeModel(),
        tool_registry=FakeToolRegistry(),
        tool_router=FakeToolRouter(),
        audit_sink=sink,
    )

    response = orchestrator.run(
        SupportAgentRequest(
            request_id="req-deny",
            user_text="help",
            session=SessionContext(session_id="s1", actor_id="a1", tenant_id="tenant-a"),
        )
    )

    assert response.status == "blocked"
    event_types = [event.event_type for event in sink.events]
    assert DENY_EVENT in event_types
    assert REQUEST_END_EVENT in event_types


def test_replay_artifact_completeness(tmp_path) -> None:
    sink = InMemoryAuditSink()
    trace_id = "trace-replay"
    sink.emit(
        create_audit_event(
            trace_id=trace_id,
            request_id="req-1",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=REQUEST_START_EVENT,
            payload={"session_id": "s1"},
        )
    )
    sink.emit(
        create_audit_event(
            trace_id=trace_id,
            request_id="req-1",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=REQUEST_END_EVENT,
            payload={"status": "ok"},
        )
    )

    artifact = build_replay_artifact(sink.events)
    out = tmp_path / "replay.json"
    write_replay_artifact(artifact, out)

    parsed = json.loads(out.read_text())
    assert parsed["replay_version"] == "1"
    assert parsed["trace_id"] == trace_id
    assert parsed["request_id"] == "req-1"
    assert parsed["coverage"]["request.start"] is True
    assert parsed["coverage"]["request.end"] is True
    assert parsed["event_type_counts"]["request.start"] == 1
    assert parsed["decision_summary"]["request_lifecycle"]["start_seen"] is True
    assert parsed["decision_summary"]["request_lifecycle"]["end_seen"] is True
    assert parsed["decision_summary"]["policy_decisions"] == []
    assert len(parsed["timeline"]) == 2
    assert parsed["timeline"][0]["event_type"] == REQUEST_START_EVENT
    assert parsed["timeline"][1]["event_type"] == REQUEST_END_EVENT


def test_replay_completeness_validation_reports_missing_events() -> None:
    sink = InMemoryAuditSink()
    sink.emit(
        create_audit_event(
            trace_id="trace-1",
            request_id="req-1",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=REQUEST_START_EVENT,
            payload={},
        )
    )

    artifact = build_replay_artifact(sink.events)
    complete, missing = validate_replay_completeness(
        artifact,
        required_event_types=(REQUEST_START_EVENT, REQUEST_END_EVENT),
    )

    assert complete is False
    assert missing == (REQUEST_END_EVENT,)


def test_replay_artifact_decision_summary_includes_policy_retrieval_tool_deny_fallback() -> None:
    sink = InMemoryAuditSink()
    trace_id = "trace-2"
    request_id = "req-2"
    for event_type, payload in (
        (REQUEST_START_EVENT, {"session_id": "s2"}),
        ("policy.decision", {"action": "retrieval.search", "allow": True, "reason": "ok", "risk_tier": "low"}),
        ("retrieval.decision", {"document_count": 1, "top_k": 1, "allowed_source_ids": ["kb-main"]}),
        ("tool.decision", {"decisions": ["deny"]}),
        (DENY_EVENT, {"stage": "tool.route", "tool_name": "ticket_lookup", "reason": "denied"}),
        ("fallback.event", {"mode": "rag_only", "reason": "tools disabled"}),
        (REQUEST_END_EVENT, {"status": "ok"}),
    ):
        sink.emit(
            create_audit_event(
                trace_id=trace_id,
                request_id=request_id,
                actor_id="actor-1",
                tenant_id="tenant-a",
                event_type=event_type,
                payload=payload,
            )
        )

    artifact = build_replay_artifact(sink.events)

    summary = artifact.decision_summary
    assert summary["request_lifecycle"]["start_seen"] is True
    assert summary["request_lifecycle"]["end_seen"] is True
    assert summary["policy_decisions"][0]["action"] == "retrieval.search"
    assert summary["retrieval_decisions"][0]["document_count"] == 1
    assert summary["tool_decisions"][0]["decisions"] == ["deny"]
    assert summary["deny_events"][0]["stage"] == "tool.route"
    assert summary["fallback_events"][0]["mode"] == "rag_only"


def test_replay_artifact_sets_lifecycle_and_core_decision_coverage_flags() -> None:
    sink = InMemoryAuditSink()
    trace_id = "trace-coverage"
    for event_type, payload in (
        (REQUEST_START_EVENT, {"session_id": "s1"}),
        ("policy.decision", {"action": "retrieval.search", "allow": True, "reason": "ok", "risk_tier": "low"}),
        ("retrieval.decision", {"document_count": 1, "top_k": 1, "allowed_source_ids": ["kb-main"]}),
        ("tool.decision", {"decisions": ["allow"]}),
        (REQUEST_END_EVENT, {"status": "ok"}),
    ):
        sink.emit(
            create_audit_event(
                trace_id=trace_id,
                request_id="req-coverage",
                actor_id="actor-1",
                tenant_id="tenant-a",
                event_type=event_type,
                payload=payload,
            )
        )

    artifact = build_replay_artifact(sink.events)

    assert artifact.coverage["request_lifecycle_complete"] is True
    assert artifact.coverage["decision_replay_core_complete"] is True


def test_replay_artifact_redacts_sensitive_payload_fields() -> None:
    sink = InMemoryAuditSink()
    sink.emit(
        create_audit_event(
            trace_id="trace-redact",
            request_id="req-redact",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=DENY_EVENT,
            payload={"stage": "tool.route", "raw_password": "topsecret", "ssn": "123-45-6789"},
        )
    )

    artifact = build_replay_artifact(sink.events)
    timeline_payload = artifact.timeline[0]["payload"]

    assert timeline_payload["raw_password"] == "[redacted]"
    assert timeline_payload["ssn"] == "[redacted]"
