"""Audit telemetry package."""

from telemetry.audit.contracts import (
    CONFIRMATION_REQUIRED_EVENT,
    DENY_EVENT,
    ERROR_EVENT,
    FALLBACK_EVENT,
    POLICY_DECISION_EVENT,
    REQUEST_END_EVENT,
    REQUEST_START_EVENT,
    RETRIEVAL_DECISION_EVENT,
    TOOL_DECISION_EVENT,
    TOOL_EXECUTION_ATTEMPT_EVENT,
    AuditEvent,
    AuditSink,
)
from telemetry.audit.events import create_audit_event, generate_trace_id
from telemetry.audit.replay import (
    REPLAY_EVENT_COVERAGE_KEYS,
    ReplayArtifact,
    build_replay_artifact,
    validate_replay_completeness,
    write_replay_artifact,
)
from telemetry.audit.sinks import InMemoryAuditSink, JsonlAuditSink

__all__ = [
    "CONFIRMATION_REQUIRED_EVENT",
    "DENY_EVENT",
    "ERROR_EVENT",
    "FALLBACK_EVENT",
    "InMemoryAuditSink",
    "JsonlAuditSink",
    "POLICY_DECISION_EVENT",
    "REQUEST_END_EVENT",
    "REQUEST_START_EVENT",
    "RETRIEVAL_DECISION_EVENT",
    "REPLAY_EVENT_COVERAGE_KEYS",
    "ReplayArtifact",
    "TOOL_DECISION_EVENT",
    "TOOL_EXECUTION_ATTEMPT_EVENT",
    "AuditEvent",
    "AuditSink",
    "build_replay_artifact",
    "create_audit_event",
    "generate_trace_id",
    "validate_replay_completeness",
    "write_replay_artifact",
]
