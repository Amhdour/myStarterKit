"""Replay artifact generation from audit event streams."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from telemetry.audit.contracts import (
    DENY_EVENT,
    FALLBACK_EVENT,
    POLICY_DECISION_EVENT,
    REQUEST_END_EVENT,
    REQUEST_START_EVENT,
    RETRIEVAL_DECISION_EVENT,
    TOOL_DECISION_EVENT,
    AuditEvent,
)


REPLAY_EVENT_COVERAGE_KEYS = (
    REQUEST_START_EVENT,
    REQUEST_END_EVENT,
    POLICY_DECISION_EVENT,
    RETRIEVAL_DECISION_EVENT,
    TOOL_DECISION_EVENT,
    DENY_EVENT,
    FALLBACK_EVENT,
)


@dataclass(frozen=True)
class ReplayArtifact:
    """Replay-friendly execution artifact."""

    trace_id: str
    request_id: str
    actor_id: str
    tenant_id: str
    timeline: tuple[dict, ...]
    event_type_counts: Mapping[str, int] = field(default_factory=dict)
    coverage: Mapping[str, bool] = field(default_factory=dict)
    decision_summary: Mapping[str, object] = field(default_factory=dict)


def build_replay_artifact(events: Sequence[AuditEvent]) -> ReplayArtifact:
    if not events:
        raise ValueError("cannot build replay artifact from empty event list")

    ordered = tuple(sorted(events, key=lambda item: item.created_at))
    first = ordered[0]

    trace_ids = {event.trace_id for event in ordered}
    if len(trace_ids) > 1:
        raise ValueError(f"replay artifact requires single trace; found {len(trace_ids)} distinct trace_ids")

    event_type_counts: dict[str, int] = {}
    timeline = []
    for event in ordered:
        event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
        timeline.append(
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "created_at": event.created_at,
                "payload": dict(event.event_payload),
            }
        )

    coverage = {event_type: (event_type_counts.get(event_type, 0) > 0) for event_type in REPLAY_EVENT_COVERAGE_KEYS}

    return ReplayArtifact(
        trace_id=first.trace_id,
        request_id=first.request_id,
        actor_id=first.actor_id,
        tenant_id=first.tenant_id,
        timeline=tuple(timeline),
        event_type_counts=event_type_counts,
        coverage=coverage,
        decision_summary=_build_decision_summary(ordered),
    )


def validate_replay_completeness(
    artifact: ReplayArtifact,
    *,
    required_event_types: Sequence[str],
) -> tuple[bool, tuple[str, ...]]:
    missing = tuple(event_type for event_type in required_event_types if artifact.event_type_counts.get(event_type, 0) == 0)
    return len(missing) == 0, missing


def write_replay_artifact(artifact: ReplayArtifact, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "replay_version": "1",
                "trace_id": artifact.trace_id,
                "request_id": artifact.request_id,
                "actor_id": artifact.actor_id,
                "tenant_id": artifact.tenant_id,
                "event_type_counts": dict(artifact.event_type_counts),
                "coverage": dict(artifact.coverage),
                "decision_summary": dict(artifact.decision_summary),
                "timeline": list(artifact.timeline),
            },
            sort_keys=True,
            indent=2,
        )
    )


def _build_decision_summary(events: Sequence[AuditEvent]) -> Mapping[str, object]:
    policy_decisions: list[dict[str, object]] = []
    retrieval_decisions: list[dict[str, object]] = []
    tool_decisions: list[dict[str, object]] = []
    deny_events: list[dict[str, object]] = []
    fallback_events: list[dict[str, object]] = []

    request_start = False
    request_end = False

    for event in events:
        payload = dict(event.event_payload)
        if event.event_type == REQUEST_START_EVENT:
            request_start = True
        elif event.event_type == REQUEST_END_EVENT:
            request_end = True
        elif event.event_type == POLICY_DECISION_EVENT:
            policy_decisions.append(
                {
                    "action": payload.get("action"),
                    "allow": payload.get("allow"),
                    "reason": payload.get("reason"),
                    "risk_tier": payload.get("risk_tier"),
                }
            )
        elif event.event_type == RETRIEVAL_DECISION_EVENT:
            retrieval_decisions.append(
                {
                    "document_count": payload.get("document_count"),
                    "top_k": payload.get("top_k"),
                    "allowed_source_ids": payload.get("allowed_source_ids"),
                }
            )
        elif event.event_type == TOOL_DECISION_EVENT:
            tool_decisions.append(
                {
                    "decisions": payload.get("decisions", []),
                }
            )
        elif event.event_type == DENY_EVENT:
            deny_events.append(
                {
                    "stage": payload.get("stage"),
                    "tool_name": payload.get("tool_name"),
                    "reason": payload.get("reason"),
                }
            )
        elif event.event_type == FALLBACK_EVENT:
            fallback_events.append(
                {
                    "mode": payload.get("mode"),
                    "reason": payload.get("reason"),
                }
            )

    return {
        "request_lifecycle": {
            "start_seen": request_start,
            "end_seen": request_end,
        },
        "policy_decisions": policy_decisions,
        "retrieval_decisions": retrieval_decisions,
        "tool_decisions": tool_decisions,
        "deny_events": deny_events,
        "fallback_events": fallback_events,
    }
