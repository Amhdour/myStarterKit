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
                "timeline": list(artifact.timeline),
            },
            sort_keys=True,
            indent=2,
        )
    )
