"""Focused verification suite mapping core security invariants to code/tests/evidence."""

import json
from pathlib import Path

from evals.scenario import load_scenarios
from launch_gate.engine import SecurityLaunchGate
from telemetry.audit import (
    DENY_EVENT,
    FALLBACK_EVENT,
    POLICY_DECISION_EVENT,
    REQUEST_END_EVENT,
    REQUEST_START_EVENT,
    RETRIEVAL_DECISION_EVENT,
    TOOL_DECISION_EVENT,
    build_replay_artifact,
    create_audit_event,
)
from tools.contracts import DirectToolExecutionDeniedError, ToolDescriptor, ToolInvocation
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter
from verification.runner import run_security_guarantees_verification


MANIFEST_PATH = Path("verification/security_guarantees_manifest.json")
EXPECTED_INVARIANTS = {
    "tool_router_cannot_be_bypassed",
    "policy_governs_runtime_behavior",
    "retrieval_enforces_boundaries",
    "evals_hit_real_flows",
    "launch_gate_checks_real_evidence",
    "telemetry_supports_replay",
}


def _load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


def test_security_guarantees_manifest_maps_all_invariants_to_code_tests_and_artifacts() -> None:
    payload = _load_manifest()
    invariants = payload.get("invariants", [])
    assert isinstance(invariants, list)

    ids = {item.get("id") for item in invariants}
    assert ids == EXPECTED_INVARIANTS

    for item in invariants:
        assert item.get("enforcement_locations")
        assert item.get("test_coverage")
        assert item.get("artifact_evidence")

        for rel_path in item["enforcement_locations"] + item["test_coverage"]:
            assert Path(rel_path).is_file(), f"missing mapped file: {rel_path}"


def test_tool_router_cannot_be_bypassed_runtime_verification() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="Lookup", allowed=True),
        executor=lambda invocation: {"status": "ok", "tool": invocation.tool_name},
    )
    router = SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter(), policy_engine=None)
    invocation = ToolInvocation(
        request_id="req-1",
        actor_id="actor-1",
        tenant_id="tenant-a",
        tool_name="ticket_lookup",
        action="lookup",
        arguments={"ticket_id": "T-1"},
    )

    # direct registry execution must fail loudly when not mediated by router context.
    try:
        registry.execute(invocation, execution_secret=object())
        assert False, "direct registry execution unexpectedly succeeded"
    except DirectToolExecutionDeniedError:
        pass

    decision, result = router.mediate_and_execute(invocation)
    assert decision.status == "deny"
    assert result is None


def test_evals_and_launch_gate_verification_checks_are_runtime_bound() -> None:
    scenarios = load_scenarios("evals/scenarios/security_baseline.json")
    assert any(item.execution_path == "full_runtime" for item in scenarios)

    report = run_security_guarantees_verification(Path("."), require_evidence_presence=False)
    by_id = {item["invariant_id"]: item for item in report["results"]}

    assert by_id["evals_hit_real_flows"]["status"] == "pass"
    assert by_id["launch_gate_checks_real_evidence"]["status"] == "pass"

    gate = SecurityLaunchGate(repo_root=Path("."))
    readiness = gate.evaluate()
    assert isinstance(readiness.status, str)
    assert any(check.check_name == "eval_suite_evidence" for check in readiness.checks)


def test_replay_artifact_reconstructs_decisions_including_deny_and_fallback() -> None:
    trace_id = "trace-g"
    events = [
        create_audit_event(
            trace_id=trace_id,
            request_id="req-g",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=REQUEST_START_EVENT,
            payload={"session_id": "s1"},
        ),
        create_audit_event(
            trace_id=trace_id,
            request_id="req-g",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=POLICY_DECISION_EVENT,
            payload={"action": "retrieval.search", "allow": True, "reason": "ok", "risk_tier": "low"},
        ),
        create_audit_event(
            trace_id=trace_id,
            request_id="req-g",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=RETRIEVAL_DECISION_EVENT,
            payload={"document_count": 1, "top_k": 1, "allowed_source_ids": ["kb-main"]},
        ),
        create_audit_event(
            trace_id=trace_id,
            request_id="req-g",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=TOOL_DECISION_EVENT,
            payload={"decisions": ["deny"]},
        ),
        create_audit_event(
            trace_id=trace_id,
            request_id="req-g",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=DENY_EVENT,
            payload={"stage": "tool.route", "reason": "denied"},
        ),
        create_audit_event(
            trace_id=trace_id,
            request_id="req-g",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=FALLBACK_EVENT,
            payload={"mode": "rag_only", "reason": "tools disabled"},
        ),
        create_audit_event(
            trace_id=trace_id,
            request_id="req-g",
            actor_id="actor-1",
            tenant_id="tenant-a",
            event_type=REQUEST_END_EVENT,
            payload={"status": "ok"},
        ),
    ]

    artifact = build_replay_artifact(events)

    assert artifact.coverage["request_lifecycle_complete"] is True
    assert artifact.coverage["decision_replay_core_complete"] is True
    assert artifact.coverage[DENY_EVENT] is True
    assert artifact.coverage[FALLBACK_EVENT] is True
    assert artifact.decision_summary["deny_events"]
    assert artifact.decision_summary["fallback_events"]
