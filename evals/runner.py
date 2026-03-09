"""Reusable security eval and red-team harness."""

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from evals.contracts import (
    BLOCKED_OUTCOME,
    EXPECTED_FAIL_OUTCOME,
    FAIL_OUTCOME,
    INCONCLUSIVE_OUTCOME,
    PASS_OUTCOME,
    EvalResult,
    EvalScenarioResult,
)
from evals.runtime import build_runtime_fixture, make_invocation, make_request
from identity.models import ActorType, IdentityValidationError, build_identity, parse_identity, validate_delegation_chain
from tools.capabilities import CapabilityTokenError
from tools.mcp_security import MCPPolicyError
from evals.scenario import SecurityScenario, load_scenarios
from telemetry.audit import (
    POLICY_DECISION_EVENT,
    REQUEST_END_EVENT,
    REQUEST_START_EVENT,
    RETRIEVAL_DECISION_EVENT,
    TOOL_DECISION_EVENT,
    build_replay_artifact,
    validate_replay_completeness,
    write_replay_artifact,
)


RUNTIME_COMPONENTS = {
    "orchestrator",
    "retrieval",
    "policy",
    "tool_routing",
    "audit_logging",
}


@dataclass
class SecurityEvalRunner:
    suite_name: str = "security-redteam"

    def run(
        self,
        scenario_file: str | Path,
        *,
        output_dir: str | Path = "artifacts/logs/evals",
        stamp: str | None = None,
    ) -> EvalResult:
        scenarios = load_scenarios(scenario_file)
        resolved_stamp = _resolve_stamp(stamp)
        eval_output_dir = Path(output_dir)
        replay_output_dir = eval_output_dir.parent / "replay"
        scenario_results = tuple(
            self._run_scenario(scenario, replay_output_dir=replay_output_dir, stamp=resolved_stamp)
            for scenario in scenarios
        )

        outcome_counts = {
            PASS_OUTCOME: sum(1 for item in scenario_results if item.outcome == PASS_OUTCOME),
            FAIL_OUTCOME: sum(1 for item in scenario_results if item.outcome == FAIL_OUTCOME),
            EXPECTED_FAIL_OUTCOME: sum(1 for item in scenario_results if item.outcome == EXPECTED_FAIL_OUTCOME),
            BLOCKED_OUTCOME: sum(1 for item in scenario_results if item.outcome == BLOCKED_OUTCOME),
            INCONCLUSIVE_OUTCOME: sum(1 for item in scenario_results if item.outcome == INCONCLUSIVE_OUTCOME),
        }
        passed = outcome_counts[FAIL_OUTCOME] == 0 and outcome_counts[INCONCLUSIVE_OUTCOME] == 0
        summary = (
            f"pass={outcome_counts[PASS_OUTCOME]}; fail={outcome_counts[FAIL_OUTCOME]}; "
            f"expected_fail={outcome_counts[EXPECTED_FAIL_OUTCOME]}; blocked={outcome_counts[BLOCKED_OUTCOME]}; "
            f"inconclusive={outcome_counts[INCONCLUSIVE_OUTCOME]}"
        )

        eval_result = EvalResult(
            suite_name=self.suite_name,
            passed=passed,
            summary=summary,
            scenario_results=scenario_results,
        )

        self._write_outputs(eval_result, output_dir=eval_output_dir, outcome_counts=outcome_counts, stamp=resolved_stamp)
        return eval_result

    def _run_scenario(self, scenario: SecurityScenario, *, replay_output_dir: Path, stamp: str) -> EvalScenarioResult:
        evidence: dict[str, object] = {
            "operation": scenario.operation,
            "label": scenario.label,
            "execution_path": scenario.execution_path,
            "limitation_reason": scenario.limitation_reason,
            "mocked": scenario.label in {"mock", "mocked", "simulated"},
        }

        try:
            fixture = build_runtime_fixture(scenario.policy_overrides)
            evidence.update(_runtime_realism_evidence(scenario=scenario, fixture=fixture))

            if scenario.operation == "orchestrator_request":
                request = make_request(
                    request_id=scenario.request.get("request_id", scenario.scenario_id),
                    tenant_id=scenario.request.get("tenant_id", "tenant-a"),
                    user_text=scenario.request.get("user_text", "help"),
                )
                response = fixture.orchestrator.run(request)
                event_types = [event.event_type for event in fixture.audit_sink.events]
                evidence.update(
                    {
                        "status": response.status,
                        "answer_text": response.answer_text,
                        "tool_decision_statuses": [decision.status for decision in response.tool_decisions],
                        "event_types": event_types,
                        "retrieved_document_ids": list(response.trace.retrieved_document_ids),
                        "decision_log": _extract_decision_log(fixture.audit_sink.events),
                        "runtime_components_exercised": _runtime_components_exercised(
                            operation=scenario.operation,
                            event_types=event_types,
                        ),
                    }
                )
                self._append_replay_evidence(
                    evidence=evidence,
                    scenario_id=scenario.scenario_id,
                    replay_output_dir=replay_output_dir,
                    stamp=stamp,
                    events=fixture.audit_sink.events,
                )

            elif scenario.operation in {"tool_invocation", "tool_execution"}:
                capability_token = scenario.invocation.get("capability_token")
                if bool(scenario.invocation.get("issue_capability", False)):
                    tool_name = str(scenario.invocation.get("tool_name", "ticket_lookup"))
                    operation = str(scenario.invocation.get("action", "lookup"))
                    identity = make_request(
                        request_id=scenario.invocation.get("request_id", scenario.scenario_id),
                        tenant_id=scenario.invocation.get("tenant_id", "tenant-a"),
                        user_text="capability issue helper",
                    ).session.identity
                    capability_token = fixture.capability_issuer.issue(
                        request_id=scenario.invocation.get("request_id", scenario.scenario_id),
                        identity=identity,
                        tool_id=tool_name,
                        allowed_operations=(operation,),
                        ttl_seconds=int(scenario.invocation.get("capability_ttl_seconds", 60)),
                        justification="adversarial eval",
                    )

                identity_payload = scenario.invocation.get("identity_payload")
                invocation = make_invocation(
                    request_id=scenario.invocation.get("request_id", scenario.scenario_id),
                    tenant_id=scenario.invocation.get("tenant_id", "tenant-a"),
                    tool_name=scenario.invocation.get("tool_name", "ticket_lookup"),
                    action=scenario.invocation.get("action", "lookup"),
                    arguments=scenario.invocation.get("arguments", {}),
                    confirmed=bool(scenario.invocation.get("confirmed", False)),
                    capability_token=capability_token if isinstance(capability_token, str) else None,
                    identity_payload=identity_payload if isinstance(identity_payload, dict) else None,
                )

                if scenario.operation == "tool_execution":
                    decision, execution_result = fixture.tool_router.mediate_and_execute(invocation)
                else:
                    decision = fixture.tool_router.route(invocation)
                    execution_result = None

                evidence.update(
                    {
                        "tool_decision_status": decision.status,
                        "tool_decision_reason": decision.reason,
                        "execution_performed": execution_result is not None,
                        "execution_result": execution_result,
                        "decision_log": {
                            "tool_decision": {
                                "status": decision.status,
                                "tool_name": decision.tool_name,
                                "action": decision.action,
                                "reason": decision.reason,
                            }
                        },
                        "runtime_components_exercised": _runtime_components_exercised(
                            operation=scenario.operation,
                            event_types=[],
                        ),
                    }
                )

            elif scenario.operation == "capability_replay":
                invocation_config = scenario.invocation
                identity = build_identity(
                    actor_id="eval-runtime",
                    actor_type=ActorType.ASSISTANT_RUNTIME,
                    tenant_id=str(invocation_config.get("tenant_id", "tenant-a")),
                    session_id=f"session-{invocation_config.get('request_id', scenario.scenario_id)}",
                    trust_level="high",
                    allowed_capabilities=("tools.issue_capability", "tools.invoke", "tools.route"),
                )
                token = fixture.capability_issuer.issue(
                    request_id=invocation_config.get("request_id", scenario.scenario_id),
                    identity=identity,
                    tool_id=str(invocation_config.get("tool_name", "privileged_export")),
                    allowed_operations=(str(invocation_config.get("action", "export")),),
                    ttl_seconds=60,
                    justification="capability replay test",
                )
                identity_payload = {
                    "actor_id": identity.actor_id,
                    "actor_type": identity.actor_type.value,
                    "tenant_id": identity.tenant_id,
                    "session_id": identity.session_id,
                    "delegation_chain": [],
                    "auth_context": dict(identity.auth_context),
                    "trust_level": identity.trust_level,
                    "allowed_capabilities": list(identity.allowed_capabilities),
                }
                first = make_invocation(
                    request_id=str(invocation_config.get("request_id", scenario.scenario_id)),
                    tenant_id=str(invocation_config.get("tenant_id", "tenant-a")),
                    tool_name=str(invocation_config.get("tool_name", "privileged_export")),
                    action=str(invocation_config.get("action", "export")),
                    arguments=invocation_config.get("arguments", {}),
                    confirmed=True,
                    capability_token=token,
                    identity_payload=identity_payload,
                )
                second = make_invocation(
                    request_id=f"{invocation_config.get('request_id', scenario.scenario_id)}-replay",
                    tenant_id=str(invocation_config.get("tenant_id", "tenant-a")),
                    tool_name=str(invocation_config.get("tool_name", "privileged_export")),
                    action=str(invocation_config.get("action", "export")),
                    arguments=invocation_config.get("arguments", {}),
                    confirmed=True,
                    capability_token=token,
                    identity_payload=identity_payload,
                )
                first_decision = fixture.tool_router.route(first)
                second_decision = fixture.tool_router.route(second)
                evidence.update(
                    {
                        "first_decision_status": first_decision.status,
                        "second_decision_status": second_decision.status,
                        "second_decision_reason": second_decision.reason,
                        "runtime_components_exercised": _runtime_components_exercised(operation="tool_invocation", event_types=[]),
                    }
                )

            elif scenario.operation == "identity_validation":
                payload = scenario.request.get("identity_payload", {})
                action = str(scenario.request.get("action", "tools.invoke"))
                try:
                    identity = parse_identity(payload)
                    validate_delegation_chain(identity, action=action)
                    evidence.update({"identity_validation": "accepted", "identity_error": ""})
                except Exception as exc:
                    evidence.update({"identity_validation": "denied", "identity_error": str(exc)})
                evidence.update({"runtime_components_exercised": _runtime_components_exercised(operation=scenario.operation, event_types=[])})

            elif scenario.operation == "mcp_gateway":
                request_id = str(scenario.request.get("request_id", scenario.scenario_id))
                invocation = make_invocation(
                    request_id=request_id,
                    tenant_id=str(scenario.request.get("tenant_id", "tenant-a")),
                    tool_name="ticket_lookup",
                    action="lookup",
                    arguments=scenario.request.get("arguments", {}),
                )

                class _ScenarioTransport:
                    def call(self, *, endpoint: str, payload: dict, timeout_ms: int):
                        mode = str(scenario.request.get("transport_mode", "ok"))
                        if mode == "schema_tamper":
                            return {"status": "ok", "data": "not-a-map", "origin": {"endpoint": endpoint}}
                        if mode == "oversized":
                            return {"status": "ok", "data": {"blob": "x" * 5000}, "origin": {"endpoint": endpoint}}
                        return {"status": "ok", "data": {"ticket": "123"}, "origin": {"endpoint": endpoint}}

                fixture.mcp_gateway.transport = _ScenarioTransport()
                try:
                    response = fixture.mcp_gateway.invoke_tool(
                        server_id=str(scenario.request.get("server_id", "ticketing")),
                        capability=str(scenario.request.get("capability", "tickets.read")),
                        invocation=invocation,
                    )
                    evidence.update({"mcp_status": "ok", "mcp_response": dict(response)})
                except Exception as exc:
                    evidence.update({"mcp_status": "denied", "mcp_error": str(exc)})
                event_types = [event.event_type for event in fixture.audit_sink.events]
                evidence.update({"event_types": event_types, "decision_log": _extract_decision_log(fixture.audit_sink.events), "runtime_components_exercised": _runtime_components_exercised(operation=scenario.operation, event_types=event_types)})

            elif scenario.operation == "audit_verification":
                request = make_request(
                    request_id=scenario.request.get("request_id", scenario.scenario_id),
                    tenant_id=scenario.request.get("tenant_id", "tenant-a"),
                    user_text=scenario.request.get("user_text", "help"),
                )
                _ = fixture.orchestrator.run(request)
                event_types = [event.event_type for event in fixture.audit_sink.events]
                evidence.update(
                    {
                        "event_types": event_types,
                        "event_count": len(event_types),
                        "decision_log": _extract_decision_log(fixture.audit_sink.events),
                        "runtime_components_exercised": _runtime_components_exercised(
                            operation=scenario.operation,
                            event_types=event_types,
                        ),
                    }
                )
                self._append_replay_evidence(
                    evidence=evidence,
                    scenario_id=scenario.scenario_id,
                    replay_output_dir=replay_output_dir,
                    stamp=stamp,
                    events=fixture.audit_sink.events,
                )

            checks_passed, details = _evaluate_expectations(dict(scenario.expectations), evidence)
            outcome = _classify_outcome(checks_passed=checks_passed, expectations=dict(scenario.expectations), evidence=evidence)
            evidence["scenario_summary"] = f"outcome={outcome}; checks={'pass' if checks_passed else 'fail'}; details={details}"
            return EvalScenarioResult(
                scenario_id=scenario.scenario_id,
                title=scenario.title,
                severity=scenario.severity,
                passed=checks_passed,
                outcome=outcome,
                details=details,
                evidence=evidence,
            )
        except Exception as exc:
            evidence["error"] = {"type": type(exc).__name__, "message": str(exc)}
            return EvalScenarioResult(
                scenario_id=scenario.scenario_id,
                title=scenario.title,
                severity=scenario.severity,
                passed=False,
                outcome=INCONCLUSIVE_OUTCOME,
                details="scenario execution error",
                evidence=evidence,
            )

    def _write_outputs(self, result: EvalResult, *, output_dir: Path, outcome_counts: dict[str, int], stamp: str) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        jsonl_path = output_dir / f"{self.suite_name}-{stamp}.jsonl"
        summary_path = output_dir / f"{self.suite_name}-{stamp}.summary.json"

        with jsonl_path.open("w", encoding="utf-8") as handle:
            for scenario_result in result.scenario_results:
                handle.write(
                    json.dumps(
                        {
                            "scenario_id": scenario_result.scenario_id,
                            "title": scenario_result.title,
                            "severity": scenario_result.severity,
                            "passed": scenario_result.passed,
                            "outcome": scenario_result.outcome,
                            "details": scenario_result.details,
                            "evidence": scenario_result.evidence,
                        },
                        sort_keys=True,
                    )
                )
                handle.write("\n")

        summary_path.write_text(
            json.dumps(
                {
                    "suite_name": result.suite_name,
                    "passed": result.passed,
                    "summary": result.summary,
                    "total": len(result.scenario_results),
                    "passed_count": sum(1 for item in result.scenario_results if item.passed),
                    "outcomes": outcome_counts,
                },
                sort_keys=True,
                indent=2,
            )
        )

    def _append_replay_evidence(
        self,
        *,
        evidence: dict[str, object],
        scenario_id: str,
        replay_output_dir: Path,
        stamp: str,
        events,
    ) -> None:
        if not events:
            return

        artifact = build_replay_artifact(events)
        replay_path = replay_output_dir / f"{self.suite_name}-{stamp}-{scenario_id}.replay.json"
        write_replay_artifact(artifact, replay_path)

        required = (
            REQUEST_START_EVENT,
            REQUEST_END_EVENT,
            POLICY_DECISION_EVENT,
            RETRIEVAL_DECISION_EVENT,
            TOOL_DECISION_EVENT,
        )
        complete, missing = validate_replay_completeness(artifact, required_event_types=required)
        evidence.update(
            {
                "replay_artifact_path": str(replay_path),
                "replay_event_type_counts": dict(artifact.event_type_counts),
                "replay_coverage": dict(artifact.coverage),
                "replay_decision_summary": dict(artifact.decision_summary),
                "replay_required_events": list(required),
                "replay_required_events_complete": complete,
                "replay_missing_required_events": list(missing),
            }
        )


def _classify_outcome(*, checks_passed: bool, expectations: dict, evidence: dict) -> str:
    if checks_passed:
        if evidence.get("status") == "blocked":
            return BLOCKED_OUTCOME
        return PASS_OUTCOME

    if bool(expectations.get("expected_fail", False)):
        return EXPECTED_FAIL_OUTCOME
    return FAIL_OUTCOME


def _extract_decision_log(events) -> dict[str, object]:
    policy_decisions = []
    retrieval_decisions = []
    tool_decisions = []
    deny_events = []
    fallback_events = []

    for event in events:
        payload = dict(event.event_payload)
        if event.event_type == "policy.decision":
            policy_decisions.append(
                {
                    "action": payload.get("action"),
                    "allow": payload.get("allow"),
                    "reason": payload.get("reason"),
                }
            )
        elif event.event_type == "retrieval.decision":
            retrieval_decisions.append(
                {
                    "document_count": payload.get("document_count"),
                    "top_k": payload.get("top_k"),
                    "allowed_source_ids": payload.get("allowed_source_ids"),
                }
            )
        elif event.event_type == "tool.decision":
            tool_decisions.append({"decisions": payload.get("decisions", [])})
        elif event.event_type == "deny.event":
            deny_events.append(
                {
                    "stage": payload.get("stage"),
                    "tool_name": payload.get("tool_name"),
                    "reason": payload.get("reason"),
                }
            )
        elif event.event_type == "fallback.event":
            fallback_events.append(
                {
                    "mode": payload.get("mode"),
                    "reason": payload.get("reason"),
                }
            )

    return {
        "policy_decisions": policy_decisions,
        "retrieval_decisions": retrieval_decisions,
        "tool_decisions": tool_decisions,
        "deny_events": deny_events,
        "fallback_events": fallback_events,
    }


def _runtime_components_exercised(*, operation: str, event_types: list[str]) -> dict[str, bool]:
    event_set = set(event_types)
    if operation in {"orchestrator_request", "audit_verification"}:
        return {
            "orchestrator": True,
            "retrieval": RETRIEVAL_DECISION_EVENT in event_set,
            "policy": POLICY_DECISION_EVENT in event_set,
            "tool_routing": TOOL_DECISION_EVENT in event_set,
            "audit_logging": len(event_set) > 0,
        }

    if operation in {"tool_invocation", "tool_execution", "capability_replay", "mcp_gateway", "identity_validation"}:
        return {
            "orchestrator": False,
            "retrieval": False,
            "policy": True,
            "tool_routing": operation in {"tool_invocation", "tool_execution", "capability_replay", "mcp_gateway"},
            "audit_logging": operation == "mcp_gateway",
        }

    return {name: False for name in RUNTIME_COMPONENTS}


def _runtime_realism_evidence(*, scenario: SecurityScenario, fixture) -> dict[str, object]:
    orchestrator = fixture.orchestrator
    retriever = getattr(orchestrator, "retriever", None)
    raw_retriever = getattr(retriever, "raw_retriever", None)
    model = getattr(orchestrator, "model", None)

    runtime_components = {
        "orchestrator": type(orchestrator).__name__,
        "retriever": type(retriever).__name__ if retriever is not None else "missing",
        "policy_engine": type(getattr(orchestrator, "policy_engine", None)).__name__,
        "tool_router": type(fixture.tool_router).__name__,
        "audit_sink": type(fixture.audit_sink).__name__,
    }

    simulated_dependencies: list[str] = []
    if model is not None and type(model).__module__.startswith("evals."):
        simulated_dependencies.append("model")
    if raw_retriever is not None and type(raw_retriever).__module__.startswith("evals."):
        simulated_dependencies.append("retrieval_corpus")

    return {
        "runtime_components": runtime_components,
        "simulated_dependencies": simulated_dependencies,
        "realism_notes": (
            [
                "Uses real runtime orchestration/policy/retrieval/tool-router/audit modules with deterministic eval fixtures.",
                "Model and retrieval corpus are simulated to keep scenarios deterministic and adversarially reproducible.",
            ]
            if simulated_dependencies
            else ["Uses fully runtime dependencies without simulated components."]
        ),
        "scenario_limitation_reason": scenario.limitation_reason,
    }


def _evaluate_expectations(expectations: dict, evidence: dict) -> tuple[bool, str]:
    checks: list[tuple[bool, str]] = []

    if "status" in expectations:
        checks.append((evidence.get("status") == expectations["status"], f"expected status {expectations['status']}"))

    if "tool_decision_status" in expectations:
        checks.append(
            (
                evidence.get("tool_decision_status") == expectations["tool_decision_status"],
                f"expected tool decision {expectations['tool_decision_status']}",
            )
        )

    if "answer_contains" in expectations:
        expected = str(expectations["answer_contains"])
        checks.append((expected in str(evidence.get("answer_text", "")), f"answer missing required text: {expected}"))

    if "answer_not_contains" in expectations:
        expected = str(expectations["answer_not_contains"])
        checks.append((expected not in str(evidence.get("answer_text", "")), f"answer contains forbidden text: {expected}"))

    if "execution_performed" in expectations:
        checks.append(
            (
                bool(evidence.get("execution_performed", False)) == bool(expectations["execution_performed"]),
                f"expected execution_performed={bool(expectations['execution_performed'])}",
            )
        )

    if "execution_result_status" in expectations:
        expected = str(expectations["execution_result_status"])
        actual = str((evidence.get("execution_result") or {}).get("status", ""))
        checks.append((actual == expected, f"expected execution result status {expected}"))
    if "required_policy_reasons" in expectations and isinstance(expectations["required_policy_reasons"], list):
        reasons = [str(item.get("reason", "")) for item in evidence.get("decision_log", {}).get("policy_decisions", [])]
        for expected in expectations["required_policy_reasons"]:
            checks.append((any(str(expected) in reason for reason in reasons), f"required policy reason missing: {expected}"))

    if "required_deny_reasons" in expectations and isinstance(expectations["required_deny_reasons"], list):
        reasons = [str(item.get("reason", "")) for item in evidence.get("decision_log", {}).get("deny_events", [])]
        reasons.append(str(evidence.get("tool_decision_reason", "")))
        reasons.append(str(evidence.get("second_decision_reason", "")))
        reasons.append(str(evidence.get("mcp_error", "")))
        reasons.append(str(evidence.get("identity_error", "")))
        for expected in expectations["required_deny_reasons"]:
            checks.append((any(str(expected) in reason for reason in reasons), f"required deny reason missing: {expected}"))

    if "replay_required_complete" in expectations:
        expected = bool(expectations["replay_required_complete"])
        actual = bool(evidence.get("replay_required_events_complete", False))
        checks.append((actual == expected, f"expected replay_required_events_complete={expected}"))

    if "mcp_status" in expectations:
        checks.append((str(evidence.get("mcp_status", "")) == str(expectations["mcp_status"]), f"expected mcp_status {expectations['mcp_status']}"))

    if "identity_validation" in expectations:
        checks.append((str(evidence.get("identity_validation", "")) == str(expectations["identity_validation"]), f"expected identity_validation {expectations['identity_validation']}"))

    if "second_decision_status" in expectations:
        checks.append((str(evidence.get("second_decision_status", "")) == str(expectations["second_decision_status"]), f"expected second_decision_status {expectations['second_decision_status']}"))


    required_events = expectations.get("required_events", [])
    if isinstance(required_events, list):
        event_types = evidence.get("event_types", [])
        for event in required_events:
            checks.append((event in event_types, f"required event missing: {event}"))

    forbidden_events = expectations.get("forbidden_events", [])
    if isinstance(forbidden_events, list):
        event_types = evidence.get("event_types", [])
        for event in forbidden_events:
            checks.append((event not in event_types, f"forbidden event present: {event}"))

    min_event_count = expectations.get("min_event_count")
    if isinstance(min_event_count, int):
        checks.append((len(evidence.get("event_types", [])) >= min_event_count, f"expected at least {min_event_count} events"))

    min_retrieved_docs = expectations.get("min_retrieved_docs")
    if isinstance(min_retrieved_docs, int):
        checks.append(
            (
                len(evidence.get("retrieved_document_ids", [])) >= min_retrieved_docs,
                f"expected at least {min_retrieved_docs} retrieved docs",
            )
        )

    max_retrieved_docs = expectations.get("max_retrieved_docs")
    if isinstance(max_retrieved_docs, int):
        checks.append(
            (
                len(evidence.get("retrieved_document_ids", [])) <= max_retrieved_docs,
                f"expected at most {max_retrieved_docs} retrieved docs",
            )
        )

    required_runtime_components = expectations.get("required_runtime_components", [])
    if isinstance(required_runtime_components, list):
        exercised = evidence.get("runtime_components_exercised", {})
        for component in required_runtime_components:
            checks.append(
                (
                    bool(exercised.get(component, False)),
                    f"required runtime component not exercised: {component}",
                )
            )

    max_simulated_dependencies = expectations.get("max_simulated_dependencies")
    if isinstance(max_simulated_dependencies, int):
        checks.append(
            (
                len(evidence.get("simulated_dependencies", [])) <= max_simulated_dependencies,
                f"expected at most {max_simulated_dependencies} simulated dependencies",
            )
        )

    if not checks:
        return False, "no expectations defined"

    failed = [msg for ok, msg in checks if not ok]
    if failed:
        return False, "; ".join(failed)
    return True, "all expectations satisfied"


def _resolve_stamp(stamp: str | None) -> str:
    if stamp is None:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = str(stamp).strip()
    if not candidate:
        raise ValueError("stamp must be non-empty when provided")
    if any(char.isspace() for char in candidate):
        raise ValueError("stamp must not contain whitespace")
    return candidate


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run security eval scenarios and write evidence artifacts.")
    parser.add_argument("--scenario-file", default="evals/scenarios/security_baseline.json")
    parser.add_argument("--output-dir", default="artifacts/logs/evals")
    parser.add_argument("--stamp", default=None)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    runner = SecurityEvalRunner()
    result = runner.run(args.scenario_file, output_dir=args.output_dir, stamp=args.stamp)
    print(result.summary)
