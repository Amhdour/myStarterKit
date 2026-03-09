"""Machine-checkable drift detection for security-relevant control surfaces."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from collections.abc import Mapping, Sequence
from typing import Any

from identity.models import ActorType, build_identity
from telemetry.audit import REQUEST_START_EVENT
from telemetry.audit.events import create_audit_event
from telemetry.audit.replay import build_replay_artifact
from telemetry.audit.sinks import _event_to_record

DEFAULT_DRIFT_MANIFEST_PATH = "config/security_drift_manifest.json"
DEFAULT_POLICY_PATH = "policies/bundles/default/policy.json"
DEFAULT_INTEGRATION_INVENTORY_PATH = "config/integration_inventory.json"
DEFAULT_EVAL_SCENARIO_PATH = "evals/scenarios/security_baseline.json"


@dataclass(frozen=True)
class DriftCheckResult:
    check_name: str
    severity: str
    passed: bool
    details: str
    evidence: Mapping[str, object]


def run_security_drift_checks(
    repo_root: Path,
    *,
    drift_manifest_path: str = DEFAULT_DRIFT_MANIFEST_PATH,
    policy_path: str = DEFAULT_POLICY_PATH,
    integration_inventory_path: str = DEFAULT_INTEGRATION_INVENTORY_PATH,
    eval_scenario_path: str = DEFAULT_EVAL_SCENARIO_PATH,
) -> dict[str, object]:
    manifest = _read_json(repo_root / drift_manifest_path)
    policy = _read_json(repo_root / policy_path)
    integration_inventory = _read_json(repo_root / integration_inventory_path)
    evals = _read_json(repo_root / eval_scenario_path)

    checks = [
        _check_manifest_exists(drift_manifest_path, manifest),
        _check_required_controls(repo_root, manifest),
        _check_policy_tool_drift(manifest, policy),
        _check_retrieval_source_drift(manifest, policy),
        _check_integration_inventory_drift(manifest, policy, integration_inventory),
        _check_eval_contract_drift(manifest, evals),
        _check_telemetry_replay_schema_drift(manifest),
    ]

    critical_failures = [item for item in checks if item.severity == "critical" and not item.passed]
    warning_failures = [item for item in checks if item.severity == "warning" and not item.passed]
    status = "fail" if critical_failures else "pass"

    return {
        "suite": "security_drift_detection",
        "status": status,
        "drift_manifest_path": drift_manifest_path,
        "critical_failure_count": len(critical_failures),
        "warning_failure_count": len(warning_failures),
        "results": [
            {
                "check_name": item.check_name,
                "severity": item.severity,
                "status": "pass" if item.passed else "fail",
                "details": item.details,
                "evidence": dict(item.evidence),
            }
            for item in checks
        ],
    }


def _check_manifest_exists(path: str, payload: Mapping[str, object] | None) -> DriftCheckResult:
    passed = payload is not None
    return DriftCheckResult(
        check_name="drift_manifest_present",
        severity="critical",
        passed=passed,
        details="drift manifest present" if passed else "drift manifest missing or unreadable",
        evidence={"drift_manifest_path": path, "manifest_present": passed},
    )


def _check_required_controls(repo_root: Path, manifest: Mapping[str, object] | None) -> DriftCheckResult:
    required = _tuple_str(manifest, "required_controls") if manifest else tuple()
    missing = [path for path in required if not (repo_root / path).is_file()]
    passed = len(missing) == 0 and len(required) > 0
    return DriftCheckResult(
        check_name="required_controls_drift",
        severity="critical",
        passed=passed,
        details="required controls intact" if passed else "required controls missing or drift manifest empty",
        evidence={"required_controls": list(required), "missing_controls": missing},
    )


def _check_policy_tool_drift(manifest: Mapping[str, object] | None, policy: Mapping[str, object] | None) -> DriftCheckResult:
    expected = set(_tuple_str(manifest, "expected_tool_ids")) if manifest else set()
    tools = (policy or {}).get("tools", {})
    observed = set(_to_str_list(tools.get("allowed_tools", [])))
    observed |= set(_to_str_list(tools.get("forbidden_tools", [])))
    observed |= set(_to_str_list(tools.get("confirmation_required_tools", [])))
    observed |= set(str(key) for key in (tools.get("forbidden_fields_per_tool", {}) or {}).keys())
    observed |= set(str(key) for key in (tools.get("rate_limits_per_tool", {}) or {}).keys())

    undocumented = sorted(tool for tool in observed if tool not in expected)
    stale_expected = sorted(tool for tool in expected if tool not in observed)
    passed = len(undocumented) == 0
    return DriftCheckResult(
        check_name="policy_tool_registry_drift",
        severity="critical",
        passed=passed,
        details="policy tool surface matches documented manifest" if passed else "policy references undocumented tools",
        evidence={
            "documented_tools": sorted(expected),
            "policy_tools": sorted(observed),
            "undocumented_tools": undocumented,
            "stale_expected_tools": stale_expected,
        },
    )


def _check_retrieval_source_drift(manifest: Mapping[str, object] | None, policy: Mapping[str, object] | None) -> DriftCheckResult:
    documented = set(_tuple_str(manifest, "expected_retrieval_source_ids")) if manifest else set()
    policy_retrieval = (policy or {}).get("retrieval", {})
    tenant_allowed = policy_retrieval.get("tenant_allowed_sources", {}) or {}
    observed: set[str] = set()
    if isinstance(tenant_allowed, Mapping):
        for _, source_ids in tenant_allowed.items():
            observed.update(_to_str_list(source_ids if isinstance(source_ids, Sequence) else []))

    undocumented = sorted(item for item in observed if item not in documented)
    passed = len(undocumented) == 0 and len(documented) > 0
    return DriftCheckResult(
        check_name="retrieval_source_boundary_drift",
        severity="critical",
        passed=passed,
        details="retrieval source boundaries match documented manifest" if passed else "retrieval sources drifted from documented boundaries",
        evidence={"documented_sources": sorted(documented), "policy_sources": sorted(observed), "undocumented_sources": undocumented},
    )


def _check_integration_inventory_drift(
    manifest: Mapping[str, object] | None,
    policy: Mapping[str, object] | None,
    inventory: Mapping[str, object] | None,
) -> DriftCheckResult:
    expected = set(_tuple_str(manifest, "expected_integration_ids")) if manifest else set()
    policy_integrations = set(_to_str_list(((policy or {}).get("integrations", {}) or {}).get("allowed_integrations", [])))
    inventory_integrations = {
        str(item.get("integration_id", ""))
        for item in ((inventory or {}).get("integrations", []) or [])
        if isinstance(item, Mapping) and str(item.get("integration_id", ""))
    }

    undocumented_policy = sorted(item for item in policy_integrations if item not in expected)
    undocumented_inventory = sorted(item for item in inventory_integrations if item not in expected)
    missing_from_inventory = sorted(item for item in policy_integrations if item not in inventory_integrations)
    passed = len(undocumented_policy) == 0 and len(undocumented_inventory) == 0 and len(missing_from_inventory) == 0

    return DriftCheckResult(
        check_name="integration_surface_drift",
        severity="critical",
        passed=passed,
        details="integration surfaces aligned across manifest/policy/inventory" if passed else "integration drift detected",
        evidence={
            "expected_integrations": sorted(expected),
            "policy_integrations": sorted(policy_integrations),
            "inventory_integrations": sorted(inventory_integrations),
            "undocumented_policy_integrations": undocumented_policy,
            "undocumented_inventory_integrations": undocumented_inventory,
            "policy_missing_from_inventory": missing_from_inventory,
        },
    )


def _check_eval_contract_drift(manifest: Mapping[str, object] | None, evals: Mapping[str, object] | None) -> DriftCheckResult:
    required = set(_tuple_str(manifest, "required_eval_scenario_ids")) if manifest else set()
    observed = {
        str(item.get("id", ""))
        for item in ((evals or {}).get("scenarios", []) or [])
        if isinstance(item, Mapping) and str(item.get("id", ""))
    }
    missing_required = sorted(item for item in required if item not in observed)
    passed = len(missing_required) == 0 and len(required) > 0
    return DriftCheckResult(
        check_name="eval_contract_drift",
        severity="critical",
        passed=passed,
        details="eval contracts include required security scenarios" if passed else "required eval scenarios missing",
        evidence={"required_scenarios": sorted(required), "observed_scenarios": sorted(observed), "missing_required": missing_required},
    )


def _check_telemetry_replay_schema_drift(manifest: Mapping[str, object] | None) -> DriftCheckResult:
    required_audit_fields = set(_tuple_str(manifest, "required_audit_record_fields")) if manifest else set()
    required_replay_fields = set(_tuple_str(manifest, "required_replay_fields")) if manifest else set()

    identity = build_identity(
        actor_id="drift-checker",
        actor_type=ActorType.TEST_HARNESS,
        tenant_id="tenant-a",
        session_id="drift-session",
        trust_level="low",
        allowed_capabilities=("audit.emit",),
    )
    event = create_audit_event(
        trace_id="trace-drift",
        request_id="req-drift",
        identity=identity,
        event_type=REQUEST_START_EVENT,
        payload={"channel": "test"},
    )
    audit_record = _event_to_record(event)
    replay_payload = {"replay_version": "1", **asdict(build_replay_artifact((event,)))}

    missing_audit = sorted(field for field in required_audit_fields if field not in audit_record)
    missing_replay = sorted(field for field in required_replay_fields if field not in replay_payload)
    passed = len(missing_audit) == 0 and len(missing_replay) == 0

    return DriftCheckResult(
        check_name="telemetry_replay_schema_drift",
        severity="warning",
        passed=passed,
        details="telemetry/replay schema supports documented assumptions" if passed else "telemetry/replay schema drift detected",
        evidence={
            "missing_audit_fields": missing_audit,
            "missing_replay_fields": missing_replay,
        },
    )


def _read_json(path: Path) -> Mapping[str, object] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, Mapping) else None


def _tuple_str(payload: Mapping[str, object] | None, key: str) -> tuple[str, ...]:
    if payload is None:
        return tuple()
    raw = payload.get(key, [])
    return tuple(item for item in raw if isinstance(item, str)) if isinstance(raw, list) else tuple()


def _to_str_list(items: Sequence[Any]) -> list[str]:
    return [item for item in items if isinstance(item, str)]
