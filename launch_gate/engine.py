"""Machine-checkable launch-gate readiness evaluator with reviewer scorecard."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from launch_gate.contracts import (
    CONDITIONAL_GO_STATUS,
    FAIL_CHECK_STATUS,
    GO_STATUS,
    MISSING_CHECK_STATUS,
    NO_GO_STATUS,
    PASS_CHECK_STATUS,
    GateCheckResult,
    ReadinessReport,
    ScorecardCategory,
)
from policies.loader import load_policy
from verification.runner import run_security_guarantees_verification


@dataclass
class LaunchGateConfig:
    mandatory_control_files: Sequence[str] = field(
        default_factory=lambda: (
            "app/orchestrator.py",
            "policies/engine.py",
            "retrieval/service.py",
            "tools/router.py",
            "telemetry/audit/contracts.py",
        )
    )
    policy_path: str = "policies/bundles/default/policy.json"
    guarantees_manifest_path: str = "verification/security_guarantees_manifest.json"
    audit_log_path: str = "artifacts/logs/audit.jsonl"
    replay_artifact_glob: str = "artifacts/logs/replay/*.replay.json"
    eval_summary_glob: str = "artifacts/logs/evals/*.summary.json"
    eval_jsonl_glob: str = "artifacts/logs/evals/*.jsonl"
    min_eval_pass_rate: float = 0.9
    min_audit_events: int = 5
    required_audit_event_types: Sequence[str] = field(
        default_factory=lambda: (
            "request.start",
            "request.end",
            "policy.decision",
            "retrieval.decision",
            "tool.decision",
        )
    )
    required_replay_event_types: Sequence[str] = field(
        default_factory=lambda: (
            "request.start",
            "request.end",
            "policy.decision",
            "retrieval.decision",
        )
    )
    required_tool_router_scenario_outcomes: Mapping[str, str] = field(
        default_factory=lambda: {
            "forbidden_tool_argument_attempt": "pass",
            "unauthorized_tool_use_attempt": "pass",
            "policy_bypass_attempt": "pass",
            "allowed_tool_execution_path": "pass",
            "confirmation_required_tool_flow": "pass",
        }
    )
    required_runtime_scenario_components: Mapping[str, Sequence[str]] = field(
        default_factory=lambda: {
            "prompt_injection_direct": ("orchestrator", "policy", "retrieval", "tool_routing", "audit_logging"),
            "cross_tenant_retrieval_attempt": ("orchestrator", "policy", "audit_logging"),
            "auditability_verification": ("orchestrator", "policy", "retrieval", "audit_logging"),
            "allowed_tool_execution_path": ("policy", "tool_routing"),
            "confirmation_required_tool_flow": ("policy", "tool_routing"),
        }
    )
    required_fallback_scenario_id: str = "fallback_to_rag_verification"
    require_fallback_ready: bool = True
    require_replay_artifact: bool = True
    release_relevant_invariants: Sequence[str] = field(
        default_factory=lambda: (
            "tool_router_cannot_be_bypassed",
            "policy_governs_runtime_behavior",
            "retrieval_enforces_boundaries",
            "evals_hit_real_flows",
            "launch_gate_checks_real_evidence",
            "telemetry_supports_replay",
        )
    )


@dataclass(frozen=True)
class EvalEvidenceBundle:
    summary: dict
    summary_path: str
    jsonl_records: tuple[dict, ...]
    jsonl_path: str


@dataclass
class SecurityLaunchGate:
    repo_root: Path
    config: LaunchGateConfig = field(default_factory=LaunchGateConfig)

    def evaluate(self) -> ReadinessReport:
        checks = [
            self._check_mandatory_controls(),
            self._check_guarantees_manifest_contract(),
            self._check_guarantees_manifest_evidence(),
            self._check_security_guarantees_verification(),
            self._check_policy_artifact(),
            self._check_retrieval_boundary_config(),
            self._check_tool_router_enforcement_evidence(),
            self._check_kill_switch_readiness(),
            self._check_telemetry_evidence(),
            self._check_replay_evidence(),
            self._check_eval_suite_evidence(),
            self._check_fallback_readiness(),
        ]

        by_name = {check.check_name: check for check in checks}
        scorecard = (
            self._build_scorecard_category(
                "guarantees_manifest",
                ("guarantees_manifest_contract", "guarantees_manifest_evidence", "security_guarantees_verification"),
                by_name,
            ),
            self._build_scorecard_category("policy_artifacts", ("policy_artifact",), by_name),
            self._build_scorecard_category("retrieval_boundary", ("retrieval_boundary_config",), by_name),
            self._build_scorecard_category("tool_router_enforcement", ("tool_router_enforcement_evidence",), by_name),
            self._build_scorecard_category("telemetry_evidence", ("telemetry_evidence",), by_name),
            self._build_scorecard_category("replay_evidence", ("replay_evidence",), by_name),
            self._build_scorecard_category("eval_suite_evidence", ("eval_suite_evidence",), by_name),
            self._build_scorecard_category("fallback_readiness", ("fallback_readiness",), by_name),
            self._build_scorecard_category("kill_switch_readiness", ("kill_switch_readiness",), by_name),
        )

        blocker_checks = {
            "mandatory_controls",
            "guarantees_manifest_contract",
            "security_guarantees_verification",
            "policy_artifact",
            "retrieval_boundary_config",
            "tool_router_enforcement_evidence",
            "kill_switch_readiness",
            "eval_suite_evidence",
        }
        residual_checks = {
            "guarantees_manifest_evidence",
            "telemetry_evidence",
            "replay_evidence",
            "fallback_readiness",
        }

        blockers = [self._render_issue(check) for check in checks if check.check_name in blocker_checks and not check.passed]
        residual_risks = [self._render_issue(check) for check in checks if check.check_name in residual_checks and not check.passed]

        if blockers:
            status = NO_GO_STATUS
        elif residual_risks:
            status = CONDITIONAL_GO_STATUS
        else:
            status = GO_STATUS

        summary = (
            f"status={status}; checks_passed={sum(1 for c in checks if c.passed)}/{len(checks)}; "
            f"scorecard={', '.join(f'{item.category_name}:{item.status}' for item in scorecard)}; "
            f"blockers={len(blockers)}; residual_risks={len(residual_risks)}"
        )
        return ReadinessReport(
            status=status,
            checks=tuple(checks),
            scorecard=scorecard,
            blockers=tuple(blockers),
            residual_risks=tuple(residual_risks),
            summary=summary,
        )

    def _render_issue(self, check: GateCheckResult) -> str:
        evidence_ref = ""
        for key in ("manifest_path", "policy_path", "audit_path", "summary_path", "eval_jsonl_path", "replay_path"):
            value = check.evidence.get(key)
            if isinstance(value, str) and value:
                evidence_ref = value
                break
        if evidence_ref:
            return f"{check.check_name}: {check.details} (evidence={evidence_ref})"
        return f"{check.check_name}: {check.details}"

    def _build_scorecard_category(
        self,
        category_name: str,
        check_names: Sequence[str],
        checks_by_name: dict[str, GateCheckResult],
    ) -> ScorecardCategory:
        resolved = [checks_by_name[name] for name in check_names]
        if any(item.status == MISSING_CHECK_STATUS for item in resolved):
            status = MISSING_CHECK_STATUS
        elif any(item.status == FAIL_CHECK_STATUS for item in resolved):
            status = FAIL_CHECK_STATUS
        else:
            status = PASS_CHECK_STATUS

        return ScorecardCategory(
            category_name=category_name,
            status=status,
            check_names=tuple(check_names),
            details="; ".join(item.details for item in resolved),
            evidence={name: dict(checks_by_name[name].evidence) for name in check_names},
        )

    def _check_mandatory_controls(self) -> GateCheckResult:
        missing = [path for path in self.config.mandatory_control_files if not (self.repo_root / path).is_file()]
        passed = len(missing) == 0
        details = "all mandatory controls present" if passed else f"missing mandatory controls: {', '.join(missing)}"
        return GateCheckResult(
            check_name="mandatory_controls",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={"required": list(self.config.mandatory_control_files), "missing": missing},
        )

    def _check_guarantees_manifest_contract(self) -> GateCheckResult:
        manifest_path = self.repo_root / self.config.guarantees_manifest_path
        if not manifest_path.is_file():
            return GateCheckResult(
                check_name="guarantees_manifest_contract",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="guarantees manifest missing",
                evidence={"manifest_path": str(manifest_path), "manifest_exists": False},
            )

        payload = _read_json_file(manifest_path)
        if payload is None:
            return GateCheckResult(
                check_name="guarantees_manifest_contract",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details="guarantees manifest unreadable",
                evidence={"manifest_path": str(manifest_path), "manifest_exists": True},
            )

        invariants = payload.get("invariants")
        if not isinstance(invariants, list) or len(invariants) == 0:
            return GateCheckResult(
                check_name="guarantees_manifest_contract",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details="guarantees manifest invalid: invariants must be a non-empty list",
                evidence={"manifest_path": str(manifest_path), "manifest_exists": True, "invariant_count": 0},
            )

        missing_enforcement_locations: dict[str, list[str]] = {}
        missing_test_coverage_files: dict[str, list[str]] = {}
        malformed_invariants: dict[str, list[str]] = {}
        for idx, invariant in enumerate(invariants):
            if not isinstance(invariant, dict):
                malformed_invariants[f"index:{idx}"] = ["invariant entry must be an object"]
                continue

            invariant_id = str(invariant.get("id", "")).strip() or f"index:{idx}"

            entry_errors: list[str] = []
            enforcement_locations = invariant.get("enforcement_locations")
            if not isinstance(enforcement_locations, list) or len(enforcement_locations) == 0:
                entry_errors.append("enforcement_locations must be a non-empty list")
                enforcement_locations = []
            test_coverage = invariant.get("test_coverage")
            if not isinstance(test_coverage, list) or len(test_coverage) == 0:
                entry_errors.append("test_coverage must be a non-empty list")
                test_coverage = []
            artifact_evidence = invariant.get("artifact_evidence")
            if not isinstance(artifact_evidence, list) or len(artifact_evidence) == 0:
                entry_errors.append("artifact_evidence must be a non-empty list")

            if entry_errors:
                malformed_invariants[invariant_id] = entry_errors

            missing_locations = [path for path in enforcement_locations if not (self.repo_root / str(path)).is_file()]
            if missing_locations:
                missing_enforcement_locations[invariant_id] = missing_locations

            missing_tests = [path for path in test_coverage if not (self.repo_root / str(path)).is_file()]
            if missing_tests:
                missing_test_coverage_files[invariant_id] = missing_tests

        passed = not (malformed_invariants or missing_enforcement_locations or missing_test_coverage_files)

        if passed:
            details = "guarantees manifest contract verified against code/tests/evidence"
        else:
            details_parts = []
            if malformed_invariants:
                details_parts.append("invalid invariant schema")
            if missing_enforcement_locations:
                details_parts.append("missing enforcement code")
            if missing_test_coverage_files:
                details_parts.append("missing test coverage files")
            details = "guarantees manifest contract verification failed: " + "; ".join(details_parts)

        return GateCheckResult(
            check_name="guarantees_manifest_contract",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "manifest_path": str(manifest_path),
                "manifest_exists": True,
                "invariant_count": len(invariants),
                "missing_enforcement_locations": missing_enforcement_locations,
                "missing_test_coverage_files": missing_test_coverage_files,
                "malformed_invariants": malformed_invariants,
            },
        )

    def _check_guarantees_manifest_evidence(self) -> GateCheckResult:
        manifest_path = self.repo_root / self.config.guarantees_manifest_path
        payload = _read_json_file(manifest_path)
        if payload is None:
            return GateCheckResult(
                check_name="guarantees_manifest_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="guarantees manifest evidence verification unavailable: manifest missing or unreadable",
                evidence={"manifest_path": str(manifest_path), "manifest_exists": manifest_path.is_file()},
            )

        invariants = payload.get("invariants")
        if not isinstance(invariants, list) or len(invariants) == 0:
            return GateCheckResult(
                check_name="guarantees_manifest_evidence",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details="guarantees manifest evidence verification failed: invalid invariants payload",
                evidence={"manifest_path": str(manifest_path), "manifest_exists": True},
            )

        missing_artifact_evidence: dict[str, list[str]] = {}
        failing_test_evidence: dict[str, str] = {}
        eval_bundle = self._load_latest_eval_evidence_bundle()
        eval_summary_passed = bool(eval_bundle.summary.get("passed", False)) if eval_bundle is not None else None

        for idx, invariant in enumerate(invariants):
            if not isinstance(invariant, dict):
                continue
            invariant_id = str(invariant.get("id", "")).strip() or f"index:{idx}"
            artifact_evidence = invariant.get("artifact_evidence")
            if not isinstance(artifact_evidence, list):
                missing_artifact_evidence[invariant_id] = ["artifact_evidence"]
                continue

            missing_for_invariant: list[str] = []
            for pattern in artifact_evidence:
                if not isinstance(pattern, str) or not pattern.strip() or len(tuple(self.repo_root.glob(pattern))) == 0:
                    missing_for_invariant.append(str(pattern))
            if missing_for_invariant:
                missing_artifact_evidence[invariant_id] = missing_for_invariant

            if (
                eval_summary_passed is False
                and any(isinstance(pattern, str) and "artifacts/logs/evals/" in pattern for pattern in artifact_evidence)
            ):
                failing_test_evidence[invariant_id] = "latest eval summary is not passing"

        passed = not (missing_artifact_evidence or failing_test_evidence)
        details = (
            "guarantees manifest evidence verified"
            if passed
            else "guarantees manifest evidence verification failed: missing required evidence artifacts or failing eval evidence"
        )
        return GateCheckResult(
            check_name="guarantees_manifest_evidence",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "manifest_path": str(manifest_path),
                "manifest_exists": True,
                "missing_artifact_evidence": missing_artifact_evidence,
                "failing_test_evidence": failing_test_evidence,
            },
        )


    def _check_security_guarantees_verification(self) -> GateCheckResult:
        try:
            report = run_security_guarantees_verification(
                self.repo_root,
                manifest_path=self.config.guarantees_manifest_path,
                require_evidence_presence=True,
            )
        except Exception as exc:
            return GateCheckResult(
                check_name="security_guarantees_verification",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details=f"security guarantees verification runner failed: {type(exc).__name__}",
                evidence={"manifest_path": str(self.repo_root / self.config.guarantees_manifest_path)},
            )

        results = report.get("results", []) if isinstance(report.get("results", []), list) else []
        by_id = {
            str(item.get("invariant_id", "")): item
            for item in results
            if isinstance(item, dict) and str(item.get("invariant_id", ""))
        }

        required = tuple(self.config.release_relevant_invariants)
        missing_required = [invariant_id for invariant_id in required if invariant_id not in by_id]

        failing_required: dict[str, dict[str, object]] = {}
        for invariant_id in required:
            row = by_id.get(invariant_id)
            if not isinstance(row, dict):
                continue
            if str(row.get("status", "")) != PASS_CHECK_STATUS:
                failing_required[invariant_id] = {
                    "status": str(row.get("status", "unknown")),
                    "details": str(row.get("details", "")),
                    "missing_code_paths": list(row.get("missing_code_paths", [])) if isinstance(row.get("missing_code_paths", []), list) else [],
                    "missing_test_paths": list(row.get("missing_test_paths", [])) if isinstance(row.get("missing_test_paths", []), list) else [],
                    "missing_evidence_globs": list(row.get("missing_evidence_globs", [])) if isinstance(row.get("missing_evidence_globs", []), list) else [],
                }

        passed = len(missing_required) == 0 and len(failing_required) == 0
        details = (
            "security guarantees verification satisfied for all release-relevant invariants"
            if passed
            else "security guarantees verification failed for release-relevant invariants"
        )

        return GateCheckResult(
            check_name="security_guarantees_verification",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "manifest_path": str(self.repo_root / self.config.guarantees_manifest_path),
                "verification_status": str(report.get("status", "unknown")),
                "required_release_invariants": list(required),
                "missing_release_invariants": missing_required,
                "failing_release_invariants": failing_required,
            },
        )

    def _check_policy_artifact(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        if not policy_path.is_file():
            return GateCheckResult(
                check_name="policy_artifact",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="policy artifact missing",
                evidence={"policy_path": str(policy_path), "policy_exists": False},
            )

        payload = _read_json_file(policy_path)
        runtime_policy = load_policy(policy_path, environment="production")
        if payload is None:
            return GateCheckResult(
                check_name="policy_artifact",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details="policy artifact unreadable",
                evidence={"policy_path": str(policy_path), "policy_exists": True},
            )

        passed = runtime_policy.valid
        details = "policy artifact valid" if passed else "policy artifact invalid"
        return GateCheckResult(
            check_name="policy_artifact",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "policy_path": str(policy_path),
                "policy_exists": True,
                "policy_valid": runtime_policy.valid,
                "validation_errors": list(runtime_policy.validation_errors),
                "policy_keys": sorted(payload.keys()),
            },
        )

    def _check_retrieval_boundary_config(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")
        if not runtime_policy.valid:
            return GateCheckResult(
                check_name="retrieval_boundary_config",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details="retrieval boundary config invalid: policy artifact invalid",
                evidence={"policy_path": str(policy_path), "policy_valid": runtime_policy.valid},
            )

        allowed_tenants = runtime_policy.retrieval.allowed_tenants
        tenant_sources = runtime_policy.retrieval.tenant_allowed_sources
        trust_domains = tuple(runtime_policy.retrieval.allowed_trust_domains)

        tenants_missing_allowlists = [tenant for tenant in allowed_tenants if len(tenant_sources.get(tenant, tuple())) == 0]
        unexpected_tenant_mappings = [tenant for tenant in tenant_sources.keys() if tenant not in set(allowed_tenants)]

        passed = (
            len(allowed_tenants) > 0
            and len(tenants_missing_allowlists) == 0
            and len(unexpected_tenant_mappings) == 0
            and runtime_policy.retrieval.require_trust_metadata
            and runtime_policy.retrieval.require_provenance
            and len(trust_domains) > 0
        )
        details = (
            "retrieval boundary config satisfied"
            if passed
            else "retrieval boundary config missing tenant/source/trust/provenance enforcement"
        )
        return GateCheckResult(
            check_name="retrieval_boundary_config",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "allowed_tenants": list(allowed_tenants),
                "tenant_allowed_sources": {tenant: list(sources) for tenant, sources in tenant_sources.items()},
                "tenants_missing_source_allowlists": tenants_missing_allowlists,
                "unexpected_tenant_source_mappings": unexpected_tenant_mappings,
                "require_trust_metadata": runtime_policy.retrieval.require_trust_metadata,
                "require_provenance": runtime_policy.retrieval.require_provenance,
                "allowed_trust_domains": list(trust_domains),
            },
        )

    def _check_tool_router_enforcement_evidence(self) -> GateCheckResult:
        bundle = self._load_latest_eval_evidence_bundle()
        if bundle is None:
            return GateCheckResult(
                check_name="tool_router_enforcement_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="tool-router enforcement evidence missing: aligned eval summary+jsonl not found",
                evidence={"eval_summary_glob": self.config.eval_summary_glob, "eval_jsonl_glob": self.config.eval_jsonl_glob},
            )

        by_id = {
            str(item.get("scenario_id", "")): item
            for item in bundle.jsonl_records
            if isinstance(item, dict) and str(item.get("scenario_id", ""))
        }

        missing_or_mismatched: dict[str, dict[str, str]] = {}
        for scenario_id, expected in self.config.required_tool_router_scenario_outcomes.items():
            row = by_id.get(scenario_id)
            actual = str(row.get("outcome", "")) if isinstance(row, dict) else None
            if actual != expected:
                missing_or_mismatched[scenario_id] = {"expected": expected, "actual": actual or "missing"}

        realism_failures: dict[str, str] = {}
        for scenario_id in self.config.required_tool_router_scenario_outcomes:
            row = by_id.get(scenario_id)
            if not isinstance(row, dict):
                continue
            evidence = row.get("evidence", {}) if isinstance(row.get("evidence", {}), dict) else {}
            if evidence.get("mocked") is True:
                realism_failures[scenario_id] = "scenario evidence is mocked"
                continue
            exercised = evidence.get("runtime_components_exercised", {}) if isinstance(evidence.get("runtime_components_exercised", {}), dict) else {}
            if not bool(exercised.get("policy", False)) or not bool(exercised.get("tool_routing", False)):
                realism_failures[scenario_id] = "policy/tool_routing runtime components not exercised"

        passed = len(missing_or_mismatched) == 0 and len(realism_failures) == 0
        details = (
            "tool-router enforcement evidence satisfied"
            if passed
            else "tool-router enforcement evidence missing required outcomes or runtime realism proof"
        )
        return GateCheckResult(
            check_name="tool_router_enforcement_evidence",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "summary_path": bundle.summary_path,
                "eval_jsonl_path": bundle.jsonl_path,
                "required_scenarios": dict(self.config.required_tool_router_scenario_outcomes),
                "scenario_outcomes": {
                    k: str((by_id.get(k, {}) if isinstance(by_id.get(k, {}), dict) else {}).get("outcome", "missing"))
                    for k in self.config.required_tool_router_scenario_outcomes
                },
                "missing_or_mismatched": missing_or_mismatched,
                "realism_failures": realism_failures,
            },
        )

    def _check_kill_switch_readiness(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")

        if not policy_path.is_file():
            return GateCheckResult(
                check_name="kill_switch_readiness",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="kill-switch readiness missing: policy artifact missing",
                evidence={"policy_path": str(policy_path), "policy_exists": False},
            )

        passed = runtime_policy.valid and (not runtime_policy.kill_switch)
        details = "kill switch disabled for production" if passed else "kill switch enabled or policy invalid for production"
        return GateCheckResult(
            check_name="kill_switch_readiness",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "policy_path": str(policy_path),
                "policy_valid": runtime_policy.valid,
                "kill_switch": runtime_policy.kill_switch,
            },
        )

    def _check_telemetry_evidence(self) -> GateCheckResult:
        audit_path = self.repo_root / self.config.audit_log_path
        if not audit_path.is_file():
            return GateCheckResult(
                check_name="telemetry_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="telemetry evidence missing: audit log missing",
                evidence={"audit_path": str(audit_path), "audit_exists": False},
            )

        records = _read_jsonl(audit_path)
        if len(records) == 0:
            return GateCheckResult(
                check_name="telemetry_evidence",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details="telemetry evidence unreadable or empty",
                evidence={"audit_path": str(audit_path), "audit_exists": True, "event_count": 0},
            )

        event_types = [record.get("event_type") for record in records if isinstance(record, dict)]
        missing_types = [item for item in self.config.required_audit_event_types if item not in event_types]
        lifecycle_events = [
            item
            for item in records
            if isinstance(item, dict) and str(item.get("event_type")) in {"request.start", "request.end", "policy.decision"}
        ]
        missing_identity_fields = [
            idx
            for idx, event in enumerate(lifecycle_events)
            if not event.get("request_id") or not event.get("actor_id") or not event.get("tenant_id")
        ]

        passed = len(records) >= self.config.min_audit_events and len(missing_types) == 0 and len(missing_identity_fields) == 0
        details = "telemetry evidence satisfied" if passed else "telemetry evidence incomplete"
        return GateCheckResult(
            check_name="telemetry_evidence",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "audit_path": str(audit_path),
                "audit_exists": True,
                "event_count": len(records),
                "required_min": self.config.min_audit_events,
                "missing_event_types": missing_types,
                "identity_field_violations": len(missing_identity_fields),
            },
        )

    def _check_replay_evidence(self) -> GateCheckResult:
        replay_files = sorted(self.repo_root.glob(self.config.replay_artifact_glob))
        if not self.config.require_replay_artifact:
            return GateCheckResult(
                check_name="replay_evidence",
                status=PASS_CHECK_STATUS,
                passed=True,
                details="replay evidence check not required",
                evidence={"required": False, "matched_files": [str(p) for p in replay_files]},
            )

        if not replay_files:
            return GateCheckResult(
                check_name="replay_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="replay evidence missing: no replay artifacts found",
                evidence={"glob": self.config.replay_artifact_glob, "matched_files": []},
            )

        latest = replay_files[-1]
        artifact = _read_json_file(latest)
        if artifact is None:
            return GateCheckResult(
                check_name="replay_evidence",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details="replay evidence unreadable",
                evidence={"replay_path": str(latest)},
            )

        event_type_counts = artifact.get("event_type_counts", {}) if isinstance(artifact.get("event_type_counts"), dict) else {}
        missing_event_types = [
            event_type for event_type in self.config.required_replay_event_types if int(event_type_counts.get(event_type, 0) or 0) <= 0
        ]
        coverage = artifact.get("coverage") if isinstance(artifact.get("coverage"), dict) else {}
        request_complete = bool(coverage.get("request_lifecycle_complete", False))

        passed = artifact.get("replay_version") == "1" and len(missing_event_types) == 0 and request_complete
        details = "replay evidence satisfied" if passed else "replay evidence incomplete or invalid"
        return GateCheckResult(
            check_name="replay_evidence",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "replay_path": str(latest),
                "replay_version": artifact.get("replay_version"),
                "missing_event_types": missing_event_types,
                "event_type_counts": event_type_counts,
                "request_lifecycle_complete": request_complete,
            },
        )

    def _check_eval_suite_evidence(self) -> GateCheckResult:
        bundle = self._load_latest_eval_evidence_bundle()
        if bundle is None:
            return GateCheckResult(
                check_name="eval_suite_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="eval suite evidence missing: aligned eval summary+jsonl not found",
                evidence={"summary_glob": self.config.eval_summary_glob, "jsonl_glob": self.config.eval_jsonl_glob},
            )

        summary = bundle.summary
        total = int(summary.get("total", 0)) if isinstance(summary.get("total", 0), int) else 0
        passed_count = int(summary.get("passed_count", 0)) if isinstance(summary.get("passed_count", 0), int) else 0
        pass_rate = (passed_count / total) if total > 0 else 0.0

        outcomes = summary.get("outcomes", {}) if isinstance(summary.get("outcomes"), dict) else {}
        fail_count = int(outcomes.get("fail", 0)) if isinstance(outcomes.get("fail", 0), int) else 0
        inconclusive_count = int(outcomes.get("inconclusive", 0)) if isinstance(outcomes.get("inconclusive", 0), int) else 0

        calculated_total = len(bundle.jsonl_records)
        calculated_passed = sum(1 for item in bundle.jsonl_records if str(item.get("outcome", "")) == "pass")
        summary_matches_jsonl = total == calculated_total and passed_count == calculated_passed

        scenario_map = {
            str(item.get("scenario_id", "")): item
            for item in bundle.jsonl_records
            if isinstance(item, dict) and str(item.get("scenario_id", ""))
        }
        realism_failures: dict[str, str] = {}
        for scenario_id, required_components in self.config.required_runtime_scenario_components.items():
            row = scenario_map.get(scenario_id)
            if row is None:
                realism_failures[scenario_id] = "scenario evidence row missing"
                continue
            evidence = row.get("evidence", {}) if isinstance(row.get("evidence", {}), dict) else {}
            if evidence.get("mocked") is True:
                realism_failures[scenario_id] = "scenario evidence is mocked"
                continue
            exercised = evidence.get("runtime_components_exercised", {}) if isinstance(evidence.get("runtime_components_exercised", {}), dict) else {}
            missing_components = [component for component in required_components if not bool(exercised.get(component, False))]
            if missing_components:
                realism_failures[scenario_id] = f"missing runtime components: {', '.join(missing_components)}"

        passed = (
            total > 0
            and pass_rate >= self.config.min_eval_pass_rate
            and fail_count == 0
            and inconclusive_count == 0
            and bool(summary.get("passed", False))
            and summary_matches_jsonl
            and len(realism_failures) == 0
        )
        details = (
            "eval suite evidence satisfied"
            if passed
            else "eval suite evidence failed threshold/outcome health or runtime-realism checks"
        )
        return GateCheckResult(
            check_name="eval_suite_evidence",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "summary_path": bundle.summary_path,
                "eval_jsonl_path": bundle.jsonl_path,
                "total": total,
                "passed_count": passed_count,
                "pass_rate": pass_rate,
                "required_min_pass_rate": self.config.min_eval_pass_rate,
                "fail": fail_count,
                "inconclusive": inconclusive_count,
                "summary_passed": bool(summary.get("passed", False)),
                "jsonl_record_count": calculated_total,
                "jsonl_pass_count": calculated_passed,
                "summary_matches_jsonl": summary_matches_jsonl,
                "required_runtime_scenarios": {
                    key: list(value) for key, value in self.config.required_runtime_scenario_components.items()
                },
                "runtime_realism_failures": realism_failures,
            },
        )

    def _check_fallback_readiness(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")

        if not self.config.require_fallback_ready:
            return GateCheckResult(
                check_name="fallback_readiness",
                status=PASS_CHECK_STATUS,
                passed=True,
                details="fallback readiness check not required",
                evidence={"required": False},
            )

        if not policy_path.is_file():
            return GateCheckResult(
                check_name="fallback_readiness",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="fallback readiness missing: policy artifact missing",
                evidence={"policy_path": str(policy_path), "policy_exists": False},
            )

        bundle = self._load_latest_eval_evidence_bundle()
        if bundle is None:
            return GateCheckResult(
                check_name="fallback_readiness",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="fallback readiness missing: aligned eval summary+jsonl not found",
                evidence={"eval_summary_glob": self.config.eval_summary_glob, "eval_jsonl_glob": self.config.eval_jsonl_glob},
            )

        by_id = {
            str(item.get("scenario_id", "")): str(item.get("outcome", ""))
            for item in bundle.jsonl_records
            if isinstance(item, dict)
        }
        fallback_outcome = by_id.get(self.config.required_fallback_scenario_id, "missing")
        policy_ready = runtime_policy.valid and runtime_policy.fallback_to_rag

        passed = policy_ready and fallback_outcome == "pass"
        if not runtime_policy.valid:
            details = "fallback readiness not satisfied: policy invalid"
        elif not runtime_policy.fallback_to_rag:
            details = "fallback readiness not satisfied: fallback_to_rag disabled"
        elif fallback_outcome != "pass":
            details = "fallback readiness not satisfied: fallback scenario did not pass"
        else:
            details = "fallback readiness satisfied"

        return GateCheckResult(
            check_name="fallback_readiness",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "policy_path": str(policy_path),
                "policy_valid": runtime_policy.valid,
                "fallback_to_rag": runtime_policy.fallback_to_rag,
                "summary_path": bundle.summary_path,
                "eval_jsonl_path": bundle.jsonl_path,
                "required_fallback_scenario": self.config.required_fallback_scenario_id,
                "fallback_scenario_outcome": fallback_outcome,
            },
        )

    def _load_latest_eval_evidence_bundle(self) -> EvalEvidenceBundle | None:
        summary_files = sorted(self.repo_root.glob(self.config.eval_summary_glob))
        if not summary_files:
            return None

        for summary_path in reversed(summary_files):
            summary = _read_json_file(summary_path)
            if summary is None:
                continue

            base = summary_path.name.removesuffix(".summary.json")
            jsonl_path = self.repo_root / "artifacts" / "logs" / "evals" / f"{base}.jsonl"
            if not jsonl_path.is_file():
                continue

            records = _read_jsonl(jsonl_path)
            if len(records) == 0:
                continue

            return EvalEvidenceBundle(
                summary=summary,
                summary_path=str(summary_path),
                jsonl_records=tuple(records),
                jsonl_path=str(jsonl_path),
            )

        return None


def _read_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                records.append(parsed)
    except (OSError, json.JSONDecodeError):
        return []
    return records


def _read_json_file(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _as_dict(report: ReadinessReport) -> dict[str, object]:
    return {
        "status": report.status,
        "summary": report.summary,
        "blockers": list(report.blockers),
        "residual_risks": list(report.residual_risks),
        "scorecard": [
            {
                "category_name": item.category_name,
                "status": item.status,
                "details": item.details,
                "check_names": list(item.check_names),
                "evidence": dict(item.evidence),
            }
            for item in report.scorecard
        ],
        "checks": [
            {
                "check_name": check.check_name,
                "status": check.status,
                "passed": check.passed,
                "details": check.details,
                "evidence": dict(check.evidence),
            }
            for check in report.checks
        ],
    }


def main() -> None:
    report = SecurityLaunchGate(repo_root=Path(".")).evaluate()
    print(json.dumps(_as_dict(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
