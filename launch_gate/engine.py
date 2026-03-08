"""Machine-checkable launch-gate readiness evaluator with reviewer scorecard."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

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
    audit_log_path: str = "artifacts/logs/audit.jsonl"
    replay_artifact_glob: str = "artifacts/logs/replay*.json"
    eval_summary_glob: str = "artifacts/logs/evals/*.summary.json"
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
    require_fallback_ready: bool = True
    require_replay_artifact: bool = True


@dataclass
class SecurityLaunchGate:
    repo_root: Path
    config: LaunchGateConfig = field(default_factory=LaunchGateConfig)

    def evaluate(self) -> ReadinessReport:
        checks = [
            self._check_mandatory_controls(),
            self._check_policy_artifact(),
            self._check_retrieval_boundary_config(),
            self._check_tool_router_enforcement_config(),
            self._check_kill_switch_readiness(),
            self._check_telemetry_evidence(),
            self._check_eval_suite_evidence(),
            self._check_fallback_readiness(),
        ]

        by_name = {check.check_name: check for check in checks}
        scorecard = (
            self._build_scorecard_category("policy_artifacts", ("policy_artifact",), by_name),
            self._build_scorecard_category("telemetry_evidence", ("telemetry_evidence",), by_name),
            self._build_scorecard_category("eval_suite_evidence", ("eval_suite_evidence",), by_name),
            self._build_scorecard_category("fallback_readiness", ("fallback_readiness",), by_name),
            self._build_scorecard_category("kill_switch_readiness", ("kill_switch_readiness",), by_name),
        )

        blocker_checks = {
            "mandatory_controls",
            "policy_artifact",
            "retrieval_boundary_config",
            "tool_router_enforcement_config",
            "kill_switch_readiness",
            "eval_suite_evidence",
        }
        residual_checks = {"telemetry_evidence", "fallback_readiness"}

        blockers = [check.details for check in checks if check.check_name in blocker_checks and not check.passed]
        residual_risks = [check.details for check in checks if check.check_name in residual_checks and not check.passed]

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

    def _check_policy_artifact(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")

        if not policy_path.is_file():
            return GateCheckResult(
                check_name="policy_artifact",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="policy artifact missing",
                evidence={"policy_path": str(policy_path), "policy_exists": False},
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

    def _check_tool_router_enforcement_config(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")
        if not runtime_policy.valid:
            return GateCheckResult(
                check_name="tool_router_enforcement_config",
                status=FAIL_CHECK_STATUS,
                passed=False,
                details="tool-router enforcement config invalid: policy artifact invalid",
                evidence={"policy_path": str(policy_path), "policy_valid": runtime_policy.valid},
            )

        allowed_tools = runtime_policy.tools.allowed_tools
        rate_limits = runtime_policy.tools.rate_limits_per_tool
        forbidden_fields = runtime_policy.tools.forbidden_fields_per_tool

        passed = len(allowed_tools) > 0 and len(rate_limits) > 0 and len(forbidden_fields) > 0
        details = (
            "tool-router enforcement config satisfied"
            if passed
            else "tool-router enforcement config missing allowlist/rate-limit/forbidden-field controls"
        )
        return GateCheckResult(
            check_name="tool_router_enforcement_config",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "allowed_tools": list(allowed_tools),
                "rate_limits_per_tool": dict(rate_limits),
                "forbidden_fields_per_tool": {tool: list(fields) for tool, fields in forbidden_fields.items()},
                "forbidden_tools": list(runtime_policy.tools.forbidden_tools),
                "confirmation_required_tools": list(runtime_policy.tools.confirmation_required_tools),
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
        replay_files = sorted(self.repo_root.glob(self.config.replay_artifact_glob))
        if not audit_path.is_file():
            return GateCheckResult(
                check_name="telemetry_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="telemetry evidence missing: audit log missing",
                evidence={"audit_path": str(audit_path), "audit_exists": False, "replay_files": [str(p) for p in replay_files]},
            )

        records = _read_jsonl(audit_path)
        event_types = [record.get("event_type") for record in records if isinstance(record, dict)]
        missing_types = [item for item in self.config.required_audit_event_types if item not in event_types]

        if self.config.require_replay_artifact and not replay_files:
            return GateCheckResult(
                check_name="telemetry_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="telemetry evidence missing: replay artifact missing",
                evidence={
                    "audit_path": str(audit_path),
                    "audit_exists": True,
                    "event_count": len(records),
                    "missing_event_types": missing_types,
                    "replay_files": [],
                },
            )

        passed = len(records) >= self.config.min_audit_events and len(missing_types) == 0
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
                "replay_files": [str(p) for p in replay_files],
            },
        )

    def _check_eval_suite_evidence(self) -> GateCheckResult:
        summary_files = sorted(self.repo_root.glob(self.config.eval_summary_glob))
        if not summary_files:
            return GateCheckResult(
                check_name="eval_suite_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="eval suite evidence missing",
                evidence={"glob": self.config.eval_summary_glob, "matched_files": []},
            )

        latest = summary_files[-1]
        summary = _read_json_file(latest)
        if summary is None:
            return GateCheckResult(
                check_name="eval_suite_evidence",
                status=MISSING_CHECK_STATUS,
                passed=False,
                details="eval suite evidence unreadable",
                evidence={"summary_path": str(latest)},
            )

        total = int(summary.get("total", 0)) if isinstance(summary.get("total", 0), int) else 0
        passed_count = int(summary.get("passed_count", 0)) if isinstance(summary.get("passed_count", 0), int) else 0
        pass_rate = (passed_count / total) if total > 0 else 0.0

        outcomes = summary.get("outcomes", {}) if isinstance(summary.get("outcomes"), dict) else {}
        fail_count = int(outcomes.get("fail", 0)) if isinstance(outcomes.get("fail", 0), int) else 0
        inconclusive_count = int(outcomes.get("inconclusive", 0)) if isinstance(outcomes.get("inconclusive", 0), int) else 0

        passed = total > 0 and pass_rate >= self.config.min_eval_pass_rate and fail_count == 0 and inconclusive_count == 0
        details = "eval suite evidence satisfied" if passed else "eval suite evidence failed threshold/outcome health"
        return GateCheckResult(
            check_name="eval_suite_evidence",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "summary_path": str(latest),
                "total": total,
                "passed_count": passed_count,
                "pass_rate": pass_rate,
                "required_min_pass_rate": self.config.min_eval_pass_rate,
                "fail": fail_count,
                "inconclusive": inconclusive_count,
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

        passed = runtime_policy.valid and runtime_policy.fallback_to_rag
        details = "fallback readiness satisfied" if passed else "fallback readiness not satisfied"
        if not runtime_policy.valid:
            details = "fallback readiness not satisfied: policy invalid"
        return GateCheckResult(
            check_name="fallback_readiness",
            status=PASS_CHECK_STATUS if passed else FAIL_CHECK_STATUS,
            passed=passed,
            details=details,
            evidence={
                "policy_path": str(policy_path),
                "policy_valid": runtime_policy.valid,
                "fallback_to_rag": runtime_policy.fallback_to_rag,
            },
        )


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
