"""Launch gate contracts and readiness outputs."""

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence


GO_STATUS = "go"
CONDITIONAL_GO_STATUS = "conditional_go"
NO_GO_STATUS = "no_go"

PASS_CHECK_STATUS = "pass"
FAIL_CHECK_STATUS = "fail"
MISSING_CHECK_STATUS = "missing"


@dataclass(frozen=True)
class GateCheckResult:
    check_name: str
    status: str
    passed: bool
    details: str
    evidence: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ScorecardCategory:
    category_name: str
    status: str
    check_names: Sequence[str]
    details: str
    evidence: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ReadinessReport:
    status: str
    checks: Sequence[GateCheckResult]
    scorecard: Sequence[ScorecardCategory]
    blockers: Sequence[str]
    residual_risks: Sequence[str]
    summary: str


class LaunchGate(Protocol):
    def evaluate(self) -> ReadinessReport:
        """Run launch readiness checks and return a structured report."""
        ...
