"""Infrastructure egress and service-boundary policy helpers."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Mapping, Sequence


class InfrastructureBoundaryError(RuntimeError):
    """Raised when a boundary policy denies access/egress."""


@dataclass(frozen=True)
class EgressDestination:
    destination_id: str
    host: str
    trust_class: str
    category: str


@dataclass
class InfrastructureBoundaryPolicy:
    allowed_destinations: Mapping[str, EgressDestination]
    forbidden_host_patterns: Sequence[str]
    component_access_rules: Mapping[str, Sequence[str]]
    internal_only_services: Sequence[str]
    sandbox_allowlist: Sequence[str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "InfrastructureBoundaryPolicy":
        allowed_raw = payload.get("allowed_destinations", [])
        allowed: dict[str, EgressDestination] = {}
        if isinstance(allowed_raw, list):
            for item in allowed_raw:
                if not isinstance(item, Mapping):
                    continue
                destination_id = str(item.get("destination_id", "")).strip()
                host = str(item.get("host", "")).strip()
                trust_class = str(item.get("trust_class", "")).strip()
                category = str(item.get("category", "")).strip()
                if destination_id and host and trust_class and category:
                    allowed[destination_id] = EgressDestination(
                        destination_id=destination_id,
                        host=host,
                        trust_class=trust_class,
                        category=category,
                    )

        forbidden_raw = payload.get("forbidden_host_patterns", [])
        forbidden = tuple(str(item) for item in forbidden_raw if isinstance(item, str) and item.strip())

        rules_raw = payload.get("component_access_rules", {})
        rules: dict[str, tuple[str, ...]] = {}
        if isinstance(rules_raw, Mapping):
            for source, targets in rules_raw.items():
                if not isinstance(source, str):
                    continue
                if not isinstance(targets, list):
                    continue
                cleaned = tuple(str(item) for item in targets if isinstance(item, str) and item)
                rules[source] = cleaned

        internal_only = tuple(str(item) for item in payload.get("internal_only_services", []) if isinstance(item, str) and item)
        sandbox_allow = tuple(str(item) for item in payload.get("sandbox_allowlist", []) if isinstance(item, str) and item)

        return cls(
            allowed_destinations=allowed,
            forbidden_host_patterns=forbidden,
            component_access_rules=rules,
            internal_only_services=internal_only,
            sandbox_allowlist=sandbox_allow,
        )

    def validate_egress(self, *, component: str, destination_id: str, sandbox: bool = False) -> EgressDestination:
        destination = self.allowed_destinations.get(destination_id)
        if destination is None:
            raise InfrastructureBoundaryError("unknown outbound destination")

        if any(fnmatch(destination.host, pattern) for pattern in self.forbidden_host_patterns):
            raise InfrastructureBoundaryError("forbidden outbound destination")

        if sandbox and destination_id not in self.sandbox_allowlist:
            raise InfrastructureBoundaryError("sandbox egress destination not allowlisted")

        if destination.category in self.internal_only_services and component != "app_runtime":
            raise InfrastructureBoundaryError("disallowed service boundary crossing")

        return destination

    def validate_component_access(self, *, source: str, target: str) -> None:
        targets = self.component_access_rules.get(source, tuple())
        if target not in set(targets):
            raise InfrastructureBoundaryError("disallowed service boundary crossing")
