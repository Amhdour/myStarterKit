"""External integration inventory and boundary enforcement controls."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from app.infrastructure_boundaries import InfrastructureBoundaryPolicy
from identity.models import ActorIdentity, validate_identity
from policies.contracts import PolicyEngine


class IntegrationBoundaryError(RuntimeError):
    """Raised when an integration crossing fails security controls."""


@dataclass(frozen=True)
class IntegrationRecord:
    integration_id: str
    category: str
    trust_class: str
    allowed_data_classes: tuple[str, ...]
    tenant_scope: str
    auth_method: str
    logging_constraints: tuple[str, ...]
    failure_mode: str
    max_payload_bytes: int = 16_384
    strip_fields: tuple[str, ...] = tuple()
    required_payload_fields: tuple[str, ...] = tuple()


@dataclass
class IntegrationInventory:
    records: Mapping[str, IntegrationRecord]

    def get(self, integration_id: str) -> IntegrationRecord | None:
        return self.records.get(integration_id)

    @classmethod
    def from_policy_payload(cls, payload: Mapping[str, object]) -> "IntegrationInventory":
        parsed: dict[str, IntegrationRecord] = {}
        for item in payload.get("integrations", []):
            if not isinstance(item, Mapping):
                continue
            integration_id = str(item.get("integration_id", "")).strip()
            if not integration_id:
                continue
            parsed[integration_id] = IntegrationRecord(
                integration_id=integration_id,
                category=str(item.get("category", "")).strip(),
                trust_class=str(item.get("trust_class", "")).strip() or "untrusted",
                allowed_data_classes=tuple(str(value) for value in item.get("allowed_data_classes", []) if isinstance(value, str)),
                tenant_scope=str(item.get("tenant_scope", "tenant")).strip() or "tenant",
                auth_method=str(item.get("auth_method", "unknown")).strip() or "unknown",
                logging_constraints=tuple(
                    str(value) for value in item.get("logging_constraints", []) if isinstance(value, str)
                ),
                failure_mode=str(item.get("failure_mode", "deny_closed")).strip() or "deny_closed",
                max_payload_bytes=int(item.get("max_payload_bytes", 16_384)),
                strip_fields=tuple(str(value) for value in item.get("strip_fields", []) if isinstance(value, str)),
                required_payload_fields=tuple(
                    str(value) for value in item.get("required_payload_fields", []) if isinstance(value, str)
                ),
            )
        return cls(records=parsed)


@dataclass
class IntegrationBoundaryEnforcer:
    inventory: IntegrationInventory
    policy_engine: PolicyEngine
    infrastructure_policy: InfrastructureBoundaryPolicy | None = None

    def enforce(
        self,
        *,
        request_id: str,
        identity: ActorIdentity,
        integration_id: str,
        tenant_id: str,
        data_classes: Sequence[str],
        payload: Mapping[str, object],
        origin: Mapping[str, str],
    ) -> Mapping[str, object]:
        validate_identity(identity)
        record = self.inventory.get(integration_id)
        if record is None:
            raise IntegrationBoundaryError("integration not inventoried")

        if self.infrastructure_policy is not None:
            self.infrastructure_policy.validate_egress(component="app_runtime", destination_id=integration_id)

        if tenant_id != identity.tenant_id:
            raise IntegrationBoundaryError("tenant mismatch")

        if record.tenant_scope == "tenant" and tenant_id != identity.tenant_id:
            raise IntegrationBoundaryError("tenant scope violation")

        allowed_data_classes = set(record.allowed_data_classes)
        if any(data_class not in allowed_data_classes for data_class in data_classes):
            raise IntegrationBoundaryError("data class not allowlisted")

        decision = self.policy_engine.evaluate(
            request_id=request_id,
            action="integration.egress",
            identity=identity,
            context={
                "tenant_id": tenant_id,
                "integration_id": integration_id,
                "category": record.category,
                "trust_class": record.trust_class,
                "data_classes": list(data_classes),
            },
        )
        if not decision.allow:
            raise IntegrationBoundaryError(f"policy denied: {decision.reason}")

        sanitized = self._strip_sensitive_fields(payload=payload, strip_fields=record.strip_fields)
        self._validate_payload_schema(payload=sanitized, required_fields=record.required_payload_fields)
        self._validate_payload_size(payload=sanitized, max_bytes=record.max_payload_bytes)
        return {
            **sanitized,
            "_integration": {
                "integration_id": integration_id,
                "category": record.category,
                "trust_class": record.trust_class,
                "origin": dict(origin),
                "policy_action": "integration.egress",
            },
        }

    def _strip_sensitive_fields(self, *, payload: Mapping[str, object], strip_fields: Sequence[str]) -> dict[str, object]:
        output = dict(payload)
        for field in strip_fields:
            if field in output:
                output[field] = "[stripped]"
        return output

    def _validate_payload_schema(self, *, payload: Mapping[str, object], required_fields: Sequence[str]) -> None:
        for field in required_fields:
            if field not in payload:
                raise IntegrationBoundaryError(f"payload missing required field: {field}")

    def _validate_payload_size(self, *, payload: Mapping[str, object], max_bytes: int) -> None:
        encoded_size = len(str(payload).encode("utf-8"))
        if encoded_size > max_bytes:
            raise IntegrationBoundaryError("payload exceeds size limit")

