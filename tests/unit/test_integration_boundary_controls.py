"""Tests for external integration inventory and boundary enforcement controls."""

from app.integrations import IntegrationBoundaryEnforcer, IntegrationBoundaryError, IntegrationInventory
from identity.models import ActorType, build_identity
from policies.engine import RuntimePolicyEngine
from policies.schema import build_runtime_policy


def _policy_engine() -> RuntimePolicyEngine:
    payload = {
        "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "medium"},
        "risk_tiers": {"medium": {"max_retrieval_top_k": 5, "tools_enabled": True}},
        "retrieval": {
            "allowed_tenants": ["tenant-a"],
            "tenant_allowed_sources": {"tenant-a": ["kb-main"]},
            "require_trust_metadata": True,
            "require_provenance": True,
            "allowed_trust_domains": ["internal"],
        },
        "tools": {
            "allowed_tools": ["ticket_lookup"],
            "forbidden_tools": [],
            "confirmation_required_tools": [],
            "forbidden_fields_per_tool": {},
            "rate_limits_per_tool": {},
        },
        "integrations": {
            "allowed_integrations": ["retrieval_backend.default"],
            "tenant_allowed_integrations": {"tenant-a": ["retrieval_backend.default"]},
            "allowed_data_classes": ["internal_support", "metadata"],
        },
    }
    return RuntimePolicyEngine(policy=build_runtime_policy(environment="test", payload=payload))


def _identity():
    return build_identity(
        actor_id="assistant-1",
        actor_type=ActorType.ASSISTANT_RUNTIME,
        tenant_id="tenant-a",
        session_id="session-1",
        trust_level="medium",
        allowed_capabilities=("integration.egress", "retrieval.search"),
    )


def test_unknown_integration_target_denied() -> None:
    inventory = IntegrationInventory(records={})
    enforcer = IntegrationBoundaryEnforcer(inventory=inventory, policy_engine=_policy_engine())

    try:
        enforcer.enforce(
            request_id="req-1",
            identity=_identity(),
            integration_id="unknown.endpoint",
            tenant_id="tenant-a",
            data_classes=["metadata"],
            payload={"request_id": "req-1", "tenant_id": "tenant-a"},
            origin={"component": "retrieval"},
        )
        assert False, "expected IntegrationBoundaryError"
    except IntegrationBoundaryError as exc:
        assert "not inventoried" in str(exc)


def test_disallowed_data_class_denied() -> None:
    inventory = IntegrationInventory.from_policy_payload(
        {
            "integrations": [
                {
                    "integration_id": "retrieval_backend.default",
                    "category": "retrieval_backend",
                    "trust_class": "restricted",
                    "allowed_data_classes": ["metadata"],
                    "tenant_scope": "tenant",
                    "auth_method": "service_identity",
                    "logging_constraints": ["query_redacted"],
                    "failure_mode": "deny_closed",
                }
            ]
        }
    )
    enforcer = IntegrationBoundaryEnforcer(inventory=inventory, policy_engine=_policy_engine())

    try:
        enforcer.enforce(
            request_id="req-2",
            identity=_identity(),
            integration_id="retrieval_backend.default",
            tenant_id="tenant-a",
            data_classes=["internal_support"],
            payload={"request_id": "req-2", "tenant_id": "tenant-a"},
            origin={"component": "retrieval"},
        )
        assert False, "expected IntegrationBoundaryError"
    except IntegrationBoundaryError as exc:
        assert "data class not allowlisted" in str(exc)


def test_sensitive_fields_are_stripped_and_origin_tagged() -> None:
    inventory = IntegrationInventory.from_policy_payload(
        {
            "integrations": [
                {
                    "integration_id": "retrieval_backend.default",
                    "category": "retrieval_backend",
                    "trust_class": "restricted",
                    "allowed_data_classes": ["internal_support", "metadata"],
                    "tenant_scope": "tenant",
                    "auth_method": "service_identity",
                    "logging_constraints": ["query_redacted"],
                    "failure_mode": "deny_closed",
                    "strip_fields": ["query_text"],
                    "required_payload_fields": ["request_id", "tenant_id"],
                }
            ]
        }
    )
    enforcer = IntegrationBoundaryEnforcer(inventory=inventory, policy_engine=_policy_engine())

    payload = enforcer.enforce(
        request_id="req-3",
        identity=_identity(),
        integration_id="retrieval_backend.default",
        tenant_id="tenant-a",
        data_classes=["internal_support"],
        payload={"request_id": "req-3", "tenant_id": "tenant-a", "query_text": "password reset"},
        origin={"component": "retrieval"},
    )
    assert payload["query_text"] == "[stripped]"
    assert payload["_integration"]["integration_id"] == "retrieval_backend.default"
