"""Infrastructure boundary policy tests."""

from app.infrastructure_boundaries import InfrastructureBoundaryError, InfrastructureBoundaryPolicy


def _policy() -> InfrastructureBoundaryPolicy:
    return InfrastructureBoundaryPolicy.from_payload(
        {
            "allowed_destinations": [
                {"destination_id": "model_provider.default", "host": "model-api.internal.example", "trust_class": "restricted", "category": "model_provider"},
                {"destination_id": "tool_endpoint.ticket_lookup", "host": "tools.internal.example", "trust_class": "restricted", "category": "tool_endpoint"},
                {"destination_id": "storage_output.audit_jsonl", "host": "audit.internal.example", "trust_class": "trusted", "category": "storage_output"},
            ],
            "forbidden_host_patterns": ["169.254.*", "localhost"],
            "component_access_rules": {
                "app_runtime": ["model_provider", "tool_endpoint"],
                "high_risk_tool_sandbox": ["tool_endpoint", "storage_output"],
            },
            "internal_only_services": ["telemetry_sink", "audit_replay_storage"],
            "sandbox_allowlist": ["tool_endpoint.ticket_lookup"],
        }
    )


def test_unknown_outbound_destination_is_denied() -> None:
    policy = _policy()
    try:
        policy.validate_egress(component="app_runtime", destination_id="unknown.destination")
    except InfrastructureBoundaryError as exc:
        assert "unknown outbound destination" in str(exc)
    else:
        raise AssertionError("expected unknown destination denial")


def test_disallowed_service_boundary_crossing_is_denied() -> None:
    policy = _policy()
    try:
        policy.validate_component_access(source="mcp_gateway", target="model_provider")
    except InfrastructureBoundaryError as exc:
        assert "disallowed service boundary crossing" in str(exc)
    else:
        raise AssertionError("expected boundary-crossing denial")


def test_sandbox_forbidden_egress_is_denied() -> None:
    policy = _policy()
    try:
        policy.validate_egress(component="high_risk_tool_sandbox", destination_id="storage_output.audit_jsonl", sandbox=True)
    except InfrastructureBoundaryError as exc:
        assert "sandbox egress destination not allowlisted" in str(exc)
    else:
        raise AssertionError("expected sandbox egress denial")
