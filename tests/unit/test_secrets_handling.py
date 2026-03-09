import json

from app.secrets import (
    SecretConfigurationError,
    StaticMapSecretProvider,
    redact_mapping,
    safe_error_message,
    validate_secret_config,
)
from identity.models import ActorType, build_identity
from telemetry.audit import DENY_EVENT, build_replay_artifact, create_audit_event
from telemetry.audit.sinks import JsonlAuditSink


def _identity():
    return build_identity(
        actor_id="actor-1",
        actor_type=ActorType.END_USER,
        tenant_id="tenant-a",
        session_id="sess-1",
        allowed_capabilities=("tools.invoke",),
    )


def test_redact_mapping_handles_nested_secret_keys_and_values() -> None:
    payload = {
        "api_key": "sk-verysecretvalue",
        "nested": {"webhook_secret": "Bearer abcdefghijklmnop", "safe": "ok"},
        "items": [{"token": "tkn-123"}, "plain"],
    }
    redacted = redact_mapping(payload)
    assert redacted["api_key"] == "[redacted]"
    assert redacted["nested"]["webhook_secret"] == "[redacted]"
    assert redacted["items"][0]["token"] == "[redacted]"
    assert redacted["nested"]["safe"] == "ok"


def test_validate_secret_config_blocks_missing_ref_and_inline_secret() -> None:
    try:
        validate_secret_config({"required_secret_refs": ["env:MISSING_ONE"]}, environ={})
    except SecretConfigurationError:
        pass
    else:
        raise AssertionError("expected missing secret ref failure")

    try:
        validate_secret_config(
            {
                "required_secret_refs": [],
                "sensitive_values": {"api_key": "sk-inline-secret"},
            },
            environ={},
        )
    except SecretConfigurationError:
        pass
    else:
        raise AssertionError("expected inline secret failure")


def test_validate_secret_config_supports_vault_or_cloud_reference_pattern() -> None:
    providers = {
        "env": StaticMapSecretProvider(provider_name="env", values={"SUPPORT_AGENT_SIGNING_KEY": "local-sign"}),
        "vault": StaticMapSecretProvider(provider_name="vault", values={"kv/support#connector": "vault-token"}),
    }
    validate_secret_config(
        {
            "required_secret_refs": ["vault:kv/support#connector"],
            "sensitive_values": {"signing_key": "env:SUPPORT_AGENT_SIGNING_KEY"},
        },
        providers=providers,
    )


def test_inaccessible_secret_reference_fails_closed() -> None:
    providers = {"vault": StaticMapSecretProvider(provider_name="vault", values={})}
    try:
        validate_secret_config({"required_secret_refs": ["vault:kv/missing#token"]}, providers=providers)
    except SecretConfigurationError as exc:
        assert "resolution failed" in str(exc)
    else:
        raise AssertionError("expected inaccessible secret reference failure")


def test_bad_configuration_fallback_disallows_env_provider_when_required() -> None:
    providers = {"env": StaticMapSecretProvider(provider_name="env", values={"SUPPORT_AGENT_SIGNING_KEY": "x"})}
    try:
        validate_secret_config(
            {
                "required_secret_refs": ["env:SUPPORT_AGENT_SIGNING_KEY"],
                "provider_policy": {"require_managed_providers": True, "allow_env_fallback": False},
            },
            providers=providers,
        )
    except SecretConfigurationError as exc:
        assert "env provider is disallowed" in str(exc)
    else:
        raise AssertionError("expected env-disallowed policy failure")


def test_startup_denial_when_required_secret_absent_and_safe_error_message() -> None:
    try:
        validate_secret_config(
            {
                "required_secret_refs": ["env:SUPPORT_AGENT_SIGNING_KEY"],
                "sensitive_values": {"mcp_connector_token": "env:MCP_CONNECTOR_TOKEN"},
            },
            environ={"SUPPORT_AGENT_SIGNING_KEY": "present"},
        )
    except SecretConfigurationError as exc:
        message = safe_error_message(exc)
        assert "MCP_CONNECTOR_TOKEN" not in message
        assert "resolution failed" in message
    else:
        raise AssertionError("expected startup denial when required secret absent")


def test_audit_and_replay_artifacts_redact_secret_payloads(tmp_path) -> None:
    event = create_audit_event(
        trace_id="trace-secret",
        request_id="req-secret",
        identity=_identity(),
        event_type=DENY_EVENT,
        payload={
            "stage": "tool.route",
            "api_key": "sk-really-secret",
            "raw_password": "hunter2",
            "connector_secret": "xyz",
            "reason": "blocked",
        },
    )

    sink_path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(output_path=sink_path)
    sink.emit(event)

    parsed = json.loads(sink_path.read_text().strip())
    assert parsed["event_payload"]["api_key"] == "[redacted]"
    assert parsed["event_payload"]["raw_password"] == "[redacted]"
    assert parsed["event_payload"]["connector_secret"] == "[redacted]"

    replay = build_replay_artifact((event,))
    deny_events = replay.decision_summary.get("deny_events", [])
    assert len(deny_events) == 1
    assert deny_events[0]["reason"] == "blocked"
    rendered = json.dumps(replay.timeline)
    assert "sk-really-secret" not in rendered
    assert "hunter2" not in rendered
