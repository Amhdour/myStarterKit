import json

from app.secrets import SecretConfigurationError, redact_mapping, validate_secret_config
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


def test_validate_secret_config_blocks_missing_refs_and_raw_secret_embedding() -> None:
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


def test_validate_secret_config_accepts_env_refs() -> None:
    validate_secret_config(
        {
            "required_secret_refs": ["env:SUPPORT_AGENT_SIGNING_KEY"],
            "sensitive_values": {"webhook_secret": "env:SUPPORT_WEBHOOK_SECRET"},
        },
        environ={"SUPPORT_AGENT_SIGNING_KEY": "abc", "SUPPORT_WEBHOOK_SECRET": "def"},
    )


def test_audit_and_replay_artifacts_redact_secret_payloads(tmp_path) -> None:
    identity = _identity()
    event = create_audit_event(
        trace_id="trace-secret",
        request_id="req-secret",
        identity=identity,
        event_type=DENY_EVENT,
        payload={
            "reason": "blocked",
            "api_key": "sk-really-secret",
            "nested": {"authorization": "Bearer shouldnotappear"},
            "connector_secret": "xyz",
        },
    )

    sink = JsonlAuditSink(output_path=tmp_path / "audit.jsonl")
    sink.emit(event)
    parsed = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert parsed["event_payload"]["api_key"] == "[redacted]"
    assert parsed["event_payload"]["nested"]["authorization"] == "[redacted]"
    assert parsed["event_payload"]["connector_secret"] == "[redacted]"

    artifact = build_replay_artifact((event,))
    payload = artifact.timeline[0]["payload"]
    assert payload["api_key"] == "[redacted]"
    assert payload["nested"]["authorization"] == "[redacted]"
