"""IAM integration tests for claim validation and internal identity mapping."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from identity.iam import (
    Hs256IssuerConfig,
    Hs256JwtVerifier,
    IamIdentityMapper,
    IamIntegrationProfile,
    IdentityMappingError,
    TokenValidationError,
)
from identity.models import ActorType
from policies.engine import RuntimePolicyEngine
from policies.schema import build_runtime_policy
from telemetry.audit.events import create_audit_event
from telemetry.audit.sinks import _event_to_record


SHARED_SECRET = "integration-secret"
ISSUER = "https://iam.example.com"


def _jwt(claims: dict[str, object], *, secret: str = SHARED_SECRET) -> str:
    header = {"alg": "HS256", "typ": "JWT"}

    def encode(part: dict[str, object]) -> str:
        raw = json.dumps(part, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    encoded_header = encode(header)
    encoded_claims = encode(claims)
    payload = f"{encoded_header}.{encoded_claims}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    encoded_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{encoded_header}.{encoded_claims}.{encoded_sig}"


def _profile(*, actor_type: ActorType, source: str, required_roles: tuple[str, ...] = tuple(), required_scopes: tuple[str, ...] = tuple(), delegated_actor_claim: str | None = None) -> IamIntegrationProfile:
    return IamIntegrationProfile(
        source=source,
        actor_type=actor_type,
        issuer=ISSUER,
        audiences=("support-agent",),
        tenant_aliases={"acme-inc": "tenant-a"},
        required_roles=required_roles,
        required_scopes=required_scopes,
        delegated_actor_claim=delegated_actor_claim,
        role_to_capabilities={
            "support_user": ("retrieval.search", "model.generate", "tools.route"),
            "support_operator": ("retrieval.search", "model.generate", "tools.route", "tools.invoke"),
            "runtime": ("tools.invoke", "tools.route"),
        },
        default_capabilities=("retrieval.search",),
    )


def _mapper() -> IamIdentityMapper:
    verifier = Hs256JwtVerifier(
        issuers={
            ISSUER: Hs256IssuerConfig(
                issuer=ISSUER,
                audience=("support-agent",),
                shared_secret=SHARED_SECRET,
            )
        }
    )
    return IamIdentityMapper(verifier=verifier)


def _claims(**overrides: object) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    base: dict[str, object] = {
        "iss": ISSUER,
        "aud": "support-agent",
        "sub": "user-123",
        "tenant": "acme-inc",
        "roles": ["support_user"],
        "groups": ["tier1"],
        "scope": "openid profile cap:retrieval.search",
        "sid": "session-1",
        "amr": "pwd",
        "acr": "mfa",
        "jti": "cred-1",
        "exp": int((now + timedelta(minutes=10)).timestamp()),
    }
    base.update(overrides)
    return base


def _policy_engine() -> RuntimePolicyEngine:
    payload = {
        "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "medium"},
        "risk_tiers": {"medium": {"max_retrieval_top_k": 3, "tools_enabled": True}},
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
    }
    return RuntimePolicyEngine(policy=build_runtime_policy(environment="test", payload=payload))


def test_valid_oidc_end_user_token_maps_and_policy_evaluates() -> None:
    token = _jwt(_claims())
    profile = _profile(actor_type=ActorType.END_USER, source="oidc_end_user")

    envelope = _mapper().map_token(token=token, profile=profile)
    decision = _policy_engine().evaluate(
        request_id="req-1",
        action="retrieval.search",
        context={"tenant_id": "tenant-a"},
        identity=envelope.identity,
    )

    assert decision.allow is True
    assert envelope.identity.auth_context["iam_source"] == "oidc_end_user"


def test_expired_token_denied() -> None:
    token = _jwt(_claims(exp=int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp())))

    with pytest.raises(TokenValidationError, match="token expired"):
        _mapper().map_token(token=token, profile=_profile(actor_type=ActorType.END_USER, source="oidc_end_user"))


def test_wrong_audience_denied() -> None:
    token = _jwt(_claims(aud="other-service"))

    with pytest.raises(TokenValidationError, match="audience mismatch"):
        _mapper().map_token(token=token, profile=_profile(actor_type=ActorType.END_USER, source="oidc_end_user"))


def test_missing_tenant_claim_denied() -> None:
    claims = _claims()
    claims.pop("tenant")
    token = _jwt(claims)

    with pytest.raises(IdentityMappingError, match="tenant claim is required"):
        _mapper().map_token(token=token, profile=_profile(actor_type=ActorType.END_USER, source="oidc_end_user"))


def test_operator_role_mismatch_denied() -> None:
    token = _jwt(_claims(roles=["support_user"]))

    with pytest.raises(IdentityMappingError, match="required role missing"):
        _mapper().map_token(
            token=token,
            profile=_profile(
                actor_type=ActorType.HUMAN_OPERATOR,
                source="operator_admin",
                required_roles=("support_operator",),
            ),
        )


def test_service_identity_insufficient_scope_denied_by_policy() -> None:
    token = _jwt(_claims(sub="svc-runtime", roles=["runtime"], scope="openid profile"))
    profile = _profile(
        actor_type=ActorType.ASSISTANT_RUNTIME,
        source="service_runtime",
    )

    envelope = _mapper().map_token(token=token, profile=profile)
    decision = _policy_engine().evaluate(
        request_id="req-2",
        action="tools.invoke",
        context={"tenant_id": "tenant-a", "tool_name": "ticket_lookup", "action": "lookup", "arguments": {}},
        identity=envelope.identity,
    )

    assert decision.allow is True

    weak_token = _jwt(_claims(sub="svc-runtime", roles=[], scope="openid profile"))
    weak_identity = _mapper().map_token(token=weak_token, profile=profile).identity
    weak_decision = _policy_engine().evaluate(
        request_id="req-3",
        action="tools.invoke",
        context={"tenant_id": "tenant-a", "tool_name": "ticket_lookup", "action": "lookup", "arguments": {}},
        identity=weak_identity,
    )
    assert weak_decision.allow is False
    assert weak_decision.reason == "capability denied"


def test_delegated_workload_requires_delegated_claim() -> None:
    token = _jwt(_claims(sub="workload-a", roles=["runtime"]))

    with pytest.raises(IdentityMappingError, match="delegated actor claim missing"):
        _mapper().map_token(
            token=token,
            profile=_profile(
                actor_type=ActorType.DELEGATED_AGENT,
                source="delegated_workload",
                delegated_actor_claim="act",
            ),
        )


def test_audit_record_captures_external_and_internal_identity() -> None:
    token = _jwt(_claims())
    identity = _mapper().map_token(token=token, profile=_profile(actor_type=ActorType.END_USER, source="oidc_end_user")).identity

    event = create_audit_event(
        trace_id="trace-1",
        request_id="req-1",
        identity=identity,
        event_type="policy.decision",
        payload={"action": "retrieval.search", "allow": True},
    )
    record = _event_to_record(event)

    assert record["actor_id"] == "oidc_end_user:user-123"
    assert record["tenant_id"] == "tenant-a"
    assert record["auth_context"]["iam_source"] == "oidc_end_user"
    assert record["auth_context"]["external_subject"] == "user-123"
