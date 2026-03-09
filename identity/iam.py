"""IAM token validation and normalization into internal actor identity."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Protocol, Sequence

from identity.models import ActorIdentity, ActorType, IdentityValidationError, build_identity


class TokenValidationError(ValueError):
    """Raised when an external IAM token fails trust validation."""


class IdentityMappingError(ValueError):
    """Raised when validated IAM claims cannot map to trusted internal identity."""


class JwtVerifier(Protocol):
    """Verifies compact JWT input and returns trusted claims."""

    def verify(self, token: str, *, expected_issuer: str, expected_audience: Sequence[str]) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class Hs256IssuerConfig:
    """Per-issuer verification settings for HS256 examples."""

    issuer: str
    audience: tuple[str, ...]
    shared_secret: str


@dataclass
class Hs256JwtVerifier(JwtVerifier):
    """Minimal HS256 verifier for runnable IAM integration examples."""

    issuers: Mapping[str, Hs256IssuerConfig]
    leeway_seconds: int = 0

    def verify(self, token: str, *, expected_issuer: str, expected_audience: Sequence[str]) -> Mapping[str, object]:
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenValidationError("malformed jwt")

        header = _decode_json_part(parts[0], "jwt header")
        claims = _decode_json_part(parts[1], "jwt claims")
        signature = _b64url_decode(parts[2])

        if str(header.get("alg", "")) != "HS256":
            raise TokenValidationError("unsupported jwt alg")

        config = self.issuers.get(expected_issuer)
        if config is None:
            raise TokenValidationError("unknown issuer")

        signed = f"{parts[0]}.{parts[1]}".encode("utf-8")
        expected_sig = hmac.new(config.shared_secret.encode("utf-8"), signed, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            raise TokenValidationError("invalid jwt signature")

        issuer = str(claims.get("iss", "")).strip()
        if issuer != expected_issuer:
            raise TokenValidationError("issuer mismatch")

        token_audiences = _audience_list(claims.get("aud"))
        if len(token_audiences) == 0:
            raise TokenValidationError("missing audience")
        if not any(aud in token_audiences for aud in expected_audience):
            raise TokenValidationError("audience mismatch")

        if "exp" not in claims:
            raise TokenValidationError("missing exp")
        exp = _parse_numeric_time(claims["exp"], "exp")
        now = datetime.now(timezone.utc).timestamp()
        if now > exp + float(self.leeway_seconds):
            raise TokenValidationError("token expired")

        if "nbf" in claims:
            nbf = _parse_numeric_time(claims["nbf"], "nbf")
            if now + float(self.leeway_seconds) < nbf:
                raise TokenValidationError("token not yet valid")

        return claims


@dataclass(frozen=True)
class IamIntegrationProfile:
    """Mapping rules from external IAM claims to internal actor identity."""

    source: str
    actor_type: ActorType
    issuer: str
    audiences: tuple[str, ...]
    tenant_claims: tuple[str, ...] = ("tenant_id", "tenant", "organization", "org")
    subject_claims: tuple[str, ...] = ("sub", "subject")
    role_claims: tuple[str, ...] = ("roles", "groups")
    scope_claims: tuple[str, ...] = ("scope", "scp")
    session_claims: tuple[str, ...] = ("sid", "session_id")
    required_roles: tuple[str, ...] = tuple()
    required_scopes: tuple[str, ...] = tuple()
    role_to_capabilities: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    default_capabilities: tuple[str, ...] = tuple()
    tenant_aliases: Mapping[str, str] = field(default_factory=dict)
    delegated_actor_claim: str | None = None


@dataclass(frozen=True)
class IamIdentityEnvelope:
    """Result of trusted IAM normalization."""

    identity: ActorIdentity
    normalized_claims: Mapping[str, object]


@dataclass
class IamIdentityMapper:
    """Validates external JWT claims and maps them to ActorIdentity."""

    verifier: JwtVerifier

    def map_token(self, *, token: str, profile: IamIntegrationProfile) -> IamIdentityEnvelope:
        claims = self.verifier.verify(token, expected_issuer=profile.issuer, expected_audience=profile.audiences)
        normalized = normalize_claims(claims, profile=profile)

        if profile.actor_type == ActorType.DELEGATED_AGENT:
            delegated = profile.delegated_actor_claim
            if not delegated:
                raise IdentityMappingError("delegated actor claim is required for delegated workload")
            delegated_actor = str(claims.get(delegated, "")).strip()
            if not delegated_actor:
                raise IdentityMappingError("delegated actor claim missing")

        capabilities = set(profile.default_capabilities)
        for role in normalized["roles"]:
            capabilities.update(profile.role_to_capabilities.get(role, tuple()))
        for scope in normalized["scopes"]:
            if scope.startswith("cap:"):
                capabilities.add(scope.removeprefix("cap:"))

        identity = build_identity(
            actor_id=str(normalized["internal_actor_id"]),
            actor_type=profile.actor_type,
            tenant_id=str(normalized["tenant_id"]),
            session_id=str(normalized["session_id"]),
            trust_level=str(normalized["trust_level"]),
            allowed_capabilities=tuple(sorted(capabilities)),
            auth_context={
                "authn_method": str(normalized["authn_method"]),
                "issuer": str(normalized["issuer"]),
                "credential_id": str(normalized["credential_id"]),
                "iam_source": str(profile.source),
                "external_subject": str(normalized["subject"]),
                "audience": ",".join(normalized["audience"]),
                "tenant_external": str(normalized["tenant_external"]),
                "roles": ",".join(normalized["roles"]),
                "groups": ",".join(normalized["groups"]),
                "scopes": ",".join(normalized["scopes"]),
                "auth_context_class": str(normalized["auth_context_class"]),
            },
        )

        if profile.required_roles and not any(role in normalized["roles"] for role in profile.required_roles):
            raise IdentityMappingError("required role missing")

        if profile.required_scopes and not set(profile.required_scopes).issubset(set(normalized["scopes"])):
            raise IdentityMappingError("required scope missing")

        return IamIdentityEnvelope(identity=identity, normalized_claims=normalized)


def normalize_claims(claims: Mapping[str, object], *, profile: IamIntegrationProfile) -> Mapping[str, object]:
    """Normalize validated IAM claims into canonical primitives."""

    subject = _pick_claim(claims, profile.subject_claims, field="subject")
    issuer = _require_string(claims.get("iss"), "iss")
    audiences = _audience_list(claims.get("aud"))
    if len(audiences) == 0:
        raise IdentityMappingError("aud is required")

    tenant_external = _pick_claim(claims, profile.tenant_claims, field="tenant")
    tenant_id = profile.tenant_aliases.get(tenant_external, tenant_external)

    roles = _string_list_from_claims(claims, profile.role_claims)
    groups = _string_list(claims.get("groups"))
    scopes = _scopes_from_claims(claims, profile.scope_claims)

    session = _first_nonempty_string(claims, profile.session_claims) or f"jwt-{subject}"
    authn_method = _first_nonempty_string(claims, ("amr", "authn_method")) or "oidc"
    auth_context_class = _first_nonempty_string(claims, ("acr", "auth_context")) or "unspecified"
    credential_id = _first_nonempty_string(claims, ("jti", "client_id", "azp")) or f"jwt:{subject}"

    trust_level = "high" if auth_context_class in {"mfa", "phr"} else "medium"

    return {
        "subject": subject,
        "issuer": issuer,
        "audience": tuple(audiences),
        "tenant_external": tenant_external,
        "tenant_id": tenant_id,
        "roles": tuple(sorted(set(roles))),
        "groups": tuple(sorted(set(groups))),
        "scopes": tuple(sorted(set(scopes))),
        "session_id": session,
        "authn_method": authn_method,
        "auth_context_class": auth_context_class,
        "credential_id": credential_id,
        "internal_actor_id": f"{profile.source}:{subject}",
        "trust_level": trust_level,
    }


def _decode_json_part(part: str, label: str) -> Mapping[str, object]:
    try:
        decoded = _b64url_decode(part).decode("utf-8")
        loaded = json.loads(decoded)
    except Exception as exc:
        raise TokenValidationError(f"invalid {label}") from exc
    if not isinstance(loaded, Mapping):
        raise TokenValidationError(f"invalid {label}")
    return loaded


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise TokenValidationError("invalid base64url encoding") from exc


def _parse_numeric_time(value: object, field: str) -> float:
    if isinstance(value, int | float):
        return float(value)
    raise TokenValidationError(f"{field} must be numeric")


def _audience_list(raw: object) -> list[str]:
    if isinstance(raw, str):
        parsed = raw.strip()
        return [parsed] if parsed else []
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        audiences: list[str] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                audiences.append(item.strip())
        return audiences
    return []


def _pick_claim(claims: Mapping[str, object], candidates: Sequence[str], *, field: str) -> str:
    value = _first_nonempty_string(claims, candidates)
    if not value:
        raise IdentityMappingError(f"{field} claim is required")
    return value


def _first_nonempty_string(claims: Mapping[str, object], candidates: Sequence[str]) -> str | None:
    for key in candidates:
        raw = claims.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def _require_string(value: object, field: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise IdentityMappingError(f"{field} claim is required")


def _string_list(raw: object) -> list[str]:
    if isinstance(raw, str):
        values = [token.strip() for token in raw.split(",")]
        return [value for value in values if value]
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        values: list[str] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                values.append(item.strip())
        return values
    return []


def _string_list_from_claims(claims: Mapping[str, object], claim_names: Sequence[str]) -> list[str]:
    values: list[str] = []
    for name in claim_names:
        values.extend(_string_list(claims.get(name)))
    return values


def _scopes_from_claims(claims: Mapping[str, object], claim_names: Sequence[str]) -> list[str]:
    scopes: list[str] = []
    for name in claim_names:
        raw = claims.get(name)
        if isinstance(raw, str):
            scopes.extend([token.strip() for token in raw.split(" ") if token.strip()])
        else:
            scopes.extend(_string_list(raw))
    return scopes


def verify_identity_for_policy(identity: ActorIdentity) -> None:
    """Guard helper for policy/tool callers that depend on mapped IAM identity."""

    iam_source = identity.auth_context.get("iam_source", "")
    if not iam_source:
        raise IdentityValidationError("iam_source is required in auth_context")
