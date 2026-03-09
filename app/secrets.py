"""Secret handling utilities, provider-backed reference resolution, and startup validation."""

from dataclasses import dataclass
import os
import re
from typing import Mapping, Protocol

SECRET_KEY_HINTS = (
    "secret",
    "token",
    "password",
    "api_key",
    "apikey",
    "bearer",
    "credential",
    "signing_key",
    "webhook",
    "private_key",
)

SECRET_VALUE_PATTERNS = (
    re.compile(r"^sk-[A-Za-z0-9]{10,}$"),
    re.compile(r"^Bearer\s+[A-Za-z0-9._\-]{8,}$", re.IGNORECASE),
    re.compile(r"^[A-Za-z0-9_\-]{20,}$"),
)


class SecretConfigurationError(ValueError):
    """Raised when secret configuration is missing or insecure."""


class SecretProviderError(RuntimeError):
    """Raised when secret provider cannot resolve a secret reference."""


@dataclass(frozen=True)
class SecretRef:
    provider: str
    name: str


class SecretProvider(Protocol):
    """Provider contract for reference-based secret resolution."""

    provider_name: str

    def resolve(self, ref: SecretRef) -> str: ...


@dataclass
class EnvSecretProvider(SecretProvider):
    provider_name: str = "env"
    environ: Mapping[str, str] | None = None

    def resolve(self, ref: SecretRef) -> str:
        env = dict(self.environ or os.environ)
        value = env.get(ref.name)
        if not value:
            raise SecretProviderError("missing required secret reference")
        return value


@dataclass
class StaticMapSecretProvider(SecretProvider):
    """Demo provider for vault/cloud secret-reference patterns in tests/examples."""

    provider_name: str
    values: Mapping[str, str]

    def resolve(self, ref: SecretRef) -> str:
        value = self.values.get(ref.name)
        if not value:
            raise SecretProviderError("secret reference not found")
        return value


DEFAULT_ALLOWED_PROVIDERS = ("env", "vault", "sm")


def parse_secret_ref(value: str) -> SecretRef:
    if not isinstance(value, str) or ":" not in value:
        raise SecretConfigurationError("invalid secret reference format")
    provider, name = value.split(":", 1)
    provider = provider.strip().lower()
    name = name.strip()
    if provider not in DEFAULT_ALLOWED_PROVIDERS or not name:
        raise SecretConfigurationError("secret reference must use allowed provider and non-empty name")
    return SecretRef(provider=provider, name=name)


def is_secret_reference(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parse_secret_ref(value)
        return True
    except SecretConfigurationError:
        return False


def resolve_secret_ref(
    ref: str,
    *,
    providers: Mapping[str, SecretProvider] | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    parsed = parse_secret_ref(ref)
    resolved_providers = dict(providers or default_secret_providers(environ=environ))
    provider = resolved_providers.get(parsed.provider)
    if provider is None:
        raise SecretConfigurationError("secret provider unavailable")
    try:
        return provider.resolve(parsed)
    except SecretProviderError as exc:
        raise SecretConfigurationError(f"secret reference resolution failed for provider: {parsed.provider}") from exc


def default_secret_providers(*, environ: Mapping[str, str] | None = None) -> Mapping[str, SecretProvider]:
    """Default provider map: env only; vault/cloud providers are deployment-integrated examples."""

    return {"env": EnvSecretProvider(environ=environ)}


def redact_value(value: object, *, key_hint: str | None = None) -> object:
    if isinstance(value, Mapping):
        return {str(key): redact_value(inner, key_hint=str(key)) for key, inner in value.items()}
    if isinstance(value, list):
        return [redact_value(item, key_hint=key_hint) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, key_hint=key_hint) for item in value)

    if isinstance(value, str):
        lowered_hint = (key_hint or "").lower()
        if any(hint in lowered_hint for hint in SECRET_KEY_HINTS):
            return "[redacted]"
        if any(pattern.match(value.strip()) for pattern in SECRET_VALUE_PATTERNS):
            return "[redacted]"
    return value


def redact_mapping(payload: Mapping[str, object]) -> dict[str, object]:
    return {str(key): redact_value(value, key_hint=str(key)) for key, value in payload.items()}


def safe_error_message(exc: Exception) -> str:
    """Return redaction-safe error message suitable for startup logs."""

    return str(redact_value(str(exc)))


def validate_secret_config(
    config: Mapping[str, object],
    *,
    environ: Mapping[str, str] | None = None,
    providers: Mapping[str, SecretProvider] | None = None,
) -> None:
    """Fail closed when sensitive-flow secret configuration is missing or insecure."""

    raw_refs = config.get("required_secret_refs", [])
    if not isinstance(raw_refs, list):
        raise SecretConfigurationError("required_secret_refs must be a list")

    policy = config.get("provider_policy", {})
    if not isinstance(policy, Mapping):
        raise SecretConfigurationError("provider_policy must be an object")
    allow_env_fallback = bool(policy.get("allow_env_fallback", True))
    require_managed_providers = bool(policy.get("require_managed_providers", False))

    for ref in raw_refs:
        if not isinstance(ref, str):
            raise SecretConfigurationError("required_secret_refs values must be strings")
        parsed = parse_secret_ref(ref)
        if require_managed_providers and parsed.provider == "env" and not allow_env_fallback:
            raise SecretConfigurationError("env provider is disallowed by provider_policy")
        _ = resolve_secret_ref(ref, providers=providers, environ=environ)

    raw_values = config.get("sensitive_values", {})
    if not isinstance(raw_values, Mapping):
        raise SecretConfigurationError("sensitive_values must be an object")
    for key, value in raw_values.items():
        if not isinstance(key, str):
            raise SecretConfigurationError("sensitive_values keys must be strings")
        if not isinstance(value, str):
            continue
        if is_secret_reference(value):
            parsed = parse_secret_ref(value)
            if require_managed_providers and parsed.provider == "env" and not allow_env_fallback:
                raise SecretConfigurationError("env provider is disallowed by provider_policy")
            _ = resolve_secret_ref(value, providers=providers, environ=environ)
            continue
        if any(hint in key.lower() for hint in SECRET_KEY_HINTS):
            raise SecretConfigurationError(f"insecure raw secret in config for key: {key}")
