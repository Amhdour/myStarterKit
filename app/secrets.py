"""Secret handling utilities, reference resolution, and startup validation."""

from dataclasses import dataclass
import os
import re
from typing import Mapping

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


@dataclass(frozen=True)
class SecretRef:
    provider: str
    name: str


def parse_secret_ref(value: str) -> SecretRef:
    if not isinstance(value, str) or ":" not in value:
        raise SecretConfigurationError("invalid secret reference format")
    provider, name = value.split(":", 1)
    provider = provider.strip().lower()
    name = name.strip()
    if provider != "env" or not name:
        raise SecretConfigurationError("secret reference must use env:<NAME>")
    return SecretRef(provider=provider, name=name)


def is_secret_reference(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parse_secret_ref(value)
        return True
    except SecretConfigurationError:
        return False


def resolve_secret_ref(ref: str, *, environ: Mapping[str, str] | None = None) -> str:
    parsed = parse_secret_ref(ref)
    env = dict(environ or os.environ)
    resolved = env.get(parsed.name)
    if not resolved:
        raise SecretConfigurationError(f"missing required secret: {parsed.name}")
    return resolved


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


def validate_secret_config(config: Mapping[str, object], *, environ: Mapping[str, str] | None = None) -> None:
    """Fail closed when sensitive-flow secret configuration is missing or insecure."""

    env = dict(environ or os.environ)
    raw_refs = config.get("required_secret_refs", [])
    if not isinstance(raw_refs, list):
        raise SecretConfigurationError("required_secret_refs must be a list")

    for ref in raw_refs:
        if not isinstance(ref, str):
            raise SecretConfigurationError("required_secret_refs values must be strings")
        _ = resolve_secret_ref(ref, environ=env)

    raw_values = config.get("sensitive_values", {})
    if not isinstance(raw_values, Mapping):
        raise SecretConfigurationError("sensitive_values must be an object")
    for key, value in raw_values.items():
        if not isinstance(key, str):
            raise SecretConfigurationError("sensitive_values keys must be strings")
        if not isinstance(value, str):
            continue
        if is_secret_reference(value):
            _ = resolve_secret_ref(value, environ=env)
            continue
        if any(hint in key.lower() for hint in SECRET_KEY_HINTS):
            raise SecretConfigurationError(f"insecure raw secret in config for key: {key}")
