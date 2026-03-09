from pathlib import Path
import sys

import yaml

from app.secrets import SecretConfigurationError, safe_error_message, validate_secret_config


def _load_settings() -> dict:
    local = Path("config/settings.local.yaml")
    template = Path("config/settings.template.yaml")
    target = local if local.is_file() else template
    if not target.is_file():
        return {}
    payload = yaml.safe_load(target.read_text())
    return payload if isinstance(payload, dict) else {}


def main() -> None:
    settings = _load_settings()
    secret_cfg = settings.get("secrets", {}) if isinstance(settings, dict) else {}
    if isinstance(secret_cfg, dict):
        try:
            validate_secret_config(secret_cfg)
        except SecretConfigurationError as exc:
            print(f"startup blocked: {safe_error_message(exc)}")
            sys.exit(2)
    print("secure-support-agent startup validation passed")


if __name__ == "__main__":
    main()
