"""Deployment architecture artifact integrity checks."""

import json
from pathlib import Path


def test_environment_profiles_have_required_environments_and_boundaries() -> None:
    payload = json.loads(Path("config/deployments/environment_profiles.json").read_text())
    profiles = payload.get("profiles", [])
    assert isinstance(profiles, list)

    by_name = {item.get("name"): item for item in profiles if isinstance(item, dict)}
    assert {"local", "staging", "production"}.issubset(by_name.keys())

    required_boundaries = {
        "app_runtime",
        "policy_bundle_delivery",
        "retrieval_backend",
        "telemetry_sink",
        "audit_replay_storage",
        "high_risk_tool_sandbox",
        "secret_source",
        "iam_provider",
    }
    for name in ("local", "staging", "production"):
        boundaries = by_name[name].get("trust_boundaries", {})
        assert required_boundaries.issubset(boundaries.keys())


def test_topology_and_dependency_inventory_minimum_shape() -> None:
    topology = json.loads(Path("config/deployments/topology.spec.json").read_text())
    dependencies = json.loads(Path("config/deployments/security_dependency_inventory.json").read_text())

    services = topology.get("topology", {}).get("services", [])
    deps = dependencies.get("dependencies", [])

    assert isinstance(services, list)
    assert isinstance(deps, list)
    assert len(services) >= 6
    assert len(deps) >= 5
