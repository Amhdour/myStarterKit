# Infrastructure Boundary Controls

This repository includes explicit, machine-checkable infrastructure boundary definitions in `config/infrastructure_boundaries.json`.

## What is defined

- Allowed outbound destinations (`allowed_destinations`)
- Forbidden outbound host patterns (`forbidden_host_patterns`)
- Component-to-component access rules (`component_access_rules`)
- Internal-only service categories (`internal_only_services`)
- High-risk sandbox egress allowlist (`sandbox_allowlist`)

## In-repo enforcement links

- Integration egress controls can apply infrastructure boundary checks through `IntegrationBoundaryEnforcer`.
- MCP gateway can enforce boundary egress destination checks (`mcp_server.<id>` mapping).
- High-risk sandbox enforces network-policy denial and optional boundary-policy allowlisting for requested egress.

## Launch-gate validation

`launch_gate` check `infrastructure_boundary_evidence` verifies:
- boundary definition artifact exists and is readable,
- expected destination mappings are present,
- required rule sources exist (`app_runtime`, `mcp_gateway`, `high_risk_tool_sandbox`),
- integration inventory and boundary definitions are consistent.

## Enforced vs expected

Enforced in repo:
- machine-checkable boundary definitions,
- allowlist/deny behavior in boundary helper,
- launch-gate consistency checks.

Expected from surrounding infrastructure:
- actual network ACL/firewall/security-group enforcement,
- DNS and service mesh policy enforcement,
- transport attestation and certificate lifecycle hardening.
