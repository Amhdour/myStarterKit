# External Integration Boundary Security Baseline

All external boundaries must be explicitly inventoried in `config/integration_inventory.json`.

## Inventory Fields

Each integration record includes:
- `integration_id`
- `category`
- `trust_class`
- `allowed_data_classes`
- `tenant_scope`
- `auth_method`
- `logging_constraints`
- `failure_mode`

Optional runtime controls include `max_payload_bytes`, `strip_fields`, and `required_payload_fields`.

## Enforcement Model

`IntegrationBoundaryEnforcer` applies deny-by-default controls before an egress boundary is crossed:
1. deny unknown integration ids
2. deny tenant mismatch
3. deny disallowed data classes
4. enforce policy action `integration.egress`
5. strip configured sensitive fields
6. validate required payload fields and payload size
7. attach provenance metadata (`_integration.origin`, policy action, trust class)

## Launch-Gate Requirement

`launch_gate` runs `integration_inventory_completeness` and blocks release when:
- inventory is missing/unreadable
- required categories are missing (`model_provider`, `retrieval_backend`, `tool_endpoint`, `mcp_server`, `webhook`, `storage_output`)
- required inventory fields are missing
- duplicate integration ids exist

## Residual Risk

This starter kit enforces structural controls and policy mediation, but transport-level attestations and cryptographic endpoint identity proofs remain deployment responsibilities.


See also: `docs/infrastructure_boundaries.md` for explicit egress and service-boundary policy modeling.
