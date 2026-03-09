# IAM Integration Examples (OIDC/JWT, Service, Operator, Delegated Workload)

This starter kit now includes an implementation-oriented IAM mapping layer in `identity/iam.py` that validates external JWTs before any policy/tool authorization decisions.

## What is implemented

- `Hs256JwtVerifier`: verifies JWT structure, signature (`HS256`), issuer (`iss`), audience (`aud`), and token lifetime (`exp`/`nbf`) before claim use.
- `IamIntegrationProfile`: per-identity-source contract that defines trusted issuer/audiences, claim names, tenant aliases, required roles/scopes, and actor type mapping.
- `IamIdentityMapper`: normalizes trusted external claims into `ActorIdentity` and stores normalized identity provenance in `auth_context`.
- `verify_identity_for_policy`: guard helper for callers that require mapped IAM provenance in identity auth-context.

## External IAM -> Internal Actor mapping

| External identity source | Example actor type | Internal actor id format | Notes |
|---|---|---|---|
| OIDC end user token | `end_user` | `oidc_end_user:<sub>` | Role->capability and `cap:*` scopes mapped to internal capabilities. |
| Service-to-service runtime token | `assistant_runtime` | `service_runtime:<sub>` | Service scopes/roles map to runtime capabilities. |
| Operator/admin token | `human_operator` | `operator_admin:<sub>` | Role requirements enforced in mapper (`required_roles`). |
| Delegated workload token | `delegated_agent` | `delegated_workload:<sub>` | Requires delegated-actor claim presence via `delegated_actor_claim`. |

## Claim normalization performed

- subject: `sub` or `subject`
- issuer: `iss`
- audience: `aud` (string or array)
- tenant/org: configurable claim list (`tenant_id`, `tenant`, `organization`, `org`) + alias mapping to internal tenant IDs
- roles/groups: configurable role claims (`roles`, `groups`) and normalized `groups`
- session/auth context: `sid`/`session_id`, `amr`, `acr`, and credential id from `jti`/`client_id`/`azp`

## Trust-boundary behavior

- Raw claims are never trusted until token verification succeeds.
- Policy and tool authorization continue to evaluate only internal `ActorIdentity` (`allowed_capabilities`, tenant binding, actor type).
- Invalid tokens or mapping failures fail closed and are denied.

## Negative-path examples covered by tests

- Valid token path
- Expired token
- Wrong audience
- Missing tenant claim
- Role/group mismatch for operator profile
- Service identity missing required mapped capability (denied by policy)

See: `tests/unit/test_iam_integration.py`.
