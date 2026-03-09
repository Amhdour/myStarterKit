from datetime import datetime, timedelta, timezone

from identity.models import (
    ActorType,
    DelegationGrant,
    IdentityValidationError,
    build_identity,
    parse_identity,
    validate_delegation_chain,
    verify_delegation_evidence,
)
from policies.engine import RuntimePolicyEngine
from policies.schema import build_runtime_policy


def _engine() -> RuntimePolicyEngine:
    return RuntimePolicyEngine(
        policy=build_runtime_policy(
            environment="test",
            payload={
                "meta": {"version": "1", "owner": "test", "default_risk_tier": "medium"},
                "risk_tiers": {"medium": {"max_retrieval_top_k": 5, "tools_enabled": True}},
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
            },
        )
    )


def _grant(*, parent: str, child: str, caps: tuple[str, ...], tenant: str, expires_offset_minutes: int = 30) -> DelegationGrant:
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(minutes=expires_offset_minutes)
    return DelegationGrant(
        parent_actor_id=parent,
        child_actor_id=child,
        delegated_capabilities=caps,
        delegation_reason="subtask",
        issued_at=issued.isoformat(),
        expires_at=expires.isoformat(),
        scope_constraints={"tenant_id": tenant, "purpose": "support"},
    )


def test_valid_identity_allows_policy_eval() -> None:
    identity = build_identity(
        actor_id="user-1",
        actor_type=ActorType.END_USER,
        tenant_id="tenant-a",
        session_id="s1",
        trust_level="medium",
        allowed_capabilities=("retrieval.search",),
    )
    decision = _engine().evaluate("req-1", "retrieval.search", context={"tenant_id": "tenant-a"}, identity=identity)
    assert decision.allow is True


def test_missing_identity_denies() -> None:
    decision = _engine().evaluate("req-1", "retrieval.search", context={})
    assert decision.allow is False


def test_forged_identity_denies_parse() -> None:
    try:
        parse_identity(
            {
                "actor_id": "agent-x",
                "actor_type": "delegated_agent",
                "tenant_id": "tenant-a",
                "session_id": "s1",
                "delegation_chain": [],
                "auth_context": {"authn_method": "m", "issuer": "i", "credential_id": "c"},
                "trust_level": "medium",
                "allowed_capabilities": ["retrieval.search"],
            }
        )
    except IdentityValidationError:
        return
    raise AssertionError("expected invalid delegated identity to fail")


def test_cross_tenant_mismatch_denied() -> None:
    identity = build_identity(
        actor_id="user-1",
        actor_type=ActorType.END_USER,
        tenant_id="tenant-a",
        session_id="s1",
        trust_level="medium",
        allowed_capabilities=("retrieval.search",),
    )
    decision = _engine().evaluate("req-1", "retrieval.search", context={"tenant_id": "tenant-b"}, identity=identity)
    assert decision.allow is False


def test_valid_delegation_chain_for_tools_invoke() -> None:
    identity = build_identity(
        actor_id="agent-child",
        actor_type=ActorType.DELEGATED_AGENT,
        tenant_id="tenant-a",
        session_id="s2",
        allowed_capabilities=("tools.invoke",),
        delegation_chain=(
            _grant(parent="user-1", child="agent-parent", caps=("tools.invoke", "retrieval.search"), tenant="tenant-a"),
            _grant(parent="agent-parent", child="agent-child", caps=("tools.invoke",), tenant="tenant-a"),
        ),
    )
    validate_delegation_chain(identity, action="tools.invoke")
    decision = _engine().evaluate("req-2", "tools.invoke", context={"tenant_id": "tenant-a", "tool_name": "ticket_lookup", "action": "lookup", "arguments": {}, "risk_tier": "medium"}, identity=identity)
    assert decision.allow is True


def test_delegation_scope_inflation_denied() -> None:
    identity = build_identity(
        actor_id="agent-child",
        actor_type=ActorType.DELEGATED_AGENT,
        tenant_id="tenant-a",
        session_id="s2",
        allowed_capabilities=("tools.invoke", "model.generate"),
        delegation_chain=(
            _grant(parent="user-1", child="agent-parent", caps=("tools.invoke",), tenant="tenant-a"),
            _grant(parent="agent-parent", child="agent-child", caps=("tools.invoke", "model.generate"), tenant="tenant-a"),
        ),
    )
    ok, issues = verify_delegation_evidence(identity, action="tools.invoke")
    assert ok is False
    assert "scope inflation" in issues


def test_delegation_expired_denied() -> None:
    identity = build_identity(
        actor_id="agent-child",
        actor_type=ActorType.DELEGATED_AGENT,
        tenant_id="tenant-a",
        session_id="s2",
        allowed_capabilities=("retrieval.search",),
        delegation_chain=(_grant(parent="user-1", child="agent-child", caps=("retrieval.search",), tenant="tenant-a", expires_offset_minutes=-1),),
    )
    ok, issues = verify_delegation_evidence(identity, action="retrieval.search")
    assert ok is False
    assert "expired delegation" in issues


def test_parent_child_tenant_mismatch_denied() -> None:
    identity = build_identity(
        actor_id="agent-child",
        actor_type=ActorType.DELEGATED_AGENT,
        tenant_id="tenant-a",
        session_id="s2",
        allowed_capabilities=("retrieval.search",),
        delegation_chain=(
            DelegationGrant(
                parent_actor_id="user-1",
                child_actor_id="agent-child",
                delegated_capabilities=("retrieval.search",),
                delegation_reason="subtask",
                issued_at=datetime.now(timezone.utc).isoformat(),
                expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                scope_constraints={"tenant_id": "tenant-b"},
            ),
        ),
    )
    ok, issues = verify_delegation_evidence(identity, action="retrieval.search")
    assert ok is False
    assert "broken chain continuity" in issues
