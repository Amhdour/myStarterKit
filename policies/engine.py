"""Policy-as-code runtime engine enforcing retrieval/tool constraints."""

from dataclasses import dataclass
from typing import Mapping

from identity.models import ActorIdentity, ActorType, validate_delegation_chain, validate_identity
from policies.contracts import PolicyDecision, PolicyEngine
from policies.schema import RiskTierPolicy, RuntimePolicy


@dataclass
class RuntimePolicyEngine(PolicyEngine):
    """Evaluates policy decisions that affect runtime behavior."""

    policy: RuntimePolicy

    def evaluate(self, request_id: str, action: str, context: dict, identity: ActorIdentity | None = None) -> PolicyDecision:
        risk_tier, tier = self._resolve_risk_tier(context)

        if identity is None:
            tenant = str(context.get("tenant_id", ""))
            if not tenant:
                return PolicyDecision(request_id=request_id, allow=False, reason="invalid identity", risk_tier=risk_tier)
            identity = ActorIdentity(
                actor_id="legacy-policy-caller",
                actor_type=ActorType.ASSISTANT_RUNTIME,
                tenant_id=tenant,
                session_id="legacy-session",
                delegation_chain=tuple(),
                auth_context={"authn_method": "asserted", "issuer": "starter-kit", "credential_id": "legacy"},
                trust_level="low",
                allowed_capabilities=("retrieval.search", "model.generate", "tools.route", "tools.invoke"),
            )
        try:
            validate_identity(identity)
        except Exception:
            return PolicyDecision(request_id=request_id, allow=False, reason="invalid identity", risk_tier=risk_tier)

        if not self.policy.valid:
            return PolicyDecision(request_id=request_id, allow=False, reason="invalid policy: fail closed", risk_tier=risk_tier)
        if self.policy.kill_switch:
            return PolicyDecision(request_id=request_id, allow=False, reason="kill switch enabled", risk_tier=risk_tier)


        try:
            validate_delegation_chain(identity, action=action)
        except Exception as exc:
            return PolicyDecision(request_id=request_id, allow=False, reason=f"invalid delegation: {exc}", risk_tier=risk_tier)

        if action == "retrieval.search":
            tenant_id = str(context.get("tenant_id", identity.tenant_id))
            if tenant_id != identity.tenant_id:
                return PolicyDecision(request_id=request_id, allow=False, reason="tenant mismatch", risk_tier=risk_tier)
            if self.policy.retrieval.allowed_tenants and tenant_id not in self.policy.retrieval.allowed_tenants:
                return PolicyDecision(request_id=request_id, allow=False, reason="tenant not allowed", risk_tier=risk_tier)
            if "retrieval.search" not in identity.allowed_capabilities:
                return PolicyDecision(request_id=request_id, allow=False, reason="capability denied", risk_tier=risk_tier)

            allowed_sources = self.policy.retrieval.tenant_allowed_sources.get(tenant_id, tuple())
            if len(allowed_sources) == 0:
                return PolicyDecision(request_id=request_id, allow=False, reason="no allowlisted retrieval sources for tenant", risk_tier=risk_tier)
            return PolicyDecision(
                request_id=request_id,
                allow=True,
                reason="retrieval allowed",
                risk_tier=risk_tier,
                constraints={
                    "allowed_source_ids": list(allowed_sources),
                    "top_k_cap": tier.max_retrieval_top_k,
                    "require_trust_metadata": self.policy.retrieval.require_trust_metadata,
                    "require_provenance": self.policy.retrieval.require_provenance,
                    "allowed_trust_domains": list(self.policy.retrieval.allowed_trust_domains),
                },
            )

        if action == "model.generate":
            if "model.generate" not in identity.allowed_capabilities:
                return PolicyDecision(request_id=request_id, allow=False, reason="capability denied", risk_tier=risk_tier)
            return PolicyDecision(request_id=request_id, allow=True, reason="model generation allowed", risk_tier=risk_tier)

        if action == "tools.route":
            if "tools.route" not in identity.allowed_capabilities:
                return PolicyDecision(request_id=request_id, allow=False, reason="capability denied", risk_tier=risk_tier)
            if not tier.tools_enabled:
                return PolicyDecision(request_id=request_id, allow=False, reason="tools disabled for risk tier", risk_tier=risk_tier, fallback_to_rag=self.policy.fallback_to_rag)
            if len(self.policy.tools.allowed_tools) == 0:
                return PolicyDecision(request_id=request_id, allow=False, reason="no allowlisted tools configured", risk_tier=risk_tier, fallback_to_rag=self.policy.fallback_to_rag)
            return PolicyDecision(
                request_id=request_id,
                allow=True,
                reason="tool routing allowed",
                risk_tier=risk_tier,
                constraints={
                    "allowed_tools": list(self.policy.tools.allowed_tools),
                    "forbidden_tools": list(self.policy.tools.forbidden_tools),
                    "confirmation_required_tools": list(self.policy.tools.confirmation_required_tools),
                    "forbidden_fields_per_tool": {tool: list(fields) for tool, fields in self.policy.tools.forbidden_fields_per_tool.items()},
                    "rate_limits_per_tool": dict(self.policy.tools.rate_limits_per_tool),
                },
            )


        if action == "tools.issue_capability":
            if not tier.tools_enabled:
                return PolicyDecision(request_id=request_id, allow=False, reason="tools disabled for risk tier", risk_tier=risk_tier)
            tenant_id = str(context.get("tenant_id", identity.tenant_id))
            tool_name = str(context.get("tool_name", ""))
            allowed_operations = context.get("allowed_operations", [])
            ttl_seconds = context.get("ttl_seconds", 0)
            if tenant_id != identity.tenant_id:
                return PolicyDecision(request_id=request_id, allow=False, reason="tenant mismatch", risk_tier=risk_tier)
            if "tools.issue_capability" not in identity.allowed_capabilities:
                return PolicyDecision(request_id=request_id, allow=False, reason="capability denied", risk_tier=risk_tier)
            if not isinstance(allowed_operations, list) or len(allowed_operations) == 0:
                return PolicyDecision(request_id=request_id, allow=False, reason="invalid allowed_operations", risk_tier=risk_tier)
            if not isinstance(ttl_seconds, int) or ttl_seconds <= 0 or ttl_seconds > 600:
                return PolicyDecision(request_id=request_id, allow=False, reason="invalid ttl", risk_tier=risk_tier)
            if tool_name in self.policy.tools.forbidden_tools:
                return PolicyDecision(request_id=request_id, allow=False, reason="tool forbidden", risk_tier=risk_tier)
            if self.policy.tools.allowed_tools and tool_name not in self.policy.tools.allowed_tools:
                return PolicyDecision(request_id=request_id, allow=False, reason="tool not allowlisted by policy", risk_tier=risk_tier)
            return PolicyDecision(request_id=request_id, allow=True, reason="capability issuance allowed", risk_tier=risk_tier)

        if action == "tools.invoke":
            if not tier.tools_enabled:
                return PolicyDecision(request_id=request_id, allow=False, reason="tools disabled for risk tier", risk_tier=risk_tier, fallback_to_rag=self.policy.fallback_to_rag)
            tenant_id = str(context.get("tenant_id", identity.tenant_id))
            tool_name = str(context.get("tool_name", ""))
            action_name = str(context.get("action", ""))
            arguments = context.get("arguments", {})
            risk_class = str(context.get("risk_class", "low")).lower()
            if tenant_id != identity.tenant_id:
                return PolicyDecision(request_id=request_id, allow=False, reason="tenant mismatch", risk_tier=risk_tier)
            if "tools.invoke" not in identity.allowed_capabilities:
                return PolicyDecision(request_id=request_id, allow=False, reason="capability denied", risk_tier=risk_tier)
            if not tool_name or not action_name or not isinstance(arguments, Mapping):
                return PolicyDecision(request_id=request_id, allow=False, reason="invalid tool invocation envelope", risk_tier=risk_tier)
            if tool_name in self.policy.tools.forbidden_tools:
                return PolicyDecision(request_id=request_id, allow=False, reason="tool forbidden", risk_tier=risk_tier)
            if self.policy.tools.allowed_tools and tool_name not in self.policy.tools.allowed_tools:
                return PolicyDecision(request_id=request_id, allow=False, reason="tool not allowlisted by policy", risk_tier=risk_tier)
            for field in self.policy.tools.forbidden_fields_per_tool.get(tool_name, tuple()):
                if field in arguments:
                    return PolicyDecision(request_id=request_id, allow=False, reason=f"forbidden field in arguments: {field}", risk_tier=risk_tier)
            high_risk_approved = False
            if risk_class == "high":
                high_risk_approved = tool_name in self.policy.tools.high_risk_approved_tools

            return PolicyDecision(
                request_id=request_id,
                allow=True,
                reason="tool invocation allowed",
                risk_tier=risk_tier,
                constraints={
                    "confirmation_required": (tool_name in self.policy.tools.confirmation_required_tools) or risk_class == "high",
                    "rate_limit_per_minute": self.policy.tools.rate_limits_per_tool.get(tool_name),
                    "tool_action": action_name,
                    "high_risk_approved": high_risk_approved,
                },
            )

        if action == "integration.egress":
            tenant_id = str(context.get("tenant_id", identity.tenant_id))
            integration_id = str(context.get("integration_id", ""))
            data_classes = context.get("data_classes", [])
            if tenant_id != identity.tenant_id:
                return PolicyDecision(request_id=request_id, allow=False, reason="tenant mismatch", risk_tier=risk_tier)
            if "integration.egress" not in identity.allowed_capabilities:
                return PolicyDecision(request_id=request_id, allow=False, reason="capability denied", risk_tier=risk_tier)
            if not integration_id:
                return PolicyDecision(request_id=request_id, allow=False, reason="missing integration_id", risk_tier=risk_tier)
            if self.policy.integrations.allowed_integrations and integration_id not in self.policy.integrations.allowed_integrations:
                return PolicyDecision(request_id=request_id, allow=False, reason="integration not globally allowlisted", risk_tier=risk_tier)
            tenant_allowed = self.policy.integrations.tenant_allowed_integrations.get(tenant_id, tuple())
            if tenant_allowed and integration_id not in tenant_allowed:
                return PolicyDecision(request_id=request_id, allow=False, reason="integration not tenant allowlisted", risk_tier=risk_tier)
            if not isinstance(data_classes, list) or len(data_classes) == 0:
                return PolicyDecision(request_id=request_id, allow=False, reason="invalid data classes", risk_tier=risk_tier)
            allowed_classes = set(self.policy.integrations.allowed_data_classes)
            if any(not isinstance(data_class, str) or data_class not in allowed_classes for data_class in data_classes):
                return PolicyDecision(request_id=request_id, allow=False, reason="disallowed data class", risk_tier=risk_tier)
            return PolicyDecision(request_id=request_id, allow=True, reason="integration egress allowed", risk_tier=risk_tier)

        return PolicyDecision(request_id=request_id, allow=False, reason=f"unknown policy action: {action}", risk_tier=risk_tier)

    def _resolve_risk_tier(self, context: dict) -> tuple[str, RiskTierPolicy]:
        requested = str(context.get("risk_tier", self.policy.default_risk_tier))
        fallback_tier = self.policy.risk_tiers.get(self.policy.default_risk_tier)
        if fallback_tier is None:
            fallback_tier = RiskTierPolicy(max_retrieval_top_k=1, tools_enabled=False)
        return requested, self.policy.risk_tiers.get(requested, fallback_tier)
