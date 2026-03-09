"""MCP integration hardening layer for untrusted protocol boundaries."""

from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Mapping, Protocol, Sequence

from app.infrastructure_boundaries import InfrastructureBoundaryPolicy
from identity.models import validate_identity
from telemetry.audit import DENY_EVENT, ERROR_EVENT, TOOL_EXECUTION_ATTEMPT_EVENT
from telemetry.audit.contracts import AuditSink
from telemetry.audit.events import create_audit_event
from tools.contracts import ToolExecutor, ToolInvocation

MCP_SECURITY_EVENT = "mcp.security"
MCP_PROTOCOL_ERROR_EVENT = "mcp.protocol_error"


class MCPTrustLabel(str, Enum):
    TRUSTED = "trusted"
    RESTRICTED = "restricted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class MCPServerProfile:
    server_id: str
    endpoint: str
    tenant_id: str
    trust_label: MCPTrustLabel
    allowed_tool_capabilities: Sequence[str] = field(default_factory=tuple)
    allowed_resource_capabilities: Sequence[str] = field(default_factory=tuple)
    timeout_ms: int = 1500
    max_request_bytes: int = 8_192
    max_response_bytes: int = 16_384
    retry_limit: int = 1


class MCPTransport(Protocol):
    def call(self, *, endpoint: str, payload: Mapping[str, object], timeout_ms: int) -> Mapping[str, object]:
        ...


class MCPPolicyError(RuntimeError):
    pass


@dataclass
class SecureMCPGateway:
    """Policy-mediated MCP boundary wrapper with allowlists and protocol guards."""

    audit_sink: AuditSink
    transport: MCPTransport
    servers: Mapping[str, MCPServerProfile]
    infrastructure_policy: InfrastructureBoundaryPolicy | None = None

    def build_tool_executor(self, *, server_id: str, capability: str) -> ToolExecutor:
        """Create a registry-safe executor that cannot bypass router/policy/audit."""

        def _execute(invocation: ToolInvocation) -> Mapping[str, object]:
            return self.invoke_tool(server_id=server_id, capability=capability, invocation=invocation)

        return _execute

    def invoke_tool(self, *, server_id: str, capability: str, invocation: ToolInvocation) -> Mapping[str, object]:
        profile = self._profile(server_id)
        self._check_identity(invocation=invocation, profile=profile)
        self._check_server_policy(profile=profile, capability=capability)
        if self.infrastructure_policy is not None:
            self.infrastructure_policy.validate_egress(component="mcp_gateway", destination_id=f"mcp_server.{server_id}")

        payload = {
            "request_id": invocation.request_id,
            "tenant_id": invocation.tenant_id,
            "actor_id": invocation.actor_id,
            "origin": {
                "server_id": profile.server_id,
                "endpoint": profile.endpoint,
                "trust_label": profile.trust_label.value,
            },
            "capability": capability,
            "arguments": dict(invocation.arguments),
        }
        self._check_payload_size(payload=payload, max_bytes=profile.max_request_bytes, error_message="request exceeds size limit")

        self._emit(invocation=invocation, event_type=TOOL_EXECUTION_ATTEMPT_EVENT, payload={"server_id": profile.server_id, "endpoint": profile.endpoint, "capability": capability})

        last_error: Exception | None = None
        for _ in range(profile.retry_limit + 1):
            try:
                response = self.transport.call(endpoint=profile.endpoint, payload=payload, timeout_ms=profile.timeout_ms)
                self._check_payload_size(payload=response, max_bytes=profile.max_response_bytes, error_message="response exceeds size limit")
                parsed = self._validate_response_schema(response)
                self._emit(invocation=invocation, event_type=MCP_SECURITY_EVENT, payload={"server_id": profile.server_id, "capability": capability, "status": "ok", "origin": payload["origin"]})
                return parsed
            except MCPPolicyError as exc:
                self._emit(invocation=invocation, event_type=DENY_EVENT, payload={"stage": "mcp.gateway", "server_id": profile.server_id, "reason": str(exc)})
                raise
            except Exception as exc:  # protocol failure path
                last_error = exc

        self._emit(invocation=invocation, event_type=MCP_PROTOCOL_ERROR_EVENT, payload={"server_id": profile.server_id, "error": type(last_error).__name__ if last_error else "unknown"})
        raise MCPPolicyError("protocol error after retries")

    def _profile(self, server_id: str) -> MCPServerProfile:
        profile = self.servers.get(server_id)
        if profile is None:
            raise MCPPolicyError("server is not allowlisted")
        return profile

    def _check_identity(self, *, invocation: ToolInvocation, profile: MCPServerProfile) -> None:
        validate_identity(invocation.identity)
        if invocation.tenant_id != profile.tenant_id:
            raise MCPPolicyError("tenant boundary violation")

    def _check_server_policy(self, *, profile: MCPServerProfile, capability: str) -> None:
        if profile.trust_label == MCPTrustLabel.UNTRUSTED:
            raise MCPPolicyError("untrusted server denied")
        if capability not in profile.allowed_tool_capabilities:
            raise MCPPolicyError("tool capability not allowlisted")

    def _check_payload_size(self, *, payload: Mapping[str, object], max_bytes: int, error_message: str) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        if len(encoded) > max_bytes:
            raise MCPPolicyError(error_message)

    def _validate_response_schema(self, response: Mapping[str, object]) -> Mapping[str, object]:
        if not isinstance(response, Mapping):
            raise MCPPolicyError("response schema invalid")
        status = response.get("status")
        data = response.get("data")
        origin = response.get("origin")
        if not isinstance(status, str) or status not in {"ok", "error"}:
            raise MCPPolicyError("response schema invalid")
        if not isinstance(data, Mapping):
            raise MCPPolicyError("response schema invalid")
        if not isinstance(origin, Mapping):
            raise MCPPolicyError("response schema invalid")
        if not isinstance(origin.get("server_id"), str) or not isinstance(origin.get("endpoint"), str):
            raise MCPPolicyError("response schema invalid")
        return {"status": status, "data": dict(data), "origin": dict(origin)}

    def _emit(self, *, invocation: ToolInvocation, event_type: str, payload: dict) -> None:
        self.audit_sink.emit(
            create_audit_event(
                trace_id=f"trace-{invocation.request_id}",
                request_id=invocation.request_id,
                identity=invocation.identity,
                event_type=event_type,
                payload=payload,
            )
        )
