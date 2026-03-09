"""Local sandbox execution path for high-risk tool demonstrations."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.infrastructure_boundaries import InfrastructureBoundaryPolicy
from typing import Mapping, Protocol, Sequence

from tools.contracts import ToolDescriptor, ToolInvocation


class SandboxExecutionError(RuntimeError):
    """Raised when sandbox execution requirements are not met."""


@dataclass(frozen=True)
class SandboxExecutionProfile:
    """Execution profile for high-risk tools run in the demo sandbox."""

    profile_name: str
    boundary_name: str
    timeout_seconds: int
    network_policy: str
    allowed_commands: tuple[str, ...]
    allowed_env_keys: tuple[str, ...] = ("PATH", "LANG", "LC_ALL")
    evidence_dir: str = "artifacts/logs/sandbox"
    max_output_chars: int = 4000


@dataclass(frozen=True)
class SandboxExecutionEvidence:
    request_id: str
    tool_name: str
    actor_id: str
    tenant_id: str
    profile_name: str
    boundary_name: str
    network_policy: str
    timeout_seconds: int
    allowed_env_keys: tuple[str, ...]
    exposed_env_keys: tuple[str, ...]
    isolated_workdir: str
    command: tuple[str, ...]
    status: str
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    created_at: str


class HighRiskSandbox(Protocol):
    def supports(self, descriptor: ToolDescriptor) -> bool: ...
    def execute(self, invocation: ToolInvocation, descriptor: ToolDescriptor) -> Mapping[str, object]: ...


@dataclass
class LocalSubprocessSandbox:
    """Executes high-risk commands in an ephemeral local subprocess boundary."""

    profiles: Mapping[str, SandboxExecutionProfile]
    repo_root: Path
    infrastructure_policy: InfrastructureBoundaryPolicy | None = None

    def supports(self, descriptor: ToolDescriptor) -> bool:
        if not descriptor.isolation_profile or not descriptor.isolation_boundary:
            return False
        profile = self.profiles.get(descriptor.isolation_profile)
        if profile is None:
            return False
        return profile.boundary_name == descriptor.isolation_boundary

    def execute(self, invocation: ToolInvocation, descriptor: ToolDescriptor) -> Mapping[str, object]:
        profile_name = descriptor.isolation_profile or ""
        profile = self.profiles.get(profile_name)
        if profile is None:
            raise SandboxExecutionError("sandbox profile not found")
        if profile.boundary_name != descriptor.isolation_boundary:
            raise SandboxExecutionError("sandbox boundary mismatch")

        command = _parse_command(invocation.arguments.get("command"))
        if command[0] not in profile.allowed_commands:
            raise SandboxExecutionError("command is not allowlisted by sandbox profile")

        sandbox_env = _build_env(profile.allowed_env_keys)
        egress_destination = invocation.arguments.get("egress_destination")
        if isinstance(egress_destination, str) and egress_destination:
            if profile.network_policy == "disabled":
                raise SandboxExecutionError("sandbox network policy denies egress")
            if self.infrastructure_policy is not None:
                self.infrastructure_policy.validate_egress(
                    component="high_risk_tool_sandbox",
                    destination_id=egress_destination,
                    sandbox=True,
                )
        if profile.network_policy not in {"disabled", "allow"}:
            raise SandboxExecutionError("invalid network policy")
        if profile.network_policy == "disabled":
            sandbox_env["SANDBOX_NETWORK_POLICY"] = "disabled"

        result_status = "error"
        exit_code: int | None = None
        timed_out = False
        stdout = ""
        stderr = ""
        with tempfile.TemporaryDirectory(prefix="tool-sandbox-") as workdir:
            try:
                completed = subprocess.run(
                    command,
                    cwd=workdir,
                    env=sandbox_env,
                    capture_output=True,
                    text=True,
                    timeout=profile.timeout_seconds,
                    check=False,
                )
                exit_code = completed.returncode
                stdout = _sanitize_output(completed.stdout, max_chars=profile.max_output_chars)
                stderr = _sanitize_output(completed.stderr, max_chars=profile.max_output_chars)
                result_status = "ok" if completed.returncode == 0 else "error"
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                result_status = "timeout"
                exit_code = None
                stdout = _sanitize_output((exc.stdout or ""), max_chars=profile.max_output_chars)
                stderr = _sanitize_output((exc.stderr or ""), max_chars=profile.max_output_chars)

            evidence = SandboxExecutionEvidence(
                request_id=invocation.request_id,
                tool_name=invocation.tool_name,
                actor_id=invocation.actor_id,
                tenant_id=invocation.tenant_id,
                profile_name=profile.profile_name,
                boundary_name=profile.boundary_name,
                network_policy=profile.network_policy,
                timeout_seconds=profile.timeout_seconds,
                allowed_env_keys=profile.allowed_env_keys,
                exposed_env_keys=tuple(sorted(sandbox_env.keys())),
                isolated_workdir=workdir,
                command=tuple(command),
                status=result_status,
                exit_code=exit_code,
                timed_out=timed_out,
                stdout=stdout,
                stderr=stderr,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            evidence_path = _write_evidence(evidence=evidence, repo_root=self.repo_root, evidence_dir=profile.evidence_dir)

        return {
            "status": result_status,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "sandbox": {
                "profile": profile.profile_name,
                "boundary": profile.boundary_name,
                "network_policy": profile.network_policy,
                "filesystem_scope": "ephemeral_workdir",
                "env_scope": list(profile.allowed_env_keys),
                "evidence_path": evidence_path,
            },
        }


def _parse_command(raw: object) -> list[str]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise SandboxExecutionError("sandbox command must be a non-empty array")
    command: list[str] = []
    for token in raw:
        if not isinstance(token, str) or not token.strip():
            raise SandboxExecutionError("sandbox command includes invalid token")
        command.append(token.strip())
    if len(command) == 0:
        raise SandboxExecutionError("sandbox command must be a non-empty array")
    return command


def _build_env(allowed_keys: Sequence[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for key in allowed_keys:
        val = os.environ.get(key)
        if val is not None:
            output[key] = val
    output.setdefault("PATH", "/usr/bin:/bin")
    output.setdefault("LANG", "C.UTF-8")
    output.setdefault("LC_ALL", "C.UTF-8")
    return output


def _sanitize_output(raw: str, *, max_chars: int) -> str:
    text = raw[:max_chars]
    for marker in ("SECRET", "TOKEN", "PASSWORD"):
        text = text.replace(marker, "[redacted]")
    return text


def _write_evidence(*, evidence: SandboxExecutionEvidence, repo_root: Path, evidence_dir: str) -> str:
    path = repo_root / evidence_dir
    path.mkdir(parents=True, exist_ok=True)
    filename = f"{evidence.request_id}-{evidence.tool_name}-{int(datetime.now(timezone.utc).timestamp())}.json"
    full_path = path / filename
    full_path.write_text(json.dumps(asdict(evidence), sort_keys=True))
    return str(full_path.relative_to(repo_root))
