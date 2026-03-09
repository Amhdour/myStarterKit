# High-Risk Tool Sandboxing & Isolation Model

## What is now implemented (demo-grade but real execution path)

High-risk tools (`risk_class: high`) now run through a dedicated local sandbox path in `tools/sandbox.py`.

The execution flow is:
1. `SecureToolRouter.route` enforces high-risk metadata and policy approval.
2. `SecureToolRouter.mediate_and_execute` sends high-risk tools to `LocalSubprocessSandbox.execute`.
3. High-risk tools are **not** executed through normal registry executor path.
4. Sandbox execution writes JSON evidence artifacts to `artifacts/logs/sandbox/*.json`.

## Demonstrated isolation controls

`SandboxExecutionProfile` demonstrates:
- isolated runtime boundary: subprocess in ephemeral temp working directory
- restricted filesystem access: process starts in temporary workdir only (`cwd`), no inherited repo working dir
- restricted environment variable exposure: only explicit allowlisted env keys are exposed
- configurable network policy: profile carries `network_policy` (`disabled`/`allow`) and records it in evidence
- execution timeout: enforced via `subprocess.run(..., timeout=...)`
- stdout/stderr capture: captured and returned
- result sanitization: output is bounded and basic secret markers are redacted

## Evidence artifacts

Each sandbox run emits a JSON record with:
- request/tool/actor/tenant context
- profile + boundary names
- command, timeout, network policy
- env keys exposed and isolated workdir path
- status (`ok`/`timeout`/`error`), exit code, stdout/stderr

Launch gate (`high_risk_tool_isolation_readiness`) now checks for sandbox controls **and** sandbox evidence artifacts for policy-approved high-risk tools.

## Demo limitations (explicit)

This is a realistic **local sandbox demonstration**, not production container hardening:
- No kernel-enforced namespace/cgroup/seccomp isolation in this starter path.
- `network_policy=disabled` is configuration/evidence-oriented, not host-level packet enforcement.
- Filesystem restriction is working-directory isolation, not full chroot/container FS sandbox.
- Command allowlist + explicit environment reduction provide practical guardrails, but do not replace hardened runtime sandboxing.

## Deferred production hardening

- Replace local subprocess boundary with hardened container runtime boundary (namespaces, seccomp, cgroups, no-new-privileges).
- Add network egress enforcement at runtime boundary (policy-based firewall/sidecar).
- Add immutable execution image/profile attestation and signature verification for sandbox runtime.
- Add stronger output sanitization and structured redaction policies by data class.
