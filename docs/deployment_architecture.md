# Deployment Architecture (Practical, Implementation-Aligned)

This document shows how the **current starter-kit implementation** runs in a practical environment.
It is intentionally provider-neutral and does **not** assume unsupported infrastructure.

See also:
- `docs/deployment/environment_profiles.md`
- `docs/architecture.md`
- `docs/architecture_diagrams.md`
- `docs/trust_boundaries.md`
- `docs/threat_model.md`

## 1) Deployment view: layers and runtime responsibilities

### Client / interface layer (untrusted)
- External clients submit `SupportAgentRequest` data (`request_id`, actor/tenant/session metadata, user text).
- Entry is untrusted and must pass orchestrator + policy checkpoints.

### API / app service layer
- A runtime app service hosts `SupportAgentOrchestrator` (`app/orchestrator.py`) as the primary control-flow entrypoint.
- Stage order in production-shaped flow:
  1. policy check: `retrieval.search`
  2. retrieval execution
  3. policy check: `model.generate`
  4. model generation
  5. policy check: `tools.route`
  6. tool routing decisions (and optionally mediated execution for tool-exec eval paths)

### Retrieval boundary layer
- `SecureRetrievalService` (`retrieval/service.py`) wraps the retriever backend.
- `InMemorySourceRegistry` (`retrieval/registry.py`) provides source registration metadata used by boundary checks.
- Enforces tenant/source/trust/provenance controls before content enters model context.

### Policy engine layer
- `RuntimePolicyEngine` (`policies/engine.py`) evaluates runtime actions:
  - `retrieval.search`
  - `model.generate`
  - `tools.route`
  - `tools.invoke`
- Policy artifacts are loaded from `policies/bundles/default/policy.json` through `policies/loader.py` with fail-closed behavior for invalid/missing policy.

### Tool router boundary layer
- `SecureToolRouter` (`tools/router.py`) is the centralized decision point for tool routing outcomes.
- `InMemoryToolRegistry` + execution guard (`tools/registry.py`, `tools/execution_guard.py`) enforce router-mediated execution semantics.

### Telemetry / audit layer
- Structured audit events are produced via `telemetry/audit/events.py` and `telemetry/audit/contracts.py`.
- Sinks (`telemetry/audit/sinks.py`) write JSONL evidence.
- Replay artifacts are built from event streams using `telemetry/audit/replay.py`.

### Artifact storage + readiness layer
- Baseline artifact paths:
  - `artifacts/logs/audit.jsonl`
  - `artifacts/logs/replay/*.replay.json`
  - `artifacts/logs/evals/*.jsonl`
  - `artifacts/logs/evals/*.summary.json`
  - `artifacts/logs/verification/security_guarantees.summary.json`
  - `artifacts/logs/verification/security_guarantees.summary.md`
- `launch_gate/SecurityLaunchGate` consumes these artifacts + policy artifact to produce readiness status (`go`, `conditional_go`, `no_go`).

---

## 2) Practical deployment diagram

```mermaid
flowchart TB
  subgraph Client[Client / Interface (Untrusted)]
    U[Support UI / API Client]
  end

  subgraph App[API / App Service]
    O[SupportAgentOrchestrator]
    M[LanguageModel Adapter]
  end

  subgraph Control[Policy + Boundary Controls]
    P[RuntimePolicyEngine]
    R[SecureRetrievalService]
    T[SecureToolRouter]
  end

  subgraph Data[Boundary Registries / Backends]
    RR[Raw Retriever Backend]
    SR[Source Registry]
    TR[Tool Registry + Executors]
  end

  subgraph Telemetry[Telemetry / Audit]
    AE[Audit Event Pipeline]
    AJ[JSONL Audit Sink]
    RP[Replay Artifact Builder]
  end

  subgraph Artifacts[Artifact Storage + Launch Gate]
    A1[artifacts/logs/audit.jsonl]
    A2[artifacts/logs/replay/*.replay.json]
    A3[artifacts/logs/evals/*.jsonl + *.summary.json]
    A4[artifacts/logs/verification/*.summary.json|md]
    LG[SecurityLaunchGate]
  end

  U --> O

  O -->|policy checks| P
  O -->|retrieval query| R
  R --> RR
  R --> SR
  O -->|model input| M
  O -->|tool decisions / mediated exec| T
  T --> TR
  T -->|tools.invoke policy| P

  O --> AE
  AE --> AJ
  AJ --> A1
  AJ --> RP
  RP --> A2

  A1 --> LG
  A2 --> LG
  A3 --> LG
  A4 --> LG
```

---

## 3) Security controls in deployment context

| Deployment crossing | Control location(s) | Implemented control | Evidence output |
|---|---|---|---|
| Client -> App | `app/orchestrator.py`, `policies/engine.py` | Stage policy gates + fail-closed blocked response path | `request.start`, `policy.decision`, `deny.event`, `request.end` |
| App -> Retrieval | `retrieval/service.py`, `retrieval/registry.py` | Tenant/source allowlists, trust-domain checks, trust/provenance enforcement, fail-closed behavior | `retrieval.decision`, `deny.event` |
| App -> Model | `app/orchestrator.py`, `policies/engine.py` | `model.generate` policy checkpoint before generation | `policy.decision` |
| App -> Tool boundary | `tools/router.py`, `policies/engine.py` | Centralized allow/deny/require-confirmation + policy invoke controls | `tool.decision`, `confirmation.required`, `deny.event` |
| Tool exec path | `tools/registry.py`, `tools/execution_guard.py` | Router-only execution mediation with callsite/context/secret checks | test + eval evidence (tool execution scenarios) |
| Runtime -> Audit | `telemetry/audit/*` | Structured audit events + replay reconstruction | `audit.jsonl`, replay JSON |
| Release decision | `launch_gate/engine.py` | Artifact-backed readiness checks + blockers/residual risks | launch-gate report |

---

## 4) Artifact locations and operational meaning

| Artifact location | Produced by | Used by |
|---|---|---|
| `artifacts/logs/audit.jsonl` | Audit sink | Replay tooling, launch gate, security review |
| `artifacts/logs/replay/*.replay.json` | Replay builder | Launch gate, forensic replay review |
| `artifacts/logs/evals/*.jsonl` | Security eval runner | Launch gate, evidence pack |
| `artifacts/logs/evals/*.summary.json` | Security eval runner | Launch gate thresholds/outcome checks |
| `artifacts/logs/verification/security_guarantees.summary.json` | Verification runner | Reviewer evidence, compliance review |
| `artifacts/logs/verification/security_guarantees.summary.md` | Verification runner | Human-readable guarantee review |

---

## 5) Practical starter-kit deployment profile

Minimal credible deployment profile for this repository:
1. One app service process hosting orchestrator/policy/retrieval/tool-router modules.
2. One retrieval backend adapter behind `SecureRetrievalService`.
3. File-backed audit output (`audit.jsonl`) and replay artifact generation.
4. Security eval pipeline producing JSONL + summary artifacts.
5. Launch-gate step reading policy + audit/replay/eval/verification artifacts.

This profile matches implemented boundaries and controls without assuming cloud/vendor-specific infrastructure.

## 6) Reviewer quick checks (deployment lens)

- Are policy artifacts valid and environment-appropriate?
- Are retrieval and tool boundaries enforced before model/tool side effects?
- Are audit/replay artifacts present and structurally complete?
- Are launch-gate blockers/residual risks tied to concrete artifacts?
- Are eval artifacts showing real runtime component coverage (not mocked evidence)?


## 7) Environment-specific architecture artifacts (example vs enforced)

Environment-specific profiles and dependency/topology specs are defined in:
- `config/deployments/environment_profiles.json`
- `config/deployments/topology.spec.json`
- `config/deployments/security_dependency_inventory.json`

These artifacts are **architecture declarations**. Launch gate validates shape/completeness of these declarations, but does not by itself prove external infrastructure hardening. Operational evidence is still required for production assertions.
