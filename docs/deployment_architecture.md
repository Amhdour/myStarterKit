# Deployment Architecture (Practical Starter-Kit View)

This document describes a practical deployment shape for the **implemented** starter kit.
It intentionally avoids provider-specific infrastructure claims.

See also:
- `docs/architecture.md`
- `docs/trust_boundaries.md`
- `docs/threat_model.md`

## 1) Deployment Layers (What runs where)

### Client / Interface layer
- External UI/API clients submit requests with `request_id`, actor, and tenant metadata.
- Trust level: untrusted input.

### API / App service layer
- Hosts `SupportAgentOrchestrator` (`app/orchestrator.py`) as the runtime entrypoint.
- Orchestrates stage order:
  1. `retrieval.search` policy check
  2. retrieval execution
  3. `model.generate` policy check
  4. model generation
  5. `tools.route` policy check
  6. tool routing decisions

### Retrieval boundary layer
- `SecureRetrievalService` (`retrieval/service.py`) fronts retrieval backend adapters.
- Enforces tenant/source/trust/provenance controls before documents become model context.

### Policy layer
- `RuntimePolicyEngine` (`policies/engine.py`) evaluates:
  - `retrieval.search`
  - `model.generate`
  - `tools.route`
  - `tools.invoke`
- Policy artifact source: `policies/bundles/default/policy.json`.

### Tool boundary layer
- `SecureToolRouter` (`tools/router.py`) mediates all tool decisions.
- `InMemoryToolRegistry` + execution guard enforce router-mediated execution semantics.

### Telemetry / audit layer
- Structured `AuditEvent` emission via `telemetry/audit/contracts.py`.
- Sinks: in-memory + JSONL (`telemetry/audit/sinks.py`).
- Replay artifact construction via `telemetry/audit/replay.py`.

### Artifact storage layer
- File-based evidence paths in baseline:
  - `artifacts/logs/audit.jsonl`
  - `artifacts/logs/replay/*.replay.json`
  - `artifacts/logs/evals/*.jsonl`
  - `artifacts/logs/evals/*.summary.json`
- `SecurityLaunchGate` consumes these artifacts for readiness classification.

---

## 2) Deployment Diagram (Mermaid)

```mermaid
flowchart TB
  subgraph Client[Client / Interface (Untrusted)]
    C[Support UI / API Client]
  end

  subgraph App[App Service]
    O[SupportAgentOrchestrator]
    M[LanguageModel Adapter]
  end

  subgraph Controls[Control Plane]
    P[RuntimePolicyEngine]
    R[SecureRetrievalService]
    T[SecureToolRouter]
  end

  subgraph Backends[Boundary Backends]
    RR[Raw Retriever Backend]
    SR[Source Registry]
    TR[Tool Registry / Executors]
  end

  subgraph Telemetry[Telemetry / Audit]
    AE[Audit Events]
    AS[Audit Sink JSONL]
    RB[Replay Builder]
  end

  subgraph Evidence[Artifact Storage + Gate]
    A1[artifacts/logs/audit.jsonl]
    A2[artifacts/logs/replay/*.replay.json]
    A3[artifacts/logs/evals/*.jsonl + *.summary.json]
    LG[launch_gate/SecurityLaunchGate]
  end

  C --> O
  O --> P
  O --> R
  R --> RR
  R --> SR
  O --> M
  O --> T
  T --> TR

  O --> AE
  AE --> AS
  AS --> A1
  AS --> RB
  RB --> A2

  A1 --> LG
  A2 --> LG
  A3 --> LG
```

---

## 3) Where security controls sit in deployment

| Deployment boundary | Control point | Implemented control | Primary evidence |
|---|---|---|---|
| Client -> App | Orchestrator ingress | Untrusted input handling + context propagation + stage policy checks | `request.start`, `policy.decision`, `request.end` |
| App -> Retrieval | Secure retrieval service | Tenant/source allowlists, trust-domain filtering, trust/provenance requirements, fail-closed behavior | `retrieval.decision`, `deny.event` |
| App -> Model | Orchestrator model stage | `model.generate` policy checkpoint before generation | `policy.decision` |
| App -> Tool boundary | Secure tool router | allow/deny/require_confirmation, forbidden fields/actions, rate limits, policy `tools.invoke` checks | `tool.decision`, `confirmation.required`, `deny.event` |
| Tool execution path | Router + registry + execution guard | direct non-mediated execution blocked | integration/unit verification tests + deny outcomes |
| Runtime -> Telemetry | Audit contracts/sinks/replay | structured event schema, replay decision/lifecycle reconstruction, redaction in replay payloads | audit JSONL + replay artifacts |
| Release readiness | Launch gate | artifact-backed checks over policy/eval/replay/audit/fallback/kill-switch | launch-gate scorecard/blockers/residual risks |

---

## 4) Practical baseline deployment profile

A practical baseline for this repository is:
1. One app service process hosting orchestrator/policy/retrieval/tool-router modules.
2. One retrieval backend integration behind `SecureRetrievalService`.
3. One audit JSONL output path.
4. Replay generation step producing replay artifacts.
5. Eval run step producing scenario JSONL + summary artifacts.
6. Launch-gate run step consuming those artifacts and policy file.

This profile matches current code boundaries and evidence model without assuming external infrastructure.

## 5) Deployment readiness checklist (minimal)

- Policy artifact exists and validates for target environment.
- Audit pipeline emits lifecycle + decision events.
- Replay artifacts reconstruct lifecycle/decisions.
- Eval outputs are present and coherent.
- Launch-gate outputs are reviewed (blockers + residual risks).
