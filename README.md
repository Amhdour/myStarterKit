# Secure Support Agent Starter Kit

A production-oriented repository scaffold for building a **secure support agent** with retrieval-augmented generation (RAG), policy enforcement, telemetry/audit trails, evaluations, and launch gating.

> Phase 10 adds a hardening and cleanup pass focused on safer defaults, tighter fail-safe behavior, and clearer deployment/demo readiness guidance.

## Purpose

This starter kit provides a clean foundation to:
- Build support-focused agent workflows incrementally.
- Separate concerns across app, retrieval, tools, policies, telemetry, evals, and launch controls.
- Enable safe iteration with clear extension points and test scaffolding.

## Current Scope

Included:
- Modular repository layout.
- Structured request/response/context models.
- Policy-aware orchestration flow with explicit stage boundaries.
- Secure retrieval service with source registration and tenant/source enforcement.
- Trust/provenance metadata requirements for citation-friendly retrieval results.
- Secure tool router with explicit allow/deny/require_confirmation decisions and mediated execution path.
- Policy-as-code runtime engine with validation, risk tiers, environment overrides, kill switch, and fallback-to-RAG handling.
- Structured telemetry and audit pipeline with JSONL output and replay artifact generation.
- Reusable security eval runner with scenario-based red-team cases and regression outputs.
- Launch-gate readiness evaluator with machine-checkable checks, blockers, and residual-risk summaries.
- Evidence-pack and reviewer/operator/portfolio documentation for practical review workflows.
- Hardening pass across policy/retrieval/tool/launch-gate fail-safe behavior and stricter tests.
- Environment/config templates.
- Engineering and safety guidance in `AGENTS.md`.
- Baseline and orchestration-focused tests.

Not included:
- Business/domain logic.
- Live integrations (LLM providers, vector stores, ticketing systems, etc.).
- Security claims beyond what is actually implemented.

## Repository Layout

```text
.
├── app/                  # Agent models, context, orchestration, model contracts
├── retrieval/            # Retrieval abstractions, indexing/query contracts
├── tools/                # Tool registry and mediated routing contracts
├── policies/             # Policy specs and enforcement integration points
├── telemetry/
│   └── audit/            # Audit event schemas and telemetry pipeline hooks
├── evals/                # Evaluation harness and datasets placeholders
├── launch_gate/          # Pre-launch readiness checks and release gate scaffolding
├── docs/                 # Architecture, roadmap, and operating docs
├── tests/                # Unit/integration/e2e structure and fixtures
├── artifacts/
│   └── logs/             # Runtime and CI artifact output location
├── config/               # Config templates and environment-specific overlays
└── scripts/              # Utility scripts for setup/validation (safe, non-prod)
```

## Core Flow (Phase 10)

1. Request enters with `SupportAgentRequest` and `SessionContext`.
2. Orchestrator builds `RequestContext`.
3. Policy gate checks retrieval stage.
4. Retrieval returns supporting documents.
5. Policy gate checks model generation stage.
6. Model receives user input plus retrieved context (RAG-first prompt envelope).
7. Policy gate checks tool-routing stage.
8. Tool router returns **decisions only** (never direct execution).
9. Response returns structured output + trace for auditability.

## Quick Start (Reviewer, ~10 minutes)

1. **Setup**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements-dev.txt
   cp .env.example .env
   ```
2. **Minimal validation**
   ```bash
   pytest -q
   ```
3. **Run baseline evals (writes evidence artifacts)**
   ```bash
   python -m evals.runner
   ls -1 artifacts/logs/evals
   ```
4. **Run launch gate (reads policy + audit/eval evidence)**
   ```bash
   python -m launch_gate.engine
   ```

### Minimal request-flow demo

> Uses repository runtime fixture wiring (`evals/runtime.py`) so reviewers can exercise real orchestrator/policy/retrieval/tool paths quickly.

#### A) Normal request (orchestrator path)
```bash
python -c "from evals.runtime import build_runtime_fixture, make_request; f=build_runtime_fixture(); r=f.orchestrator.run(make_request(request_id='demo-ok', tenant_id='tenant-a', user_text='How do I reset my password?')); print('status:', r.status); print('retrieved_docs:', list(r.trace.retrieved_document_ids)); print('events:', [e.event_type for e in f.audit_sink.events])"
```

#### B) Guarded action (denied tool invocation)
```bash
python -c "from evals.runtime import build_runtime_fixture, make_invocation; f=build_runtime_fixture(); d=f.tool_router.route(make_invocation(request_id='demo-deny', tenant_id='tenant-a', tool_name='admin_shell', action='exec', arguments={'command':'whoami'})); print('tool_decision:', d.status); print('reason:', d.reason)"
```

#### C) Launch-gate output example
```bash
python -c "from pathlib import Path; from launch_gate.engine import SecurityLaunchGate; report=SecurityLaunchGate(repo_root=Path('.')).evaluate(); print('status:', report.status); print('summary:', report.summary); [print(f'- {c.check_name}:', 'PASS' if c.passed else 'FAIL') for c in report.checks]"
```

### Where to inspect evidence

- Eval scenario logs: `artifacts/logs/evals/*.jsonl`
- Eval summaries: `artifacts/logs/evals/*.summary.json`
- Audit logs (if JSONL sink is wired in your runtime entrypoint): `artifacts/logs/audit.jsonl`
- Replay artifacts (if generated): `artifacts/logs/replay*.json`
- Launch-gate policy input: `policies/bundles/default/policy.json`

## Development Principles

- Keep all execution paths policy-aware and auditable.
- Prefer explicit contracts between modules.
- Add implementation only with tests and documented threat considerations.
- Never claim security properties that are not verifiably implemented.

## Phase 10 Hardening Notes

- Retrieval and tool-routing now fail closed when policy evaluation errors occur.
- Tool decision outputs keep argument shape while redacting argument values to reduce leakage risk.
- Launch-gate evaluation now treats unreadable required evidence files as explicit blockers.


## Documentation & Evidence Pack

- Architecture deep-dive: `docs/architecture.md`
- Architecture diagrams: `docs/architecture_diagrams.md`
- Trust boundaries: `docs/trust_boundaries.md`
- Threat model: `docs/threat_model.md`
- Operator/developer setup: `docs/operator/setup.md`
- Security reviewer guide: `docs/reviewer/security_review_guide.md`
- Portfolio summary: `docs/portfolio/project_summary.md`
- Evidence pack index: `docs/evidence_pack/README.md`
