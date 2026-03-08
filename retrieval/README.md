# retrieval/

Secure retrieval abstraction layer with explicit tenant/source boundaries.

Phase 3 adds:
- Source registration model (`SourceRegistration`, `SourceRegistry`).
- Trust and provenance metadata requirements for retrieved documents.
- `SecureRetrievalService` to enforce tenant and source restrictions.
- Optional retrieval filter hooks for future policy-enforcement integration.

Safe defaults:
- Missing trust/provenance metadata fails closed.
- Empty or mixed authorized/unauthorized source allowlists fail closed.
- Unregistered, disabled, malformed, unauthorized, or cross-tenant sources are denied.
- Trust-domain allowlisting is enforced (internal-only by default), quarantining low-trust domains unless explicitly allowlisted by policy.
