"""Secure retrieval service with tenant/source boundary enforcement."""

from dataclasses import dataclass, field, replace
from typing import Sequence

from identity.models import validate_delegation_chain, validate_identity
from policies.contracts import PolicyDecision, PolicyEngine
from retrieval.contracts import (
    RetrievalDocument,
    RetrievalFilterHook,
    RetrievalQuery,
    Retriever,
    SourceRegistration,
    SourceRegistry,
)


class RawRetriever(Retriever):
    """Marker protocol-equivalent base for raw retrieval backends."""


@dataclass
class SecureRetrievalService(Retriever):
    """Boundary-enforcing retriever wrapper."""

    source_registry: SourceRegistry
    raw_retriever: RawRetriever
    filter_hooks: Sequence[RetrievalFilterHook] = field(default_factory=tuple)
    policy_engine: PolicyEngine | None = None

    def search(self, query: RetrievalQuery) -> Sequence[RetrievalDocument]:
        try:
            validate_identity(query.identity)
        except Exception:
            return tuple()

        try:
            validate_delegation_chain(query.identity, action="retrieval.search")
        except Exception:
            return tuple()

        if not query.tenant_id or not query.query_text.strip() or query.top_k <= 0:
            return tuple()

        requested_sources = tuple(source_id for source_id in query.allowed_source_ids if isinstance(source_id, str) and source_id)
        if len(requested_sources) == 0:
            return tuple()

        tenant_registered_sources = {
            source.source_id
            for source in self.source_registry.list_for_tenant(query.tenant_id)
            if self._is_valid_registered_source(source)
        }
        if len(tenant_registered_sources) == 0:
            return tuple()

        if any(source_id not in tenant_registered_sources for source_id in requested_sources):
            return tuple()

        if self.policy_engine is None:
            return tuple()

        decision = self._evaluate_policy(query)
        if decision is None or not decision.allow:
            return tuple()

        constrained_sources = decision.constraints.get("allowed_source_ids")
        if not isinstance(constrained_sources, list) or len(constrained_sources) == 0:
            return tuple()

        constrained_set = {
            source
            for source in constrained_sources
            if isinstance(source, str) and source and source in tenant_registered_sources
        }
        if len(constrained_set) == 0:
            return tuple()

        if any(source not in constrained_set for source in requested_sources):
            return tuple()

        effective_allowed_sources = tuple(source for source in requested_sources if source in constrained_set)
        if len(effective_allowed_sources) == 0:
            return tuple()

        effective_top_k = query.top_k
        top_k_cap = decision.constraints.get("top_k_cap")
        if isinstance(top_k_cap, int) and top_k_cap > 0:
            effective_top_k = min(effective_top_k, top_k_cap)

        # Trust metadata and provenance are mandatory boundary controls.
        # They are enforced as hard safe defaults regardless of policy toggles.
        require_trust_metadata = True
        require_provenance = True

        allowed_trust_domains: tuple[str, ...] = ("internal",)
        constrained_domains = decision.constraints.get("allowed_trust_domains")
        if isinstance(constrained_domains, list):
            parsed_domains = tuple(
                domain.strip().lower() for domain in constrained_domains if isinstance(domain, str) and domain.strip()
            )
            if len(parsed_domains) == 0:
                return tuple()
            allowed_trust_domains = parsed_domains

        effective_query = RetrievalQuery(
            request_id=query.request_id,
            tenant_id=query.tenant_id,
            query_text=query.query_text,
            top_k=effective_top_k,
            allowed_source_ids=effective_allowed_sources,
        )

        try:
            raw_documents = self.raw_retriever.search(effective_query)
        except Exception:
            return tuple()

        accepted: list[RetrievalDocument] = []
        for document in raw_documents:
            if require_trust_metadata and not self._has_valid_trust_metadata(document=document, tenant_id=effective_query.tenant_id):
                continue

            source = self.source_registry.get(document.trust.source_id)
            if source is None:
                continue
            if not self._is_valid_registered_source(source):
                continue
            if not self._source_allowed_for_query(source=source, query=effective_query, allowed_trust_domains=allowed_trust_domains):
                continue
            if require_provenance and not self._has_valid_provenance(document=document):
                continue
            if not self._passes_filter_hooks(query=effective_query, document=document, source=source):
                continue
            accepted.append(self._attach_provenance(document=document, source=source))
            if len(accepted) >= effective_query.top_k:
                break

        return tuple(accepted)

    def _evaluate_policy(self, query: RetrievalQuery) -> PolicyDecision | None:
        if self.policy_engine is None:
            return None
        try:
            try:
                return self.policy_engine.evaluate(
                    request_id=query.request_id,
                    action="retrieval.search",
                    identity=query.identity,
                    context={"tenant_id": query.tenant_id},
                )
            except TypeError:
                return self.policy_engine.evaluate(
                    request_id=query.request_id,
                    action="retrieval.search",
                    context={"tenant_id": query.tenant_id},
                )
        except Exception:
            return None

    def _is_valid_registered_source(self, source: SourceRegistration) -> bool:
        if not source.source_id or not source.tenant_id:
            return False
        if not source.display_name or not source.display_name.strip():
            return False
        if not source.trust_domain or not source.trust_domain.strip():
            return False
        return True

    def _source_allowed_for_query(
        self,
        source: SourceRegistration,
        query: RetrievalQuery,
        allowed_trust_domains: tuple[str, ...],
    ) -> bool:
        if not source.enabled:
            return False
        if source.tenant_id != query.tenant_id:
            return False
        if query.allowed_source_ids and source.source_id not in query.allowed_source_ids:
            return False
        allowed_set = {item.strip().lower() for item in allowed_trust_domains}
        if source.trust_domain.strip().lower() not in allowed_set:
            return False
        return True

    def _has_valid_trust_metadata(self, document: RetrievalDocument, tenant_id: str) -> bool:
        trust = document.trust
        if not trust.source_id or not trust.tenant_id:
            return False
        if trust.tenant_id != tenant_id:
            return False
        if not trust.checksum or not trust.ingested_at:
            return False
        return True

    def _has_valid_provenance(self, document: RetrievalDocument) -> bool:
        provenance = document.provenance
        if not provenance.citation_id or not provenance.citation_id.strip():
            return False
        if not provenance.document_uri or not provenance.document_uri.strip() or not provenance.chunk_id or not provenance.chunk_id.strip():
            return False
        if provenance.source_id != document.trust.source_id:
            return False
        return True

    def _attach_provenance(self, document: RetrievalDocument, source: SourceRegistration) -> RetrievalDocument:
        return replace(
            document,
            provenance=replace(document.provenance, source_id=source.source_id),
        )

    def _passes_filter_hooks(
        self,
        query: RetrievalQuery,
        document: RetrievalDocument,
        source: SourceRegistration,
    ) -> bool:
        for hook in self.filter_hooks:
            try:
                if not hook.allow(query=query, document=document, source=source):
                    return False
            except Exception:
                return False
        return True
