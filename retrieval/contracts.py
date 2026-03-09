"""Retrieval contracts with source registration and provenance structures."""

from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from identity.models import ActorIdentity, ActorType, build_identity


@dataclass(frozen=True)
class SourceRegistration:
    source_id: str
    tenant_id: str
    display_name: str
    enabled: bool = True
    trust_domain: str = "internal"


@dataclass(frozen=True)
class SourceTrustMetadata:
    source_id: str
    tenant_id: str
    checksum: str
    ingested_at: str


@dataclass(frozen=True)
class DocumentProvenance:
    citation_id: str
    source_id: str
    document_uri: str
    chunk_id: str


@dataclass(frozen=True, init=False)
class RetrievalQuery:
    request_id: str
    identity: ActorIdentity
    query_text: str
    top_k: int
    allowed_source_ids: Sequence[str] = tuple()

    def __init__(
        self,
        *,
        request_id: str,
        query_text: str,
        top_k: int,
        allowed_source_ids: Sequence[str] = tuple(),
        identity: ActorIdentity | None = None,
        tenant_id: str | None = None,
        actor_id: str = "retrieval-caller",
        session_id: str = "retrieval-session",
    ) -> None:
        if identity is None:
            if not tenant_id:
                raise ValueError("identity is required")
            identity = build_identity(
                actor_id=actor_id,
                actor_type=ActorType.ASSISTANT_RUNTIME,
                tenant_id=tenant_id,
                session_id=session_id,
                trust_level="medium",
                allowed_capabilities=("retrieval.search",),
            )
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "query_text", query_text)
        object.__setattr__(self, "top_k", top_k)
        object.__setattr__(self, "allowed_source_ids", allowed_source_ids)

    @property
    def tenant_id(self) -> str:
        return self.identity.tenant_id


@dataclass(frozen=True)
class RetrievalDocument:
    document_id: str
    content: str
    trust: SourceTrustMetadata
    provenance: DocumentProvenance
    attributes: Mapping[str, str]


class Retriever(Protocol):
    def search(self, query: RetrievalQuery) -> Sequence[RetrievalDocument]: ...


class SourceRegistry(Protocol):
    def register(self, source: SourceRegistration) -> None: ...
    def get(self, source_id: str) -> SourceRegistration | None: ...
    def list_for_tenant(self, tenant_id: str) -> Sequence[SourceRegistration]: ...


class RetrievalFilterHook(Protocol):
    def allow(self, query: RetrievalQuery, document: RetrievalDocument, source: SourceRegistration) -> bool: ...
