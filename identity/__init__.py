"""Canonical actor identity contracts for secure runtime flows."""

from identity.iam import (
    Hs256IssuerConfig,
    Hs256JwtVerifier,
    IamIdentityEnvelope,
    IamIdentityMapper,
    IamIntegrationProfile,
    IdentityMappingError,
    TokenValidationError,
    normalize_claims,
    verify_identity_for_policy,
)
from identity.models import (
    ActorIdentity,
    ActorType,
    DelegationGrant,
    IdentityValidationError,
    build_identity,
    parse_identity,
    validate_delegation_chain,
    validate_identity,
    verify_delegation_evidence,
)

__all__ = [
    "Hs256IssuerConfig",
    "Hs256JwtVerifier",
    "IamIntegrationProfile",
    "IamIdentityMapper",
    "IamIdentityEnvelope",
    "TokenValidationError",
    "IdentityMappingError",
    "normalize_claims",
    "verify_identity_for_policy",
    "ActorIdentity",
    "ActorType",
    "DelegationGrant",
    "IdentityValidationError",
    "parse_identity",
    "validate_identity",
    "validate_delegation_chain",
    "build_identity",
    "verify_delegation_evidence",
]
