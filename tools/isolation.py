"""Isolation abstractions for high-risk tool execution boundaries."""

from dataclasses import dataclass
from enum import Enum


class ToolRiskClass(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


@dataclass(frozen=True)
class IsolationProfile:
    """Declarative isolation requirements for high-risk tool execution."""

    profile_name: str
    restricted_filesystem: bool
    restricted_network: bool
    restricted_environment: bool
    notes: str = ""
