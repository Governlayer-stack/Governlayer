"""Shared type definitions for governlayer-langchain."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class GovernanceAction(str, Enum):
    """Possible governance decisions from the GovernLayer API."""

    APPROVE = "APPROVE"
    ESCALATE_HUMAN = "ESCALATE_HUMAN"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class RiskProfile:
    """Risk profile flags sent with governance requests.

    Each boolean maps to a dimension in GovernLayer's 6-axis risk model.
    Defaults match a low-risk configuration so users only need to set
    the flags that apply to their system.
    """

    handles_personal_data: bool = False
    makes_autonomous_decisions: bool = False
    used_in_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    is_explainable: bool = True
    has_bias_testing: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "handles_personal_data": self.handles_personal_data,
            "makes_autonomous_decisions": self.makes_autonomous_decisions,
            "used_in_critical_infrastructure": self.used_in_critical_infrastructure,
            "has_human_oversight": self.has_human_oversight,
            "is_explainable": self.is_explainable,
            "has_bias_testing": self.has_bias_testing,
        }


@dataclass
class GovernanceResult:
    """Parsed response from the GovernLayer /v1/govern endpoint."""

    decision_id: str
    action: GovernanceAction
    reason: str
    risk_score: int
    risk_level: str
    drift_coefficient: float
    drift_vetoed: bool
    drift_flags: int
    ledger_hash: str
    policy_version: str
    timestamp: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> GovernanceResult:
        """Build from the JSON body returned by POST /v1/govern."""
        return cls(
            decision_id=data.get("decision_id", ""),
            action=GovernanceAction(data.get("action", "APPROVE")),
            reason=data.get("reason", ""),
            risk_score=data.get("risk", {}).get("score", 0),
            risk_level=data.get("risk", {}).get("level", "LOW"),
            drift_coefficient=data.get("drift", {}).get("coefficient", 0.0),
            drift_vetoed=data.get("drift", {}).get("vetoed", False),
            drift_flags=data.get("drift", {}).get("flags", 0),
            ledger_hash=data.get("ledger", {}).get("hash", ""),
            policy_version=data.get("ledger", {}).get("policy_version", ""),
            timestamp=data.get("timestamp", ""),
            raw=data,
        )

    @property
    def is_blocked(self) -> bool:
        return self.action == GovernanceAction.BLOCK

    @property
    def is_escalated(self) -> bool:
        return self.action == GovernanceAction.ESCALATE_HUMAN


@dataclass
class ScanResult:
    """Parsed response from the GovernLayer /v1/scan endpoint."""

    system: str
    action: GovernanceAction
    risk_score: int
    drift_coefficient: float
    vetoed: bool
    timestamp: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> ScanResult:
        return cls(
            system=data.get("system", ""),
            action=GovernanceAction(data.get("action", "APPROVE")),
            risk_score=data.get("risk_score", 0),
            drift_coefficient=data.get("drift_coefficient", 0.0),
            vetoed=data.get("vetoed", False),
            timestamp=data.get("timestamp", ""),
            raw=data,
        )

    @property
    def is_blocked(self) -> bool:
        return self.action == GovernanceAction.BLOCK
