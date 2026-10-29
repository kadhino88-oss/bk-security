"""Per-customer autonomy levels for automatic response (managed-service model).

The level is set by the operator with a recorded customer consent. It only governs *automatic* responses; plans
that a human creates through the response API keep their existing approval path. The default is OBSERVE and any
invalid or missing stored policy falls back to it. An emergency stop forces OBSERVE regardless of the level.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from .engine import Action


class AutonomyLevel(IntEnum):
    OBSERVE = 1       # detect and notify only
    RECOMMEND = 2     # also prepare dry-run response plans, never executed
    CONTAIN_AUTO = 3  # also execute reversible, low-impact containment (BLOCK) within strict bounds
    EXTENDED = 4      # also the extra actions the operator listed explicitly, still with consent and caps


DEFAULT_PROTECTED_NETWORKS = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10",
)
_AUTO_CAPABLE = frozenset({Action.BLOCK, Action.ISOLATE, Action.TERMINATE_PROCESS})
_LEVEL3_ACTIONS = frozenset({Action.BLOCK})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must carry a UTC offset.")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class Consent:
    """The customer's recorded agreement to automatic action, bounded in time."""

    approved_by: str
    customer_reference: str
    approved_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for name in ("approved_by", "customer_reference"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"Consent {name} is required and must be bounded.")
        if _parse(self.expires_at, "expires_at") <= _parse(self.approved_at, "approved_at"):
            raise ValueError("Consent must expire after it was approved.")

    def valid_at(self, moment: datetime) -> bool:
        return _parse(self.approved_at, "approved_at") <= moment < _parse(self.expires_at, "expires_at")


@dataclass(frozen=True, slots=True)
class AutonomyPolicy:
    level: AutonomyLevel = AutonomyLevel.OBSERVE
    auto_actions: frozenset[Action] = _LEVEL3_ACTIONS
    min_risk_score: int = 80
    max_actions_per_hour: int = 10
    protected_networks: tuple[str, ...] = DEFAULT_PROTECTED_NETWORKS
    consent: Consent | None = None
    emergency_stop: bool = False
    version: int = 1
    _networks: tuple = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "level", AutonomyLevel(self.level))
        actions = frozenset(Action(item) for item in self.auto_actions)
        if not actions <= _AUTO_CAPABLE:
            raise ValueError("auto_actions may only contain block, isolate or terminate_process.")
        object.__setattr__(self, "auto_actions", actions)
        if isinstance(self.min_risk_score, bool) or not isinstance(self.min_risk_score, int) \
                or not 50 <= self.min_risk_score <= 100:
            raise ValueError("min_risk_score must be an integer between 50 and 100.")
        if isinstance(self.max_actions_per_hour, bool) or not isinstance(self.max_actions_per_hour, int) \
                or not 1 <= self.max_actions_per_hour <= 1000:
            raise ValueError("max_actions_per_hour must be an integer between 1 and 1000.")
        try:
            networks = tuple(ipaddress.ip_network(item, strict=False) for item in self.protected_networks)
        except ValueError as exc:
            raise ValueError("protected_networks must contain valid CIDR networks.") from exc
        object.__setattr__(self, "_networks", networks)
        object.__setattr__(self, "protected_networks", tuple(str(item) for item in networks))
        if self.level >= AutonomyLevel.CONTAIN_AUTO and self.consent is None:
            raise ValueError("Automatic execution requires a recorded customer consent.")
        if not isinstance(self.version, int) or self.version < 1:
            raise ValueError("version must be a positive integer.")

    def effective_actions(self) -> frozenset[Action]:
        if self.level >= AutonomyLevel.EXTENDED:
            return self.auto_actions
        if self.level == AutonomyLevel.CONTAIN_AUTO:
            return self.auto_actions & _LEVEL3_ACTIONS
        return frozenset()

    def is_protected(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return True
        return any(ip.version == net.version and ip in net for net in self._networks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": int(self.level), "level_name": self.level.name.lower(),
            "auto_actions": sorted(item.value for item in self.auto_actions),
            "min_risk_score": self.min_risk_score, "max_actions_per_hour": self.max_actions_per_hour,
            "protected_networks": list(self.protected_networks),
            "consent": None if self.consent is None else {
                "approved_by": self.consent.approved_by, "customer_reference": self.consent.customer_reference,
                "approved_at": self.consent.approved_at, "expires_at": self.consent.expires_at},
            "emergency_stop": self.emergency_stop, "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AutonomyPolicy":
        consent = data.get("consent")
        return cls(
            level=AutonomyLevel(int(data["level"])),
            auto_actions=frozenset(Action(item) for item in data.get("auto_actions", ["block"])),
            min_risk_score=data.get("min_risk_score", 80),
            max_actions_per_hour=data.get("max_actions_per_hour", 10),
            protected_networks=tuple(data.get("protected_networks", DEFAULT_PROTECTED_NETWORKS)),
            consent=Consent(**consent) if consent else None,
            emergency_stop=bool(data.get("emergency_stop", False)),
            version=int(data.get("version", 1)),
        )


@dataclass(frozen=True, slots=True)
class AutonomyDecision:
    mode: str  # observe | recommend | execute
    action: Action | None
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "action": self.action.value if self.action else None, "reasons": list(self.reasons)}


def decide(policy: AutonomyPolicy, action: Action, target: str, risk_score: int, evidence_count: int,
           recent_count: int, *, now: datetime | None = None) -> AutonomyDecision:
    """Pure decision: what may happen automatically for one candidate response. Never exceeds the policy."""
    now = now or _now()
    if policy.emergency_stop:
        return AutonomyDecision("observe", None, ("emergency_stop",))
    if policy.level == AutonomyLevel.OBSERVE:
        return AutonomyDecision("observe", None, ("level_observe",))
    if risk_score < policy.min_risk_score:
        return AutonomyDecision("observe", None, ("below_min_risk",))
    if evidence_count < 1:
        return AutonomyDecision("observe", None, ("no_evidence",))
    if recent_count >= policy.max_actions_per_hour:
        return AutonomyDecision("observe", None, ("hourly_cap_reached",))
    if policy.level == AutonomyLevel.RECOMMEND:
        return AutonomyDecision("recommend", action, ("level_recommend",))

    blockers = []
    if action not in policy.effective_actions():
        blockers.append("action_not_enabled")
    if action == Action.BLOCK and policy.is_protected(target):
        blockers.append("protected_target")
    if policy.consent is None or not policy.consent.valid_at(now):
        blockers.append("consent_missing_or_expired")
    if blockers:
        return AutonomyDecision("recommend", action, tuple(blockers))
    return AutonomyDecision("execute", action, ("within_policy",))
