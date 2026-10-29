from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Action(str, Enum):
    ALERT = "alert"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"
    ISOLATE = "isolate"
    TERMINATE_PROCESS = "terminate_process"


PROTECTED_ACTIONS = frozenset({Action.BLOCK, Action.ISOLATE, Action.TERMINATE_PROCESS})


@dataclass(frozen=True, slots=True)
class ResponsePolicy:
    """Deterministic policy. AI output is a proposal and never changes policy."""

    critical_auto_action: Action = Action.REQUIRE_APPROVAL
    high_auto_action: Action = Action.REQUIRE_APPROVAL
    medium_auto_action: Action = Action.ALERT
    low_auto_action: Action = Action.ALERT
    info_auto_action: Action = Action.ALERT

    def action_for(self, severity: str) -> Action:
        return {
            "critical": self.critical_auto_action,
            "high": self.high_auto_action,
            "medium": self.medium_auto_action,
            "low": self.low_auto_action,
            "info": self.info_auto_action,
        }.get(str(severity).lower(), Action.ALERT)

    def evaluate(
        self,
        severity: str,
        requested_action: Action | str | None = None,
        ai_recommendation: Action | str | None = None,
    ) -> dict:
        """Return an explainable decision; only configured policy can authorize."""
        configured = self.action_for(severity)
        requested = Action(requested_action) if requested_action is not None else None
        recommendation = Action(ai_recommendation) if ai_recommendation is not None else None
        candidate = requested if requested is not None else recommendation

        if configured in PROTECTED_ACTIONS:
            selected = configured
            allowed = True
            reason = f"The {severity} policy selects {configured.value}."
        elif configured == Action.REQUIRE_APPROVAL:
            selected = candidate or Action.REQUIRE_APPROVAL
            allowed = True
            reason = (
                f"The {severity} policy permits a proposed response only after explicit approval."
                if selected in PROTECTED_ACTIONS
                else f"The {severity} policy requires human review before selecting a response."
            )
        elif candidate in PROTECTED_ACTIONS:
            selected = Action.ALERT
            allowed = False
            reason = (
                f"The {severity} policy permits {configured.value} and does not authorize "
                f"the proposed {candidate.value} action."
            )
        else:
            selected = configured
            allowed = True
            reason = f"The {severity} policy selects {configured.value}."

        requires_approval = selected in PROTECTED_ACTIONS or selected == Action.REQUIRE_APPROVAL
        return {
            "severity": str(severity).lower(),
            "configured_action": configured.value,
            "requested_action": requested.value if requested else None,
            "ai_recommendation": recommendation.value if recommendation else None,
            "action": selected.value,
            "allowed": allowed,
            "requires_approval": requires_approval,
            "reason": reason,
        }
