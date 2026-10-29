from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RiskFactors:
    indicator: float = 0.0
    behavior: float = 0.0
    process: float = 0.0
    destination: float = 0.0
    persistence: float = 0.0
    impact: float = 0.0
    context_bonus: float = 0.0


class RiskEngine:
    """Deterministic risk scoring. AI can enrich factors, never silently override them."""

    WEIGHTS = {
        "indicator": 0.24,
        "behavior": 0.22,
        "process": 0.16,
        "destination": 0.14,
        "persistence": 0.10,
        "impact": 0.10,
    }

    def score(self, factors: RiskFactors) -> int:
        values = {k: max(0.0, min(100.0, getattr(factors, k))) for k in self.WEIGHTS}
        weighted = sum(values[k] * weight for k, weight in self.WEIGHTS.items())
        weighted += max(-15.0, min(15.0, factors.context_bonus))
        return max(0, min(100, round(weighted)))

    @staticmethod
    def severity(score: int) -> str:
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 45:
            return "medium"
        if score >= 20:
            return "low"
        return "info"
