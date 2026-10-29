from __future__ import annotations
from .engine import Action

class DisabledSystemAdapter:
    """Safe production placeholder: never executes OS/network commands."""
    def __init__(self, capability: str): self.capability = capability
    def execute(self, target: str, action: Action, reason: str) -> dict:
        return {"simulated": False, "capability": self.capability, "target": target, "message": "Real executor not enabled"}
    def rollback(self, execution: dict) -> dict:
        return {"simulated": False, "capability": self.capability, "message": "Rollback executor not enabled"}
