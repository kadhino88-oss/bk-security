from __future__ import annotations

from datetime import datetime

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ..policy.engine import Action
from ..policy.autonomy import DEFAULT_PROTECTED_NETWORKS


class ConsentIn(BaseModel):
    approved_by: str = Field(min_length=1, max_length=256)
    customer_reference: str = Field(min_length=1, max_length=256)
    expires_at: str = Field(min_length=10, max_length=64)

    @field_validator("expires_at")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("expires_at must be an ISO-8601 timestamp.") from exc
        if parsed.tzinfo is None:
            raise ValueError("expires_at must carry a UTC offset.")
        return value


class AutonomyPolicyIn(BaseModel):
    level: int = Field(ge=1, le=4)
    auto_actions: list[Action] = Field(default_factory=lambda: [Action.BLOCK], max_length=3)
    min_risk_score: int = Field(default=80, ge=50, le=100)
    max_actions_per_hour: int = Field(default=10, ge=1, le=1000)
    protected_networks: list[str] = Field(default_factory=lambda: list(DEFAULT_PROTECTED_NETWORKS), max_length=256)
    consent: ConsentIn | None = None


def install(app, core, require):
    @app.get("/api/v1/autonomy")
    def get_autonomy(p=Depends(require("admin", "analyst", "viewer", "approver", "responder"))):
        return core.autonomy.status()

    @app.put("/api/v1/autonomy")
    def set_autonomy(body: AutonomyPolicyIn, p=Depends(require("admin"))):
        try:
            policy = core.autonomy.set_policy(
                p.username, level=body.level, auto_actions=body.auto_actions,
                min_risk_score=body.min_risk_score, max_actions_per_hour=body.max_actions_per_hour,
                protected_networks=body.protected_networks,
                consent=body.consent.model_dump() if body.consent else None)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {**policy.to_dict()}

    @app.post("/api/v1/autonomy/emergency-stop")
    def emergency_stop(p=Depends(require("admin", "approver", "responder"))):
        return core.autonomy.emergency_stop(p.username).to_dict()

    @app.post("/api/v1/autonomy/resume")
    def resume(p=Depends(require("admin"))):
        return core.autonomy.resume(p.username).to_dict()
