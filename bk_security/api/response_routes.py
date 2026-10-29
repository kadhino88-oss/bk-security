from __future__ import annotations

from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from ..policy.engine import Action


class ResponsePlanRequest(BaseModel):
    action: Action | None = None
    target: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=1, max_length=2000)
    dry_run: bool = True
    risk_level: Literal["critical", "high", "medium", "low", "info"] = "high"
    risk_score: int | None = Field(default=None, ge=0, le=100)
    alert_id: str | None = Field(default=None, max_length=128)
    incident_id: str | None = Field(default=None, max_length=128)
    evidence_ids: list[str] = Field(default_factory=list, max_length=64)
    ai_recommendation: Action | None = None


class ResponseExecutionRequest(BaseModel):
    plan_id: str = Field(min_length=1, max_length=128)
    dry_run: bool | None = None


def _raise_for_execution(result: dict) -> None:
    status = result.get("status")
    if status in {
        "approval_required", "approver_and_executor_must_be_distinct",
        "approval_expired_or_invalid", "approval_plan_mismatch",
        "plan_is_dry_run", "policy_denied", "plan_not_found",
        "idempotency_key_mismatch", "non_reversible", "not_reversible",
    }:
        raise HTTPException(409, detail=result)
    if status == "adapter_not_configured":
        raise HTTPException(503, detail=result)
    if status in {"failed", "degraded", "rollback_failed"}:
        raise HTTPException(502, detail=result)


def install(router_app, core, require):
    router = APIRouter(prefix="/api/v1/response", tags=["response"])

    @router.post("/plan")
    async def plan(body: ResponsePlanRequest, p=Depends(require("admin", "analyst")),
                   idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        try:
            return core.plan_response(
                body.action, body.target, body.reason, actor=p.username, actor_role=p.role,
                dry_run=body.dry_run, risk_level=body.risk_level,
                risk_score=body.risk_score, alert_id=body.alert_id,
                incident_id=body.incident_id, evidence_ids=body.evidence_ids,
                ai_recommendation=body.ai_recommendation,
                plan_id=idempotency_key or str(uuid4()),
            )
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            status_code = 409 if "cannot be reused" in str(exc) else 422
            raise HTTPException(status_code, str(exc)) from exc

    @router.post("/approve/{plan_id}")
    async def approve(plan_id: str, p=Depends(require("approver"))):
        try:
            result = core.approve_response(plan_id, actor=p.username, role=p.role)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        return result

    @router.post("/approve-rollback/{execution_id}")
    async def approve_rollback(execution_id: str, p=Depends(require("approver"))):
        try:
            result = core.approve_response(execution_id, actor=p.username, role=p.role, rollback=True)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        return result

    @router.post("/execute")
    async def execute(body: ResponseExecutionRequest, p=Depends(require("responder"))):
        result = core.execute_response(
            body.plan_id, body.plan_id, actor=p.username, actor_role=p.role, dry_run=body.dry_run,
        )
        _raise_for_execution(result)
        return result

    @router.post("/rollback/{execution_id}")
    async def rollback(execution_id: str, p=Depends(require("responder"))):
        result = core.rollback_response(execution_id, actor=p.username, actor_role=p.role)
        _raise_for_execution(result)
        return result

    @router.get("/actions")
    async def actions(p=Depends(require("admin", "analyst", "viewer", "approver", "responder"))):
        return {"actions": core.store.list_response_actions(500)}

    @router.get("/audit")
    async def response_audit(p=Depends(require("admin", "analyst", "viewer", "approver", "responder"))):
        entries = core.store.list_audit(10_000)
        return {"audit": [entry for entry in entries if str(entry.get("action", "")).startswith("response_")][:500]}

    router_app.include_router(router)
