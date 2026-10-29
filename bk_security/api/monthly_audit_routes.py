from __future__ import annotations

from fastapi import Depends, HTTPException, Query

from ..monthly_audit import build_monthly_audit


def install(app, core, require, reliability):
    @app.get("/api/v1/audit/monthly")
    async def monthly_audit(
        month: str = Query(..., min_length=7, max_length=7, pattern=r"^\d{4}-(0[1-9]|1[0-2])$"),
        principal=Depends(require("admin", "analyst", "viewer", "approver", "responder")),
    ):
        try:
            ledger = getattr(getattr(reliability, "monitor", None), "ledger", None)
            return build_monthly_audit(core.store, month, ledger)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
