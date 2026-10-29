from __future__ import annotations

import math
import os
import threading

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..ingestion import IngestionQueue, ingestion_settings
from ..provenance import is_simulation_record

_STATUS_CODES = {"accepted": 202, "duplicate": 200, "quarantined": 422, "throttled": 429, "backpressure": 503}


def _production_policy(event: dict):
    if is_simulation_record(event):
        return ("simulation_in_production", "Simulation-marked telemetry is not accepted in production.")
    return None


def install(app, core, require, get_context):
    """Authenticated local ingestion routes.

    The queue lives beside the customer database and is only available for a
    dedicated customer deployment; the queue file is bound to that deployment.
    The authenticated principal is the sender identity until per-agent
    credentials exist; no remote listener is opened. SQLite and core work runs
    in the thread pool so a drain never stalls the event loop.
    """
    cache: dict[tuple, IngestionQueue] = {}
    lock = threading.Lock()

    def queue_for_request() -> IngestionQueue:
        context = get_context()
        if context.profile != "dedicated_customer":
            raise HTTPException(409, "Envelope ingestion requires a dedicated customer deployment.")
        try:
            settings = ingestion_settings(os.environ)
        except ValueError as exc:
            raise HTTPException(503, f"Invalid ingestion configuration: {exc}") from exc
        production = os.getenv("BK_SECURITY_ENV", "").strip().lower() == "production"
        path = os.getenv("BK_SECURITY_INGEST_DB") or f"{core.store.path}.ingest.db"
        key = (path, context, production, tuple(sorted(settings.items())))
        with lock:
            if key not in cache:
                try:
                    cache[key] = IngestionQueue(path, context, event_policy=_production_policy if production else None,
                                                **settings)
                except ValueError as exc:
                    raise HTTPException(503, f"Ingestion queue unavailable: {exc}") from exc
            return cache[key]

    @app.post("/api/v1/ingest/envelopes")
    async def submit_envelope(request: Request, p=Depends(require("admin", "analyst"))):
        queue = await run_in_threadpool(queue_for_request)
        raw = await request.body()
        ack = await run_in_threadpool(queue.submit, raw, authenticated_agent=p.username)
        if ack.status == "quarantined":
            await run_in_threadpool(core.store.audit, p.username, "ingest_envelope_quarantined", ack.envelope_id,
                                    {"reason": ack.reason})
        headers = {"Retry-After": str(max(1, math.ceil(ack.retry_after)))} if ack.retry_after else None
        return JSONResponse(
            status_code=_STATUS_CODES[ack.status],
            content={"status": ack.status, "envelope_id": ack.envelope_id, "reason": ack.reason},
            headers=headers,
        )

    @app.post("/api/v1/ingest/drain")
    def drain(limit: int = 100, p=Depends(require("admin"))):
        if not 1 <= limit <= 1000:
            raise HTTPException(422, "limit must be between 1 and 1000.")
        result = queue_for_request().drain(core, limit)
        core.store.audit(p.username, "ingest_queue_drained", None, result)
        return result

    @app.get("/api/v1/ingest/stats")
    def stats(p=Depends(require("admin", "analyst", "viewer"))):
        return queue_for_request().stats()
