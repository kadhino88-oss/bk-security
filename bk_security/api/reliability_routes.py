from __future__ import annotations

from fastapi import Depends, HTTPException

from ..ai.contracts import InvestigationRequest
from ..reliability import BKRegressionGuardian, ReliabilityService, RepairAction


def install(app, core, require, service: ReliabilityService, guardian: BKRegressionGuardian) -> None:
    @app.get("/api/v1/reliability/integrity")
    async def integrity(p=Depends(require("admin", "analyst", "viewer"))):
        return service.integrity().to_dict()

    @app.get("/api/v1/reliability/diagnosis")
    async def diagnosis(p=Depends(require("admin", "analyst"))):
        return guardian.diagnose()

    @app.get("/api/v1/reliability/audit")
    async def reliability_audit(limit: int = 100, p=Depends(require("admin", "analyst"))):
        valid, error = service.monitor.ledger.verify_audit()
        return {"valid": valid, "diagnostic": error, "entries": service.monitor.ledger.list_audit(limit)}

    @app.post("/api/v1/reliability/repair")
    async def safe_repair(body: dict, p=Depends(require("admin"))):
        action = str(body.get("action", ""))
        target = str(body.get("target", ""))
        if action == RepairAction.REBUILD_CACHE_INDEX.value and target != "correlation":
            raise HTTPException(422, "Correlation index repair requires target=correlation")
        if not action or not target:
            raise HTTPException(422, "action and target are required")
        result = service.run_safe_repair(action, target, actor=p.username)
        if result.get("status") != "SUCCEEDED":
            raise HTTPException(409, detail=result)
        return result

    @app.get("/api/v1/incidents/{incident_id}/investigate")
    async def investigate_incident(incident_id: str, p=Depends(require("admin", "analyst", "viewer"))):
        incident = next((item for item in core.incidents if item.incident_id == incident_id), None)
        if incident is None:
            raise HTTPException(404, "Incident not found")
        alert_ids = set(incident.alert_ids)
        alerts = [item for item in core.alerts if item.alert_id in alert_ids]
        if not alerts:
            raise HTTPException(404, "No persisted alerts are available for this incident")
        results = []
        event_ids: set[str] = set()
        for alert in alerts:
            related = [event for event in core.events if event.event_id in alert.source_event_ids]
            event_ids.update(event.event_id for event in related)
            intel = next((event.enrichment.get("threat_intel") for event in related if event.enrichment.get("threat_intel")), {})
            request = InvestigationRequest(
                alert=alert,
                related_events=related,
                threat_context={"threat_intel": intel, "incident": incident.to_dict()},
            )
            result = core.ai.investigate(request)
            results.append(result.to_dict())
        core.store.audit(p.username, "investigate_incident", incident_id, {"alert_ids": sorted(alert_ids)})
        return {
            "incident_id": incident_id,
            "traceability": {"incident_id": incident_id, "alert_ids": sorted(alert_ids), "event_ids": sorted(event_ids)},
            "investigations": results,
        }
