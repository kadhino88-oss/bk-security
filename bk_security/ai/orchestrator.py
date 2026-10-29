from __future__ import annotations

import math

from .contracts import InvestigationRequest, InvestigationResult, SecurityWorker

class SecurityOrchestrator:
    """BK-AI-WORKERS bridge: fan-out eligible analysts, then synthesize deterministically."""
    def __init__(self, workers: list[SecurityWorker] | None = None) -> None:
        self.workers = workers or []

    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        results: list[tuple[str, InvestigationResult]] = []
        worker_records: list[dict] = []
        for worker in self.workers:
            name = str(getattr(worker, "name", type(worker).__name__))
            try:
                if not worker.can_handle(request):
                    continue
                raw = worker.investigate(request)
                if not isinstance(raw, InvestigationResult):
                    raise TypeError("Worker must return InvestigationResult.")
                result = self._attach_provenance(raw, request)
                errors = result.validate_for(request)
                if not isinstance(result.confidence, (int, float)) or not math.isfinite(float(result.confidence)) or not 0 <= float(result.confidence) <= 1:
                    result.confidence = 0.0
                else:
                    result.confidence = float(result.confidence)
                if result.disposition not in {"benign", "suspicious", "malicious", "needs_review"}:
                    result.disposition = "needs_review"
                if not isinstance(result.summary, str):
                    result.summary = ""
                if not isinstance(result.findings, list):
                    result.findings = []
                if not isinstance(result.recommended_actions, list):
                    result.recommended_actions = []
                if not isinstance(result.evidence, list):
                    result.evidence = []
                if not isinstance(result.mitre_techniques, list):
                    result.mitre_techniques = []
                if not isinstance(result.limitations, list):
                    result.limitations = []
                result.valid = not errors
                result.validation_errors = errors
                results.append((name, result))
                worker_records.append({
                    "worker": name,
                    "disposition": result.disposition,
                    "confidence": float(result.confidence) if isinstance(result.confidence, (int, float)) else 0.0,
                    "valid": result.valid,
                    "validation_errors": list(errors),
                })
            except Exception as exc:
                message = f"{name} failed: {type(exc).__name__}: {exc}"
                worker_records.append({"worker": name, "valid": False, "validation_errors": [message]})

        if not results:
            return InvestigationResult(
                "needs_review", 0.0, "No eligible security worker produced a validated result.",
                limitations=["No worker conclusion is available; analyst review is required."],
                worker_results=worker_records,
                source_alert_id=request.alert.alert_id,
                source_event_ids=list(request.alert.source_event_ids or [event.event_id for event in request.related_events]),
                sources=self._source_records(request),
                mitre_techniques=list(request.alert.mitre_techniques),
                valid=False,
                validation_errors=["no_valid_worker_result"],
                source_incident_ids=self._incident_ids(request),
            )

        all_valid = all(result.valid for _, result in results) and all(record.get("valid", False) for record in worker_records)
        priority = {"malicious": 4, "suspicious": 3, "needs_review": 2, "benign": 1}
        best = max((result for _, result in results), key=lambda item: (priority.get(item.disposition, 0), item.confidence))
        dispositions = {result.disposition for _, result in results if result.valid}
        conflicts = []
        if "benign" in dispositions and dispositions.intersection({"suspicious", "malicious"}):
            conflicts.append("Workers disagree between benign and suspicious/malicious dispositions.")
        findings = [finding for _, result in results for finding in result.findings]
        actions = list(dict.fromkeys(action for _, result in results for action in result.recommended_actions))
        evidence = self._dedupe([item for _, result in results for item in result.evidence])
        source_ids = list(request.alert.source_event_ids)
        if not all_valid:
            disposition = "needs_review"
            summary = "One or more worker results failed provenance or schema validation; analyst review is required."
        elif conflicts:
            disposition = "needs_review"
            summary = "Conflicting security worker conclusions require analyst review."
        else:
            disposition = best.disposition
            summary = f"{best.summary} ({len(results)} security worker(s) consulted)."
        if not source_ids:
            # Related events are permitted as provenance when an older alert did
            # not persist source_event_ids, but only exact request events qualify.
            source_ids = [event.event_id for event in request.related_events]
        final = InvestigationResult(
            disposition,
            max(float(result.confidence) for _, result in results),
            summary,
            findings,
            actions,
            evidence,
            source_alert_id=request.alert.alert_id,
            source_event_ids=source_ids,
            sources=self._source_records(request),
            mitre_techniques=list(dict.fromkeys(
                [*request.alert.mitre_techniques, *(technique for _, result in results for technique in result.mitre_techniques)]
            )),
            limitations=self._dedupe([item for _, result in results for item in result.limitations] + (["Conflicting worker findings require human adjudication."] if conflicts else [])),
            conflicts=conflicts,
            worker_results=worker_records,
            valid=all_valid and bool(evidence) and bool(source_ids),
            source_incident_ids=self._incident_ids(request),
        )
        final.validation_errors = final.validate_for(request)
        final.valid = final.valid and not final.validation_errors
        if not final.valid and not final.validation_errors:
            final.validation_errors.append("conclusion_provenance_missing")
        return final

    @staticmethod
    def _source_records(request: InvestigationRequest) -> list[dict]:
        event_ids = list(request.alert.source_event_ids) or [event.event_id for event in request.related_events]
        sources = [{"type": "alert", "alert_id": request.alert.alert_id}]
        sources.extend({"type": "event", "event_id": event_id} for event_id in event_ids)
        sources.extend({"type": "incident", "incident_id": incident_id} for incident_id in SecurityOrchestrator._incident_ids(request))
        return sources

    @staticmethod
    def _incident_ids(request: InvestigationRequest) -> list[str]:
        context = request.threat_context or {}
        incident_ids = list(context.get("incident_ids") or [])
        incident = context.get("incident")
        if isinstance(incident, dict) and incident.get("incident_id"):
            incident_ids.append(str(incident["incident_id"]))
        if context.get("incident_id"):
            incident_ids.append(str(context["incident_id"]))
        return list(dict.fromkeys(str(value) for value in incident_ids if value))

    @classmethod
    def _attach_provenance(cls, result: InvestigationResult, request: InvestigationRequest) -> InvestigationResult:
        result.source_alert_id = request.alert.alert_id
        result.source_event_ids = list(dict.fromkeys(request.alert.source_event_ids or [event.event_id for event in request.related_events]))
        result.source_incident_ids = cls._incident_ids(request)
        result.sources = cls._source_records(request)
        if not result.evidence:
            result.evidence = [dict(item) for item in request.alert.evidence]
        if not result.evidence:
            result.evidence = [{"type": "source_event", "source_event_id": event_id} for event_id in result.source_event_ids]
        if not isinstance(result.mitre_techniques, list) or not result.mitre_techniques:
            result.mitre_techniques = list(request.alert.mitre_techniques)
        return result

    @staticmethod
    def _dedupe(items: list) -> list:
        output = []
        seen = set()
        for item in items:
            key = repr(item)
            if key not in seen:
                seen.add(key)
                output.append(item)
        return output
