from __future__ import annotations

from dataclasses import asdict, dataclass, field
import math
from typing import Any, Literal

from ..events.models import SecurityAlert, SecurityEvent


@dataclass(slots=True)
class InvestigationRequest:
    alert: SecurityAlert
    related_events: list[SecurityEvent] = field(default_factory=list)
    threat_context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class InvestigationResult:
    disposition: Literal["benign", "suspicious", "malicious", "needs_review"]
    confidence: float
    summary: str
    findings: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    source_alert_id: str | None = None
    source_event_ids: list[str] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    worker_results: list[dict[str, Any]] = field(default_factory=list)
    valid: bool = True
    validation_errors: list[str] = field(default_factory=list)
    source_incident_ids: list[str] = field(default_factory=list)

    def validate_for(self, request: InvestigationRequest) -> list[str]:
        """Return contract violations; a conclusion must cite request evidence."""
        errors: list[str] = []
        if not isinstance(self.disposition, str) or self.disposition not in {"benign", "suspicious", "malicious", "needs_review"}:
            errors.append("unsupported_disposition")
        if not isinstance(self.confidence, (int, float)) or not math.isfinite(float(self.confidence)) or not 0 <= float(self.confidence) <= 1:
            errors.append("confidence_out_of_range")
        if not isinstance(self.summary, str) or not self.summary.strip():
            errors.append("summary_missing")
        if self.source_alert_id != request.alert.alert_id:
            errors.append("source_alert_mismatch")
        context = request.threat_context or {}
        incident_ids = set(context.get("incident_ids") or [])
        incident = context.get("incident")
        if isinstance(incident, dict) and incident.get("incident_id"):
            incident_ids.add(str(incident["incident_id"]))
        if context.get("incident_id"):
            incident_ids.add(str(context["incident_id"]))
        if incident_ids and not incident_ids.issubset(set(self.source_incident_ids)):
            errors.append("source_incident_provenance_missing")
        if not set(self.source_incident_ids).issubset(incident_ids):
            errors.append("source_incident_unknown")
        known_event_ids = set(request.alert.source_event_ids)
        known_event_ids.update(event.event_id for event in request.related_events)
        if not isinstance(self.source_event_ids, list) or not self.source_event_ids or not set(self.source_event_ids).issubset(known_event_ids):
            errors.append("source_event_provenance_missing_or_unknown")
        if not isinstance(self.evidence, list) or not self.evidence:
            errors.append("evidence_missing")
        for item in self.sources if isinstance(self.sources, list) else []:
            if isinstance(item, dict) and item.get("type") == "event" and item.get("event_id") not in known_event_ids:
                errors.append("source_event_unknown")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SecurityWorker:
    name = "base_security_worker"

    def can_handle(self, request: InvestigationRequest) -> bool:
        return True

    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        raise NotImplementedError
