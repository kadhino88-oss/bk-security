from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Literal
import uuid
from .lifecycle import IncidentStatus

Severity = Literal['info','low','medium','high','critical']
def utc_now(): return datetime.now(timezone.utc).isoformat()

@dataclass(slots=True)
class SecurityIncident:
    host_id: str
    title: str
    severity: Severity
    risk_score: int
    incident_id: str = field(default_factory=lambda:str(uuid.uuid4()))
    status: IncidentStatus = 'NEW'
    alert_ids: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    summary: str = ''
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    # Stable recurring-threat identity. This does not merge incidents.
    threat_family_id: str | None = None
    threat_fingerprint: str | None = None
    def to_dict(self): return asdict(self)
