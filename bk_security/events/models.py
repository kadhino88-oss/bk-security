from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
import uuid

Severity = Literal['info','low','medium','high','critical']
EventType = Literal['network.connection','network.packet','network.dns','endpoint.process','endpoint.socket','endpoint.media','lan.device','security.alert','security.incident','response.action']

def utc_now() -> str: return datetime.now(timezone.utc).isoformat()

@dataclass(slots=True)
class SecurityEvent:
    event_type: EventType; source: str; host_id: str
    timestamp: str = field(default_factory=utc_now)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity = 'info'
    data: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    correlation_id: str | None = None
    process: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    enrichment: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    def to_dict(self) -> dict[str, Any]: return asdict(self)

@dataclass(slots=True)
class SecurityAlert:
    alert_type: str; title: str; severity: Severity; host_id: str; confidence: float; risk_score: int; reason: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    source_event_ids: list[str] = field(default_factory=list)
    correlation_id: str | None = None
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_now)
    def to_dict(self) -> dict[str, Any]: return asdict(self)

from ..incidents.models import SecurityIncident
