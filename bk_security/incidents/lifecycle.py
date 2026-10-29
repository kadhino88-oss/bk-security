from __future__ import annotations

from datetime import datetime, timezone
from typing import Final, Literal

IncidentStatus = Literal["NEW", "INVESTIGATING", "CONTAINMENT", "RESOLVED", "CLOSED"]
INCIDENT_STATUSES: Final[frozenset[str]] = frozenset({
    "NEW", "INVESTIGATING", "CONTAINMENT", "RESOLVED", "CLOSED",
})
INCIDENT_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "NEW": frozenset({"INVESTIGATING", "CLOSED"}),
    "INVESTIGATING": frozenset({"CONTAINMENT", "RESOLVED", "CLOSED"}),
    "CONTAINMENT": frozenset({"INVESTIGATING", "RESOLVED", "CLOSED"}),
    "RESOLVED": frozenset({"INVESTIGATING", "CLOSED"}),
    "CLOSED": frozenset(),
}


def normalize_incident_status(status: str) -> IncidentStatus:
    normalized = str(status).strip().upper()
    if normalized == "OPEN":  # Migrate the former pre-lifecycle default.
        normalized = "NEW"
    if normalized not in INCIDENT_STATUSES:
        raise ValueError(f"Unsupported incident status: {status}")
    return normalized  # type: ignore[return-value]


def transition_incident(incident, status: str, timestamp: str | None = None) -> tuple[str, str]:
    previous = normalize_incident_status(incident.status)
    target = normalize_incident_status(status)
    if target not in INCIDENT_TRANSITIONS[previous]:
        raise ValueError(f"Incident cannot transition from {previous} to {target}")
    incident.status = target
    incident.updated_at = timestamp or datetime.now(timezone.utc).isoformat()
    return previous, target
