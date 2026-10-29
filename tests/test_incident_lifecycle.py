from __future__ import annotations

import asyncio
from fastapi import HTTPException
from pydantic import ValidationError
import pytest

import bk_security.api.app as api_module
from bk_security.auth import Principal
from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.events.models import SecurityEvent
from bk_security.incidents import SecurityIncident
from bk_security.incidents.lifecycle import transition_incident


def test_incident_lifecycle_enforces_supported_transitions_and_updates_time():
    incident = SecurityIncident(host_id="host-1", title="test", severity="high", risk_score=70)
    previous, target = transition_incident(incident, "investigating", "2026-10-01T10:00:00+00:00")

    assert (previous, target) == ("NEW", "INVESTIGATING")
    assert incident.status == "INVESTIGATING"
    assert incident.updated_at == "2026-10-01T10:00:00+00:00"


def test_incident_lifecycle_rejects_illegal_or_unknown_transition():
    incident = SecurityIncident(host_id="host-1", title="test", severity="high", risk_score=70)

    try:
        transition_incident(incident, "RESOLVED")
    except ValueError as exc:
        assert "cannot transition" in str(exc)
    else:
        raise AssertionError("NEW incidents cannot skip directly to RESOLVED")

    try:
        transition_incident(incident, "UNKNOWN")
    except ValueError as exc:
        assert "Unsupported incident status" in str(exc)
    else:
        raise AssertionError("Unknown incident status must be rejected")


def test_terminal_incident_is_audited_persisted_and_no_longer_correlates(tmp_path):
    database = str(tmp_path / "incident-lifecycle.sqlite3")
    core = SecurityCore(SecurityStore(database))
    core.ingest(SecurityEvent(
        event_type="network.packet", source="test", host_id="host-lifecycle",
        data={"dst_ip": "203.0.113.20", "dst_port": 4444, "process_name": "powershell.exe"},
    ))
    incident_id = core.incidents[0].incident_id

    core.transition_incident(incident_id, "INVESTIGATING", "analyst")
    persisted = core.transition_incident(incident_id, "RESOLVED", "analyst")
    audit = core.store.list_audit(10)
    assert persisted["status"] == "RESOLVED"
    assert [(row["data"]["from"], row["data"]["to"]) for row in audit if row["action"] == "incident_status_transition"] == [
        ("INVESTIGATING", "RESOLVED"), ("NEW", "INVESTIGATING"),
    ]

    restarted = SecurityCore(SecurityStore(database))
    assert restarted.incidents[0].status == "RESOLVED"
    restarted.ingest(SecurityEvent(
        event_type="network.packet", source="test", host_id="host-lifecycle",
        data={"dst_ip": "203.0.113.20", "dst_port": 4444, "process_name": "powershell.exe"},
    ))
    assert len(restarted.incidents) == 2
    assert restarted.incidents[-1].incident_id != incident_id
    core.store.close()
    restarted.store.close()


def test_incident_status_api_role_validation_audit_and_overview(tmp_path, monkeypatch):
    core = SecurityCore(SecurityStore(str(tmp_path / "incident-api.sqlite3")))
    monkeypatch.setattr(api_module, "core", core)
    core.ingest(SecurityEvent(
        event_type="network.packet", source="test", host_id="host-api-lifecycle",
        data={"dst_ip": "203.0.113.21", "dst_port": 4444, "process_name": "powershell.exe"},
    ))
    incident_id = core.incidents[-1].incident_id
    admin = Principal("admin", "admin")
    viewer = Principal("viewer", "viewer")

    with pytest.raises(HTTPException) as forbidden:
        api_module.require("admin", "analyst")(p=viewer)
    assert forbidden.value.status_code == 403
    with pytest.raises(ValidationError):
        api_module.IncidentStatusUpdate(status="UNKNOWN")

    changed = asyncio.run(api_module.update_incident_status(
        incident_id, api_module.IncidentStatusUpdate(status="INVESTIGATING"), admin,
    ))
    assert changed["incident"]["status"] == "INVESTIGATING"
    with pytest.raises(HTTPException) as invalid_transition:
        asyncio.run(api_module.update_incident_status(
            incident_id, api_module.IncidentStatusUpdate(status="NEW"), admin,
        ))
    assert invalid_transition.value.status_code == 409
    resolved = asyncio.run(api_module.update_incident_status(
        incident_id, api_module.IncidentStatusUpdate(status="RESOLVED"), admin,
    ))
    assert resolved["incident"]["status"] == "RESOLVED"
    assert api_module.overview()["open_incidents"] == 0
    assert any(row["action"] == "incident_status_transition" for row in core.store.list_audit(10))
    core.store.close()


def test_incident_status_routes_are_in_openapi():
    assert "/api/v1/incidents/{incident_id}/status" in api_module.app.openapi()["paths"]
