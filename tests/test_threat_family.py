from datetime import datetime, timedelta, timezone

from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.events.models import SecurityEvent


def _packet(
    host: str,
    timestamp: str,
    pid: int,
    destination: str = "203.0.113.50",
):
    return SecurityEvent(
        event_type="network.packet",
        source="test",
        host_id=host,
        timestamp=timestamp,
        data={
            "dst_ip": destination,
            "dst_port": 4444,
            "process_name": "powershell.exe",
            "process_id": pid,
        },
    )


def test_threat_family_same_condition_different_pid():
    core = SecurityCore()

    base = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)

    first = core.ingest(
        _packet(
            "family-host",
            base.isoformat(),
            6156,
        )
    )

    second = core.ingest(
        _packet(
            "family-host",
            (base + timedelta(minutes=45)).isoformat(),
            9952,
        )
    )

    assert first
    assert second

    assert len(core.incidents) == 2

    first_incident = core.incidents[-2]
    second_incident = core.incidents[-1]

    assert first_incident.incident_id != second_incident.incident_id
    assert first_incident.threat_family_id
    assert second_incident.threat_family_id
    assert (
        first_incident.threat_family_id
        == second_incident.threat_family_id
    )


def test_threat_family_different_destination_is_distinct():
    core = SecurityCore()

    base = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)

    first = core.ingest(
        _packet(
            "family-host-destination",
            base.isoformat(),
            1001,
            "203.0.113.50",
        )
    )

    second = core.ingest(
        _packet(
            "family-host-destination",
            (base + timedelta(minutes=45)).isoformat(),
            1002,
            "203.0.113.60",
        )
    )

    assert first
    assert second
    assert len(core.incidents) == 2

    assert (
        core.incidents[-2].threat_family_id
        != core.incidents[-1].threat_family_id
    )


def test_threat_family_survives_sqlite_restart(tmp_path):
    database = str(tmp_path / "threat-family.sqlite3")

    base = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)

    first = SecurityCore(SecurityStore(database))

    alerts = first.ingest(
        _packet(
            "persistent-family-host",
            base.isoformat(),
            7001,
        )
    )

    assert alerts
    assert first.incidents

    family_id = first.incidents[-1].threat_family_id
    fingerprint = first.incidents[-1].threat_fingerprint

    first.store.close()

    restarted = SecurityCore(SecurityStore(database))

    restored = next(
        item
        for item in restarted.incidents
        if item.incident_id == first.incidents[-1].incident_id
    )

    assert restored.threat_family_id == family_id
    assert restored.threat_fingerprint == fingerprint


def test_resolved_incident_gets_new_incident_same_family(tmp_path):
    database = str(tmp_path / "threat-family-lifecycle.sqlite3")

    base = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)

    core = SecurityCore(SecurityStore(database))

    first_alerts = core.ingest(
        _packet(
            "lifecycle-family-host",
            base.isoformat(),
            8001,
        )
    )

    assert first_alerts
    first_incident = core.incidents[-1]

    core.transition_incident(
        first_incident.incident_id,
        "INVESTIGATING",
        "test",
    )

    core.transition_incident(
        first_incident.incident_id,
        "RESOLVED",
        "test",
    )

    second_alerts = core.ingest(
        _packet(
            "lifecycle-family-host",
            (base + timedelta(hours=2)).isoformat(),
            8002,
        )
    )

    assert second_alerts

    second_incident = core.incidents[-1]

    assert second_incident.incident_id != first_incident.incident_id
    assert second_incident.threat_family_id == first_incident.threat_family_id
