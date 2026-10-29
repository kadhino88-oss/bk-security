from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.events.models import SecurityAlert, SecurityEvent
from bk_security.incidents.models import SecurityIncident
from bk_security.sensors.network import NetworkSensor


def test_production_restore_hides_simulated_history_but_preserves_it_in_storage(tmp_path, monkeypatch):
    database = str(tmp_path / "simulation-history.sqlite3")
    monkeypatch.delenv("BK_SECURITY_ENV", raising=False)
    store = SecurityStore(database)
    development_core = SecurityCore(store)
    simulation_sensor = NetworkSensor(
        development_core, host_id="simulated-host", simulation=True,
    )
    simulation_sensor.start()
    simulation_sensor.stop()

    real_event = SecurityEvent(
        event_type="endpoint.socket", source="bk_socket_sensor", host_id="real-host",
        data={"state": "established"},
    )
    real_alert = SecurityAlert(
        alert_type="test.real", title="Real telemetry alert", severity="low",
        host_id="real-host", confidence=0.5, risk_score=10, reason="test fixture",
        source_event_ids=[real_event.event_id],
    )
    real_incident = SecurityIncident(
        host_id="real-host", title="Real telemetry incident", severity="low",
        risk_score=10, alert_ids=[real_alert.alert_id],
    )
    store.save_event(real_event)
    store.save_alert(real_alert)
    store.save_incident(real_incident)
    store.close()

    monkeypatch.setenv("BK_SECURITY_ENV", "production")
    production_store = SecurityStore(database)
    production_core = SecurityCore(production_store)

    assert [event.event_id for event in production_core.events] == [real_event.event_id]
    assert [alert.alert_id for alert in production_core.alerts] == [real_alert.alert_id]
    assert [incident.incident_id for incident in production_core.incidents] == [real_incident.incident_id]
    assert production_core.simulation_excluded_records == {"events": 1, "alerts": 1, "incidents": 1}

    # The operational view filters test artifacts without deleting the evidence.
    assert len(production_store.list_events(100)) == 2
    assert len(production_store.list_alerts(100)) == 2
    assert len(production_store.list_incidents(100)) == 2
    production_store.close()


def test_production_provenance_scan_precedes_event_retention(tmp_path, monkeypatch):
    database = str(tmp_path / "bounded-history.sqlite3")
    monkeypatch.delenv("BK_SECURITY_ENV", raising=False)
    development_store = SecurityStore(database, max_events=1)
    development_core = SecurityCore(development_store)
    simulation_sensor = NetworkSensor(
        development_core, host_id="simulated-host", simulation=True,
    )
    simulation_sensor.start()
    simulation_sensor.stop()
    real_event = SecurityEvent(
        event_type="endpoint.socket", source="bk_socket_sensor", host_id="real-host",
        data={"state": "established"},
    )
    development_store.save_event(real_event)
    development_store.close()

    monkeypatch.setenv("BK_SECURITY_ENV", "production")
    production_store = SecurityStore(database, max_events=1)
    production_core = SecurityCore(production_store)

    assert production_core.simulation_excluded_records == {"events": 1, "alerts": 1, "incidents": 1}
    assert [event.event_id for event in production_core.events] == [real_event.event_id]
    assert len(production_store.list_events(10)) == 1
    production_store.close()
