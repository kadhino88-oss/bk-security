from __future__ import annotations

import pytest

from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.sensors.network import NetworkSensor


@pytest.mark.parametrize("scenario", [
    "DNS_ANOMALY",
    "PORT_SCAN",
    "BEACONING",
    "EXFILTRATION",
    "SUSPICIOUS_PROCESS",
    "MULTI_SIGNAL_ATTACK",
])
def test_golden_security_scenario_reaches_alert_and_incident(scenario, tmp_path):
    core = SecurityCore(SecurityStore(str(tmp_path / f"{scenario.lower()}.sqlite3")))
    sensor = NetworkSensor(core, host_id=f"golden-{scenario.lower()}", simulation=True, scenario=scenario)
    try:
        sensor.start()
        assert core.events, scenario
        assert core.alerts, scenario
        assert core.incidents, scenario
        assert all(alert.host_id == f"golden-{scenario.lower()}" for alert in core.alerts)
        assert all(alert.source_event_ids for alert in core.alerts)
        if scenario == "EXFILTRATION":
            assert any("T1041" in alert.mitre_techniques for alert in core.alerts)
        if scenario == "MULTI_SIGNAL_ATTACK":
            assert {event.event_type for event in core.events} >= {
                "network.dns", "endpoint.process", "network.packet",
            }
            assert len(core.incidents) == 1
            assert len(core.incidents[0].alert_ids) >= 2
    finally:
        sensor.stop()
        core.store.close()

