from __future__ import annotations

from types import SimpleNamespace

import pytest
from collections import namedtuple

from bk_security.core import SecurityCore
from bk_security.sensors import endpoint as endpoint_module
from bk_security.sensors import socket as socket_module
from bk_security.sensors.endpoint import EndpointProcessSensor, _safe_command_line
from bk_security.sensors.socket import SocketAttributionSensor


def test_process_command_line_redacts_secret_flags_and_bounds_arguments():
    assert _safe_command_line([
        "powershell.exe", "--password", "do-not-store", "--api-key=private-key", "-Mode", "Safe",
    ]) == ["powershell.exe", "--password=<redacted>", "<redacted>", "--api-key=<redacted>", "-Mode", "Safe"]
    assert len(_safe_command_line(["x" * 5000])[0]) == 512


def test_endpoint_sensor_emits_new_suspicious_process_once_and_keeps_current_view(monkeypatch):
    process = SimpleNamespace(info={
        "pid": 4242, "name": "powershell.exe", "exe": "C:/Windows/powershell.exe",
        "cmdline": ["powershell.exe", "-EncodedCommand", "abc", "--password", "secret"], "ppid": 100,
        "username": "tester", "create_time": 10.0, "cpu_percent": 1.5,
        "memory_info": SimpleNamespace(rss=1024), "status": "running",
    })
    monkeypatch.setattr(endpoint_module.psutil, "process_iter", lambda attrs: [process])
    core = SecurityCore()
    sensor = EndpointProcessSensor(core, "host-process", interval_seconds=5)

    first = sensor.snapshot()
    second = sensor.snapshot()

    assert len(first) == 1
    assert second == []
    assert sensor.records[4242]["memory_bytes"] == 1024
    assert sensor.records[4242]["cmdline"][4] == "<redacted>"
    assert core.alerts[0].alert_type == "SUSPICIOUS_PROCESS_EXECUTION"
    assert "T1059.001" in core.alerts[0].mitre_techniques
    core.store.close()


def test_socket_sensor_deduplicates_unchanged_snapshots(monkeypatch):
    Address = namedtuple("Address", "ip port")
    address = Address("10.0.0.10", 52000)
    remote = Address("203.0.113.18", 4444)
    connection = SimpleNamespace(
        pid=731, status="ESTABLISHED", family=2, type=socket_module.socket.SOCK_STREAM,
        laddr=address, raddr=remote,
    )

    class Process:
        def __init__(self, _pid): pass
        def name(self): return "powershell.exe"
        def exe(self): return "C:/Windows/powershell.exe"
        def username(self): return "tester"

    monkeypatch.setattr(socket_module.psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(socket_module.psutil, "Process", Process)
    core = SecurityCore()
    sensor = SocketAttributionSensor("host-socket", core, interval_seconds=5)

    assert len(sensor.snapshot()) == 1
    assert sensor.snapshot() == []
    assert len(sensor.connections) == 1
    assert core.alerts
    core.store.close()


@pytest.mark.parametrize("scenario", [
    "NORMAL_TRAFFIC", "PORT_SCAN", "SUSPICIOUS_PROCESS", "BEACONING",
    "DNS_ANOMALY", "IOC_MATCH", "MULTI_SIGNAL_ATTACK",
])
def test_simulation_scenarios_run_through_core(scenario):
    from bk_security.sensors.network import NetworkSensor

    core = SecurityCore()
    sensor = NetworkSensor(core, host_id=f"simulation-{scenario}", simulation=True, scenario=scenario)
    sensor.start()

    assert sensor.running and sensor.status()["mode"] == "simulation"
    assert core.events
    if scenario == "NORMAL_TRAFFIC":
        assert not core.alerts
    else:
        assert core.alerts
        assert core.incidents
    if scenario == "DNS_ANOMALY":
        assert any(event.data.get("dns_anomaly") for event in core.events)
    if scenario == "IOC_MATCH":
        assert any(event.enrichment.get("threat_intel", {}).get("matched") for event in core.events)
        assert "198.51.100.133" not in core.threat_intel.ip_iocs
    if scenario == "MULTI_SIGNAL_ATTACK":
        assert any(event.event_type == "network.dns" for event in core.events)
        assert any(event.event_type == "endpoint.process" for event in core.events)
        assert len(core.incidents) == 1
        assert len(core.incidents[0].alert_ids) >= 2

    sensor.stop()
    core.store.close()
