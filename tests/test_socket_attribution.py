import socket
from collections import namedtuple
from types import SimpleNamespace

from bk_security.core import SecurityCore
from bk_security.events.models import SecurityEvent
from bk_security.sensors import socket as socket_module
from bk_security.sensors.socket import SocketAttributionSensor


def test_socket_attribution_links_process_destination_and_incident(monkeypatch):
    class Process:
        def __init__(self, pid):
            self.pid = pid
        def name(self):
            return "powershell.exe"
        def exe(self):
            return "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        def username(self):
            return "analyst"

    Address = namedtuple("Address", "ip port")
    connection = SimpleNamespace(
        pid=731,
        status="ESTABLISHED",
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=Address("10.0.0.10", 52000),
        raddr=Address("203.0.113.18", 4444),
    )
    monkeypatch.setattr(socket_module.psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(socket_module.psutil, "Process", Process)

    core = SecurityCore()
    sensor = SocketAttributionSensor(host_id="host-01", core=core)
    events = sensor.snapshot()

    assert len(events) == 1
    socket_event = events[0]
    assert socket_event.network["dst_ip"] == "203.0.113.18"
    assert socket_event.network["dst_port"] == 4444
    assert socket_event.process["name"] == "powershell.exe"
    assert core.alerts
    assert len(core.incidents) == 1

    packet_event = SecurityEvent(
        event_type="network.packet",
        source="bk_network_sensor",
        host_id="host-01",
        data={
            "process_name": "powershell.exe",
            "dst_ip": "203.0.113.18",
            "dst_port": 4444,
            "destination_score": 20,
        },
    )
    core.ingest(packet_event)
    assert len(core.incidents) == 1
    assert len(core.incidents[0].alert_ids) == 2
