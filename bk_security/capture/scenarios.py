from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import time

from ..events.models import SecurityEvent
from .models import PacketObservation


class SimulationScenario(StrEnum):
    NORMAL_TRAFFIC = "NORMAL_TRAFFIC"
    PORT_SCAN = "PORT_SCAN"
    SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS"
    BEACONING = "BEACONING"
    EXFILTRATION = "EXFILTRATION"
    DNS_ANOMALY = "DNS_ANOMALY"
    IOC_MATCH = "IOC_MATCH"
    MULTI_SIGNAL_ATTACK = "MULTI_SIGNAL_ATTACK"


def generate_scenario(name: str, host_id: str, interface: str | None = None):
    """Create a deterministic, local-only event sequence for the selected test case."""
    try:
        scenario = SimulationScenario(str(name).upper())
    except ValueError as exc:
        raise ValueError(f"Unsupported simulation scenario: {name}") from exc

    now = time.time()

    def packet(dst_ip, dst_port, process="browser.exe", index=0, *, metadata=None):
        return PacketObservation(
            src_ip="192.0.2.10", dst_ip=dst_ip, protocol="TCP", size=74,
            src_port=51514 + index, dst_port=dst_port,
            direction="local->remote", interface=interface,
            timestamp=now + index * 0.01, process_name=process, flags="S",
            metadata={"simulation": True, **(metadata or {})},
        )

    def event(event_type, data, *, process=None, index=0, network=None):
        return SecurityEvent(
            event_type=event_type, source="bk_simulation_sensor", host_id=host_id,
            timestamp=datetime.fromtimestamp(now + index * 0.01, timezone.utc).isoformat(),
            data={**data, "simulation": True}, process=process or {}, network=network or {},
            tags=["simulation", scenario.value.lower()],
        )

    if scenario == SimulationScenario.NORMAL_TRAFFIC:
        return [
            event("network.connection", {"dst_ip":"198.51.100.20","dst_port":443,"protocol":"TCP","state":"ESTABLISHED"}, index=0,
                  network={"dst_ip":"198.51.100.20","dst_port":443,"protocol":"TCP"}),
            event("network.connection", {"dst_ip":"198.51.100.21","dst_port":443,"protocol":"TCP","state":"ESTABLISHED"}, index=1,
                  network={"dst_ip":"198.51.100.21","dst_port":443,"protocol":"TCP"}),
        ]
    if scenario == SimulationScenario.PORT_SCAN:
        return [packet("203.0.113.40", port, "scanner.exe", index)
                for index, port in enumerate((21, 22, 80, 443, 445, 1337, 4444))]
    if scenario == SimulationScenario.SUSPICIOUS_PROCESS:
        process = {"pid": 4242, "name": "powershell.exe", "exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "cmdline": ["powershell.exe", "-EncodedCommand", "<redacted>"], "ppid": 1100, "username": "simulation-user"}
        return [event("endpoint.process", {**process, "process_name": process["name"], "change": "started"}, process=process)]
    if scenario == SimulationScenario.BEACONING:
        return [packet("203.0.113.88", 443, "browser.exe", index) for index in range(31)]
    if scenario == SimulationScenario.EXFILTRATION:
        return [packet(
            "203.0.113.92", 4444, "powershell.exe", 0,
            metadata={"exfiltration": True, "bytes_out": 8_388_608, "simulation": True},
        )]
    if scenario == SimulationScenario.DNS_ANOMALY:
        domain = "a9f4c7d2e8b1f036a5c9d7e4q3.example"
        return [
            event("network.dns", {"domain": domain, "qtype": "A", "answers": ["203.0.113.91"], "response": True}, index=0),
            packet("203.0.113.91", 443, "browser.exe", 1, metadata={"domain": domain}),
        ]
    if scenario == SimulationScenario.IOC_MATCH:
        return [packet("198.51.100.133", 4444, "powershell.exe", 0, metadata={"indicator_score": 99, "simulation_ioc": True})]
    # DNS, endpoint execution and network connection share a host/process/destination.
    return [
        event("network.dns", {"domain": "updates-compromised.example", "qtype": "A", "answers": ["203.0.113.99"], "response": True}, index=0),
        event("endpoint.process", {"pid": 4243, "name": "powershell.exe", "process_name": "powershell.exe", "exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "cmdline": ["powershell.exe", "-EncodedCommand", "<redacted>"], "ppid": 1100, "username": "simulation-user", "change": "started"}, process={"pid": 4243, "name": "powershell.exe"}, index=1),
        packet("203.0.113.99", 4444, "powershell.exe", 2),
    ]
