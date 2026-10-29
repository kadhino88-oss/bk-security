from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import SecurityEvent


def _value(observation: Any, name: str, default: Any = None) -> Any:
    if isinstance(observation, Mapping):
        return observation.get(name, default)
    return getattr(observation, name, default)


def _integer(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def packet_to_event(observation: Any, host_id: str = "local-host", **scores: float) -> SecurityEvent:
    """Normalize a packet observation into BK Security's stable event contract."""
    src_ip = _value(observation, "src_ip")
    dst_ip = _value(observation, "dst_ip")
    src_port = _integer(_value(observation, "src_port"))
    dst_port = _integer(_value(observation, "dst_port"))
    size = _integer(_value(observation, "size", _value(observation, "bytes")))
    protocol = str(_value(observation, "protocol", "unknown")).upper()
    direction = str(_value(observation, "direction", "unknown"))
    pid = _integer(_value(observation, "pid"))
    process_name = _value(observation, "process_name", _value(observation, "process"))
    data = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": max(0, size or 0),
        "direction": direction,
        "pid": pid,
        "process_name": process_name,
        **scores,
    }
    interface = _value(observation, "interface")
    if interface:
        data["interface"] = str(interface)
    return SecurityEvent(
        event_type="network.packet",
        source="bk_network_sensor",
        host_id=host_id,
        data=data,
        network={
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "direction": direction,
            "bytes": max(0, size or 0),
            "interface": interface,
        },
        process={"pid": pid, "name": process_name} if pid or process_name else {},
    )


def device_to_event(observation: Any, host_id: str = "local-host") -> SecurityEvent:
    data = {
        key: _value(observation, key)
        for key in ("ip", "mac", "vendor", "device_type", "hostname", "online")
    }
    return SecurityEvent(
        event_type="lan.device",
        source="bk_lan_sensor",
        host_id=host_id,
        data=data,
        network={"src_ip": data["ip"], "mac": data["mac"]},
        tags=["lan"],
    )


def media_to_event(observation: Any, host_id: str = "local-host") -> SecurityEvent:
    microphones = _value(observation, "mic", _value(observation, "microphone", [])) or []
    cameras = _value(observation, "camera", []) or []
    return SecurityEvent(
        event_type="endpoint.media",
        source="bk_endpoint_sensor",
        host_id=host_id,
        data={"microphone": list(microphones), "camera": list(cameras)},
        tags=["endpoint", "privacy"],
    )


def process_to_event(process: Any, host_id: str = "local-host") -> SecurityEvent:
    fields = (
        "pid", "name", "exe", "cmdline", "ppid", "username", "create_time",
        "cpu_percent", "memory_bytes", "status", "observed_at",
    )
    process_data = {key: _value(process, key) for key in fields}
    process_data["pid"] = _integer(process_data["pid"])
    if process_data["name"]:
        process_data["process_name"] = process_data["name"]
    if process_data.get("cmdline") is not None:
        process_data["cmdline"] = list(process_data["cmdline"])
    return SecurityEvent(
        event_type="endpoint.process",
        source="bk_endpoint_sensor",
        host_id=host_id,
        data=dict(process_data),
        process=dict(process_data),
        tags=["endpoint", "process"],
    )


def dns_to_event(query: Any, host_id: str = "local-host") -> SecurityEvent:
    domain = str(_value(query, "domain", "") or "").strip().lower().rstrip(".")
    answers = _value(query, "answers", []) or []
    return SecurityEvent(
        event_type="network.dns",
        source="bk_dns_sensor",
        host_id=host_id,
        data={"domain": domain, "qtype": str(_value(query, "qtype", "A")).upper(), "answers": list(answers)},
        tags=["network", "dns"],
    )
