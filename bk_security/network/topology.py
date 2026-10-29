from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from ..events.models import SecurityEvent


def _timestamp(value: str) -> datetime | None:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def build_network_topology(
    events: Iterable[SecurityEvent],
    minutes: int = 60,
    now: datetime | None = None,
) -> dict:
    """Build a bounded, read-only host/process/destination graph from telemetry."""
    minutes = max(1, min(1440, int(minutes)))
    end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = end - timedelta(minutes=minutes)
    recent: list[tuple[SecurityEvent, datetime]] = []
    dns_aliases: dict[tuple[str, str], set[str]] = defaultdict(set)

    for event in events:
        timestamp = _timestamp(event.timestamp)
        if timestamp is None or timestamp < start or timestamp > end:
            continue
        if event.event_type == "network.dns":
            domain = str(event.data.get("domain") or "").strip().lower().rstrip(".")
            if domain:
                for answer in event.data.get("answers") or []:
                    ip = str(answer).strip()
                    if ip:
                        dns_aliases[(event.host_id, ip)].add(domain)
        elif event.event_type in {"network.packet", "network.connection", "endpoint.socket", "lan.device"}:
            recent.append((event, timestamp))

    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str], dict] = {}

    def node(node_id: str, node_type: str, label: str, **extra) -> dict:
        return nodes.setdefault(node_id, {"id": node_id, "type": node_type, "label": label, **extra})

    def add_edge(source: str, target: str, event: SecurityEvent, timestamp: datetime, byte_count: int, port, protocol):
        key = (source, target)
        edge = edges.setdefault(key, {
            "id": f"{source}->{target}", "source": source, "target": target,
            "events": 0, "bytes": 0, "ports": set(), "protocols": set(),
            "first_seen": event.timestamp, "last_seen": event.timestamp,
        })
        edge["events"] += 1
        edge["bytes"] += byte_count
        if port is not None:
            edge["ports"].add(port)
        if protocol:
            edge["protocols"].add(str(protocol).upper())
        edge["first_seen"] = min(edge["first_seen"], event.timestamp)
        edge["last_seen"] = max(edge["last_seen"], event.timestamp)

    for event, timestamp in recent:
        data, network = event.data, event.network
        host_id = str(event.host_id)
        host_node = f"host:{host_id}"
        if event.event_type == "lan.device":
            node(host_node, "host", host_id, host_id=host_id)
            ip = str(data.get("ip") or "").strip()
            mac = str(data.get("mac") or "").strip().lower()
            if not ip and not mac:
                continue
            device_key = mac or ip
            device_node = f"lan-device:{host_id}:{device_key}"
            label = str(data.get("hostname") or ip or mac)
            node(
                device_node,
                "lan_device",
                label,
                host_id=host_id,
                ip=ip or None,
                mac=mac or None,
                vendor=data.get("vendor"),
                online=bool(data.get("online", True)),
            )
            add_edge(host_node, device_node, event, timestamp, 0, None, "ARP")
            continue

        destination_ip = data.get("dst_ip") or network.get("dst_ip")
        destination_domain = str(data.get("domain") or "").strip().lower().rstrip(".")
        if not destination_ip and not destination_domain:
            continue

        observed_source_ip = str(data.get("observed_source_ip") or "").strip()
        node(host_node, "host", observed_source_ip or host_id, host_id=host_id,
             observed_ip=observed_source_ip or None,
             sensor_host_id=data.get("sensor_host_id"))

        process = event.process or {}
        pid = process.get("pid", data.get("pid"))
        process_name = str(process.get("name") or data.get("process_name") or "").strip()
        source_node = host_node
        if pid is not None or process_name:
            process_key = f"pid:{pid}" if pid is not None else f"name:{process_name.lower()}"
            source_node = f"process:{host_id}:{process_key}"
            node(source_node, "process", process_name or f"PID {pid}", host_id=host_id, pid=pid, process_name=process_name or None)
            add_edge(host_node, source_node, event, timestamp, 0, None, None)

        destination = str(destination_ip or destination_domain).strip()
        destination_node = f"destination:{destination}"
        aliases = dns_aliases.get((host_id, destination), set())
        if destination_domain:
            aliases.add(destination_domain)
        dest_node = node(destination_node, "destination", destination, ip=destination_ip, domains=[])
        dest_node["domains"] = sorted(set(dest_node["domains"]) | aliases)

        try:
            byte_count = max(0, int(data.get("size", network.get("bytes", 0)) or 0))
        except (TypeError, ValueError, OverflowError):
            byte_count = 0
        port = data.get("dst_port", network.get("dst_port"))
        protocol = data.get("protocol", network.get("protocol"))
        add_edge(source_node, destination_node, event, timestamp, byte_count, port, protocol)

    serialized_edges = [
        {**edge, "ports": sorted(edge["ports"], key=lambda value: str(value)), "protocols": sorted(edge["protocols"])}
        for edge in edges.values()
    ]
    return {
        "window_minutes": minutes,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "event_count": len(recent),
        "nodes": list(nodes.values()),
        "edges": serialized_edges,
    }
