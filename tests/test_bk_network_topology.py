from datetime import datetime, timedelta, timezone

import asyncio

from bk_security.api.app import app, core as api_core
from bk_security.detection.correlation import CorrelationEngine
from bk_security.events.models import SecurityAlert, SecurityEvent
from bk_security.network import build_network_topology


def _alert(host, process, destination, timestamp, alert_id):
    return SecurityAlert(
        alert_type="test",
        title="test signal",
        severity="high",
        host_id=host,
        confidence=0.9,
        risk_score=80,
        reason="test",
        evidence=[
            {"field": "process", "value": process},
            {"field": "destination_ip", "value": destination},
        ],
        timestamp=timestamp,
        alert_id=alert_id,
    )


def test_correlation_clusters_by_host_process_destination_and_window():
    engine = CorrelationEngine(window_seconds=60)
    start = datetime.now(timezone.utc)
    first = _alert("host-a", "powershell.exe", "203.0.113.8", start.isoformat(), "a1")
    same_process = _alert("host-a", "powershell.exe", "203.0.113.9", (start + timedelta(seconds=10)).isoformat(), "a2")
    same_destination = _alert("host-a", "cmd.exe", "203.0.113.9", (start + timedelta(seconds=20)).isoformat(), "a3")
    unrelated = _alert("host-a", "chrome.exe", "198.51.100.4", (start + timedelta(seconds=25)).isoformat(), "a4")
    other_host = _alert("host-b", "powershell.exe", "203.0.113.9", (start + timedelta(seconds=30)).isoformat(), "b1")

    first_result = engine.add(first)
    process_result = engine.add(same_process)
    destination_result = engine.add(same_destination)
    unrelated_result = engine.add(unrelated)
    other_host_result = engine.add(other_host)

    assert first_result.incident_key == process_result.incident_key == destination_result.incident_key
    assert process_result.related_alert_ids == ["a1", "a2"]
    assert unrelated_result.incident_key != first_result.incident_key
    assert other_host_result.incident_key != first_result.incident_key


def test_correlation_starts_new_incident_after_window_expires():
    engine = CorrelationEngine(window_seconds=30)
    start = datetime.now(timezone.utc)
    first = engine.add(_alert("host-a", "powershell.exe", "203.0.113.8", start.isoformat(), "a1"))
    later = engine.add(_alert("host-a", "powershell.exe", "203.0.113.8", (start + timedelta(seconds=31)).isoformat(), "a2"))
    assert first.incident_key != later.incident_key
    assert later.related_alert_ids == ["a2"]


def test_correlation_keeps_host_and_cluster_memory_bounded():
    engine = CorrelationEngine(window_seconds=60, max_alerts_per_host=2, max_hosts=1)
    start = datetime.now(timezone.utc)
    engine.add(_alert("host-a", "one.exe", "203.0.113.1", start.isoformat(), "a1"))
    engine.add(_alert("host-a", "two.exe", "203.0.113.2", (start + timedelta(seconds=1)).isoformat(), "a2"))
    engine.add(_alert("host-a", "three.exe", "203.0.113.3", (start + timedelta(seconds=2)).isoformat(), "a3"))
    assert len(engine._by_host["host-a"]) == 2

    engine.add(_alert("host-b", "four.exe", "203.0.113.4", (start + timedelta(seconds=3)).isoformat(), "b1"))
    assert list(engine._by_host) == ["host-b"]


def test_topology_aggregates_recent_process_destination_and_dns_context():
    now = datetime.now(timezone.utc)
    dns = SecurityEvent(
        event_type="network.dns",
        source="test",
        host_id="host-a",
        timestamp=now.isoformat(),
        data={"domain": "example.test", "answers": ["203.0.113.8"]},
    )
    packet = SecurityEvent(
        event_type="network.packet",
        source="test",
        host_id="host-a",
        timestamp=now.isoformat(),
        data={"src_ip": "192.0.2.2", "dst_ip": "203.0.113.8", "dst_port": 443, "protocol": "tcp", "size": 128},
        process={"pid": 42, "name": "browser.exe"},
    )
    old = SecurityEvent(
        event_type="network.packet",
        source="test",
        host_id="host-a",
        timestamp=(now - timedelta(hours=2)).isoformat(),
        data={"dst_ip": "198.51.100.4", "dst_port": 80, "protocol": "tcp", "size": 512},
    )

    graph = build_network_topology([dns, packet, old], minutes=60, now=now)

    assert graph["event_count"] == 1
    assert {node["type"] for node in graph["nodes"]} == {"host", "process", "destination"}
    destination = next(node for node in graph["nodes"] if node["type"] == "destination")
    assert destination["domains"] == ["example.test"]
    flow = next(edge for edge in graph["edges"] if edge["target"] == destination["id"])
    assert flow["events"] == 1
    assert flow["bytes"] == 128
    assert flow["ports"] == [443]
    assert flow["protocols"] == ["TCP"]


def test_topology_includes_lan_discovered_devices():
    now = datetime.now(timezone.utc)
    device = SecurityEvent(
        event_type="lan.device",
        source="bk_lan_discovery",
        host_id="host-a",
        timestamp=now.isoformat(),
        data={"ip": "192.168.1.8", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Example", "online": True},
    )
    graph = build_network_topology([device], minutes=60, now=now)

    node = next(item for item in graph["nodes"] if item["type"] == "lan_device")
    assert node["ip"] == "192.168.1.8"
    assert node["vendor"] == "Example"
    assert graph["edges"][0]["protocols"] == ["ARP"]


def test_topology_includes_process_attributed_socket_observations():
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        event_type="endpoint.socket",
        source="bk_socket_sensor",
        host_id="host-socket",
        timestamp=now.isoformat(),
        data={"dst_ip": "203.0.113.25", "dst_port": 8443, "protocol": "TCP"},
        network={"dst_ip": "203.0.113.25", "dst_port": 8443, "protocol": "TCP"},
        process={"pid": 42, "name": "agent.exe"},
    )
    graph = build_network_topology([event], minutes=60, now=now)
    assert graph["event_count"] == 1
    assert {node["type"] for node in graph["nodes"]} == {"host", "process", "destination"}
    assert next(node for node in graph["nodes"] if node["type"] == "process")["label"] == "agent.exe"


def test_topology_endpoint_is_available_to_viewer():
    event = SecurityEvent(
        event_type="network.packet",
        source="test",
        host_id="api-topology-host",
        data={"dst_ip": "203.0.113.20", "dst_port": 443, "protocol": "tcp", "size": 64},
    )
    api_core.events.append(event)
    try:
        route = next(route for route in app.routes if getattr(route, "path", None) == "/api/v1/network/topology")
        response = asyncio.run(route.endpoint(minutes=60, p=None))
        assert response["event_count"] >= 1
        assert any(node["label"] == "203.0.113.20" for node in response["nodes"])
    finally:
        api_core.events.remove(event)
