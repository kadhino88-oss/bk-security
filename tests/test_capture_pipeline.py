import pytest
from datetime import datetime, timezone

from bk_security.capture.models import PacketObservation
from bk_security.capture.pipeline import PacketPipeline, TrafficAggregator
from bk_security.core import SecurityCore
from bk_security.sensors.network import NetworkSensor

def test_packet_becomes_security_event():
    events=[]; pipe=PacketPipeline(callback=events.append)
    event_time = "2026-10-06T10:15:00+00:00"
    event=pipe.observe(PacketObservation(
        '10.0.0.2','8.8.8.8','UDP',120,53000,53,'local->remote','eth0',
        timestamp=datetime.fromisoformat(event_time).timestamp(),
    ))
    assert event.timestamp == event_time
    assert event.event_type=='network.packet'
    assert event.network['dst_port']==53
    assert events[0].data['interface']=='eth0'


def test_dns_packet_emits_structured_passive_dns_event():
    events=[]
    pipe=PacketPipeline(callback=events.append)
    packet=PacketObservation(
        '10.0.0.2','8.8.8.8','UDP',100,53000,53,'local->remote','eth0',
        metadata={'dns':{'domain':'beacon.example','qtype':'A','answers':['203.0.113.9'],'response':True}},
    )

    pipe.observe(packet)

    assert [event.event_type for event in events] == ['network.packet','network.dns']
    assert events[1].data['domain'] == 'beacon.example'
    assert events[1].data['answers'] == ['203.0.113.9']
    assert events[1].source == 'bk_dns_packet_sensor'


def test_scapy_dns_response_parser_extracts_answer_records():
    scapy = pytest.importorskip("scapy.all")
    from bk_security.capture.live import LivePacketCapture

    packet = (
        scapy.IP(src="10.0.0.2", dst="8.8.8.8")
        / scapy.UDP(sport=53, dport=53000)
        / scapy.DNS(
            id=7,
            qr=1,
            qd=[scapy.DNSQR(qname="beacon.example", qtype="A")],
            an=[scapy.DNSRR(rrname="beacon.example", type="A", rdata="203.0.113.9")],
        )
    )
    capture = LivePacketCapture(lambda _: None, local_ips={"10.0.0.2"})
    capture._attribute = lambda *_: (42, "browser.exe")

    observation = capture._parse(packet)

    assert observation.metadata["dns"]["domain"] == "beacon.example"
    assert observation.metadata["dns"]["answers"] == ["203.0.113.9"]
    assert observation.metadata["dns"]["response"] is True
    assert observation.process_name == "browser.exe"


def test_rate_limit_bounds_burst():
    pipe=PacketPipeline(max_events_per_second=2)
    a=PacketObservation('10.0.0.2','1.1.1.1','TCP',60,5000,443)
    assert pipe.observe(a) is not None
    assert pipe.observe(a) is not None
    assert pipe.observe(a) is None
    assert pipe.rejected==1


def test_traffic_aggregator_bounds_unique_flow_history_and_keeps_recent_flows():
    aggregator = TrafficAggregator(max_events_per_window=10, max_flows=2)
    for index in range(4):
        packet = PacketObservation(
            f'10.0.0.{index + 1}', '203.0.113.20', 'TCP', 60,
            5000 + index, 443, 'local->remote', 'loopback',
        )
        assert aggregator.accept(packet)
    snapshot = aggregator.snapshot()
    assert len(snapshot) == 2
    assert all('5002' in flow or '5003' in flow for flow in snapshot)

def test_simulation_packet_reaches_detection_and_incident():
    core=SecurityCore()
    sensor=NetworkSensor(core,host_id='simulation-host',simulation=True)
    sensor.start()
    assert sensor.status()['mode']=='simulation'
    assert sensor.status()['accepted']==1
    assert core.events[-1].event_type=='network.packet'
    assert core.alerts
    assert core.incidents
    assert core.incidents[-1].threat_family_id
    assert 'T1059' in core.incidents[-1].mitre_techniques
    sensor.stop()


def test_api_capture_uses_the_stable_host_identity(monkeypatch):
    import asyncio
    from importlib import import_module
    from bk_security.auth.security import Principal
    from bk_security.sensors.host_identity import HostIdentitySensor

    api = import_module("bk_security.api.app")
    previous_sensor = api.network_sensor
    expected_host = "stable-capture-host"
    monkeypatch.setattr(api, "network_sensor", None)
    monkeypatch.setattr(api, "_host_identity", HostIdentitySensor(expected_host))
    monkeypatch.setenv("BK_SECURITY_CAPTURE_MODE", "simulation")
    try:
        response = asyncio.run(api.capture_start(Principal("tester", "admin")))
        assert response["status"] == "started"
        assert api.core.events[-1].host_id == expected_host
        asyncio.run(api.capture_stop(Principal("tester", "admin")))
    finally:
        if api.network_sensor:
            api.network_sensor.stop()
        monkeypatch.setattr(api, "network_sensor", previous_sensor)


def test_api_capture_accepts_explicit_simulation_scenario(monkeypatch):
    import asyncio
    from importlib import import_module
    from bk_security.auth.security import Principal

    api = import_module("bk_security.api.app")
    previous_sensor = api.network_sensor
    monkeypatch.setattr(api, "network_sensor", None)
    monkeypatch.setattr(api, "core", SecurityCore())
    try:
        response = asyncio.run(api.capture_start(
            Principal("tester", "admin"),
            api.CaptureStart(mode="simulation", scenario="MULTI_SIGNAL_ATTACK"),
        ))
        assert response["sensor"]["scenario"] == "MULTI_SIGNAL_ATTACK"
        assert len(api.core.incidents) == 1
        assert {event.event_type for event in api.core.events} >= {"network.dns", "endpoint.process", "network.packet"}
        asyncio.run(api.capture_stop(Principal("tester", "admin")))
    finally:
        if api.network_sensor:
            api.network_sensor.stop()
        api.core.store.close()
        monkeypatch.setattr(api, "network_sensor", previous_sensor)

def test_live_capture_packet_timestamp_propagates_to_security_event():
    scapy = pytest.importorskip("scapy.all")
    from bk_security.capture.live import LivePacketCapture

    captured_at = 1_791_234_567.25
    packet = (
        scapy.IP(src="10.0.0.2", dst="203.0.113.9")
        / scapy.UDP(sport=53000, dport=53)
        / scapy.Raw(load=b"timestamp-test")
    )
    packet.time = captured_at
    capture = LivePacketCapture(lambda _: None, local_ips={"10.0.0.2"})
    observation = capture._parse(packet)
    assert observation.timestamp == pytest.approx(captured_at)

    events = []
    event = PacketPipeline(callback=events.append).observe(observation)
    assert event.timestamp == datetime.fromtimestamp(captured_at, timezone.utc).isoformat()
    assert events[0].timestamp == event.timestamp


def test_capture_capabilities_include_runtime_prerequisites(monkeypatch):
    import asyncio
    from importlib import import_module
    from bk_security.auth.security import Principal

    api = import_module("bk_security.api.app")
    runtime = {
        "is_windows": True,
        "elevated": False,
        "npcap_present": True,
        "scapy_available": True,
        "capture_interfaces": [r"\Device\NPF_Loopback"],
        "capture_devices": [{
            "name": r"\Device\NPF_Loopback",
            "display_name": "Loopback Pseudo-Interface 1",
            "description": "Software Loopback Interface 1",
            "ipv4": "127.0.0.1",
            "status": "up",
            "is_loopback": True,
            "is_wireless": False,
        }, {
            "name": r"\Device\NPF_{wifi-guid}",
            "display_name": "Wi-Fi",
            "description": "Wireless adapter",
            "ipv4": "192.0.2.10",
            "status": "up",
            "is_loopback": False,
            "is_wireless": True,
        }],
        "loopback_interface": r"\Device\NPF_Loopback",
        "loopback_available": True,
        "live_capture_available": False,
        "reasons": ["privilèges administrateur requis pour la capture live"],
    }
    monkeypatch.setattr(api, "inspect_capture_runtime", lambda: runtime)
    monkeypatch.setattr(api.LivePacketCapture, "available", staticmethod(lambda: False))
    monkeypatch.setattr(api, "discover_interfaces", lambda: [])
    monkeypatch.setattr(api, "network_sensor", None)

    result = asyncio.run(api.capture_capabilities(Principal("viewer", "viewer")))

    assert result["runtime"] == runtime
    assert result["runtime"]["loopback_interface"] == r"\Device\NPF_Loopback"
    assert next(device for device in result["runtime"]["capture_devices"] if device["is_wireless"])["display_name"] == "Wi-Fi"
    assert result["live_capture_available"] is False
    assert result["status"]["running"] is False


def test_capture_starts_stopped_and_requires_an_explicit_operator_mode(monkeypatch):
    import asyncio
    from importlib import import_module
    from fastapi import HTTPException
    from bk_security.auth.security import Principal

    api = import_module("bk_security.api.app")
    monkeypatch.setattr(api, "network_sensor", None)
    monkeypatch.setenv("BK_SECURITY_CAPTURE_MODE", "stopped")
    status = asyncio.run(api.capture_capabilities(Principal("viewer", "viewer")))["status"]
    assert status["running"] is False
    assert status["mode"] == "stopped"
    with pytest.raises(HTTPException) as stopped:
        asyncio.run(api.capture_start(Principal("admin", "admin")))
    assert stopped.value.status_code == 409
    with pytest.raises(HTTPException) as missing_interface:
        asyncio.run(api.capture_start(
            Principal("admin", "admin"), api.CaptureStart(mode="live")
        ))
    assert missing_interface.value.status_code == 422


def test_production_api_rejects_simulation_and_hides_simulation_scenarios(monkeypatch):
    import asyncio
    from importlib import import_module
    from fastapi import HTTPException
    from bk_security.auth.security import Principal

    api = import_module("bk_security.api.app")
    monkeypatch.setenv("BK_SECURITY_ENV", "production")
    monkeypatch.setenv("BK_SECURITY_CAPTURE_MODE", "simulation")
    monkeypatch.setattr(api, "network_sensor", None)
    monkeypatch.setattr(api, "inspect_capture_runtime", lambda: {"reasons": ["test"]})
    monkeypatch.setattr(api.LivePacketCapture, "available", staticmethod(lambda: False))
    monkeypatch.setattr(api, "discover_interfaces", lambda: [])

    capabilities = asyncio.run(api.capture_capabilities(Principal("viewer", "viewer")))
    assert capabilities["status"]["mode"] == "stopped"
    assert capabilities["simulation_scenarios"] == []
    with pytest.raises(HTTPException) as denied:
        asyncio.run(api.capture_start(
            Principal("admin", "admin"), api.CaptureStart(mode="simulation")
        ))
    assert denied.value.status_code == 409


def test_api_passes_the_operator_selected_wifi_capture_interface(monkeypatch):
    import asyncio
    from importlib import import_module
    from bk_security.auth.security import Principal

    api = import_module("bk_security.api.app")
    previous_sensor = api.network_sensor
    selected_interface = r"\Device\NPF_{wifi-guid}"
    created = {}

    class FakeNetworkSensor:
        def __init__(self, core, **kwargs):
            created.update(kwargs)
            self.running = False
            self.kwargs = kwargs

        def start(self):
            self.running = True

        def status(self):
            return {"running": self.running, "mode": "live", "interface": self.kwargs["interface"]}

        def stop(self):
            self.running = False

    monkeypatch.setattr(api, "network_sensor", None)
    monkeypatch.setattr(api, "NetworkSensor", FakeNetworkSensor)
    monkeypatch.setenv("BK_SECURITY_MAX_EVENTS_PER_SECOND", "500")
    try:
        result = asyncio.run(api.capture_start(
            Principal("analyst", "analyst"),
            api.CaptureStart(mode="live", interface=selected_interface),
        ))
        assert result["status"] == "started"
        assert result["sensor"]["interface"] == selected_interface
        assert created["interface"] == selected_interface
        assert created["simulation"] is False
        asyncio.run(api.capture_stop(Principal("analyst", "analyst")))
    finally:
        monkeypatch.setattr(api, "network_sensor", previous_sensor)
