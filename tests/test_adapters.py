from types import SimpleNamespace
from bk_security.events.adapters import packet_to_event


def test_bk_packet_normalization_accepts_object_observations():
    packet = SimpleNamespace(
        src_ip="10.0.0.10", dst_ip="1.2.3.4", src_port=50000,
        dst_port=443, protocol="TCP", size=1200, direction="out",
        pid=1234, process_name="chrome.exe"
    )
    event = packet_to_event(packet)
    assert event.source == "bk_network_sensor"
    assert event.data["dst_ip"] == "1.2.3.4"
    assert event.data["process_name"] == "chrome.exe"


def test_bk_packet_normalization_accepts_mapping_and_normalizes_ports():
    event = packet_to_event({"src_ip": "10.0.0.2", "dst_ip": "203.0.113.4", "dst_port": "4444", "size": "80"})
    assert event.source == "bk_network_sensor"
    assert event.data["dst_port"] == 4444
    assert event.data["size"] == 80


def test_process_normalizer_accepts_mapping():
    from bk_security.events.adapters import process_to_event
    event = process_to_event({"pid": "12", "name": "agent.exe", "exe": "C:/agent.exe"})
    assert event.process["pid"] == 12
    assert event.process["name"] == "agent.exe"
