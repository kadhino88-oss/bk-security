import socket
from types import SimpleNamespace

import pytest

from bk_security.sensors.lan import LANDiscoverySensor


class FakeCore:
    def __init__(self):
        self.events = []

    def ingest(self, event):
        self.events.append(event)
        return []


def _mock_interface(monkeypatch):
    monkeypatch.setattr(
        "bk_security.sensors.lan.psutil.net_if_addrs",
        lambda: {
            "Wi-Fi": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.168.1.20",
                    netmask="255.255.255.0",
                )
            ]
        },
    )
    monkeypatch.setattr(
        "bk_security.sensors.lan.psutil.net_if_stats",
        lambda: {"Wi-Fi": SimpleNamespace(isup=True)},
    )


def test_lan_scan_is_explicit_bounded_and_emits_devices(monkeypatch):
    _mock_interface(monkeypatch)
    core = FakeCore()
    scans = []

    def scanner(subnet, interface):
        scans.append((subnet, interface))
        return [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01"},
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01"},
            {"ip": "192.168.2.2", "mac": "aa:bb:cc:dd:ee:02"},
            {"ip": "invalid", "mac": "aa:bb:cc:dd:ee:03"},
            {"ip": "192.168.1.8", "mac": ""},
        ]

    sensor = LANDiscoverySensor(core, "host-a", scanner=scanner)
    assert scanner not in scans
    sensor.start()
    events = sensor.discover_once("Wi-Fi", "192.168.1.0/24")

    assert scans == [("192.168.1.0/24", "Wi-Fi")]
    assert len(events) == len(core.events) == 1
    assert events[0].event_type == "lan.device"
    assert events[0].data["ip"] == "192.168.1.1"
    assert events[0].data["mac"] == "aa:bb:cc:dd:ee:01"
    assert sensor.status()["last_count"] == 1


@pytest.mark.parametrize("subnet", ["192.168.0.0/16", "8.8.8.0/24", "127.0.0.0/8"])
def test_lan_scan_rejects_ranges_outside_safe_local_bounds(monkeypatch, subnet):
    _mock_interface(monkeypatch)
    sensor = LANDiscoverySensor(FakeCore(), "host-a", scanner=lambda *_: [])
    sensor.start()
    with pytest.raises(ValueError):
        sensor.discover_once("Wi-Fi", subnet)


def test_lan_scan_must_be_started_before_probe(monkeypatch):
    _mock_interface(monkeypatch)
    sensor = LANDiscoverySensor(FakeCore(), "host-a", scanner=lambda *_: [])
    with pytest.raises(RuntimeError, match="Start the LAN sensor"):
        sensor.discover_once("Wi-Fi", "192.168.1.0/24")
