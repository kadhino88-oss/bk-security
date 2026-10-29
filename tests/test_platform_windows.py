from bk_security.platform_windows import inspect_environment, discover_interfaces
from types import SimpleNamespace
import bk_security.capture.live as live_capture
import bk_security.platform_windows as windows_platform

def test_environment_shape():
    r=inspect_environment()
    assert {"os","is_windows","elevated","npcap_present","npcap_path","interfaces","ready","reasons"} <= r.keys()
    assert isinstance(r["interfaces"], list)

def test_interface_discovery_safe():
    r=discover_interfaces(); assert isinstance(r,list)

def test_capture_device_diagnostics_return_selectable_device_metadata():
    import pytest
    pytest.importorskip("scapy.all")
    devices = windows_platform.discover_capture_devices()
    assert isinstance(devices, list)
    assert all({
        "name", "display_name", "description", "ipv4", "status", "is_loopback", "is_wireless",
    } <= device.keys() for device in devices)

def test_live_capture_requires_npcap_and_elevation_on_windows(monkeypatch):
    monkeypatch.setattr(live_capture, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(windows_platform, 'find_npcap', lambda: None)
    monkeypatch.setattr(windows_platform, 'is_elevated', lambda: False)
    assert live_capture.LivePacketCapture.available() is False
