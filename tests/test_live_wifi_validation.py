import pytest

from scripts.validate_live_wifi_capture import build_bpf_filter, select_wifi_device


def wifi_device(**overrides):
    device = {
        "name": r"\Device\NPF_{wifi-guid}",
        "display_name": "Wi-Fi",
        "description": "Intel(R) Dual Band Wireless-AC 8260",
        "ipv4": "192.168.1.121",
        "status": "up",
        "is_loopback": False,
        "is_wireless": True,
    }
    device.update(overrides)
    return device


def test_wifi_validation_selects_only_the_active_wifi_endpoint():
    selected = select_wifi_device([
        {**wifi_device(), "description": "Wi-Fi adapter"},
        wifi_device(display_name="Ethernet", is_wireless=False),
        wifi_device(display_name="Wi-Fi 2"),
        wifi_device(status="down"),
    ])

    assert selected["name"] == r"\Device\NPF_{wifi-guid}"
    assert selected["ipv4"] == "192.168.1.121"


@pytest.mark.parametrize("devices", [
    [],
    [wifi_device(status="down")],
    [wifi_device(ipv4=None)],
    [wifi_device(name="")],
    [wifi_device(), wifi_device(name=r"\Device\NPF_{other}")],
])
def test_wifi_validation_fails_closed_when_selection_is_not_unique_and_ready(devices):
    with pytest.raises(RuntimeError):
        select_wifi_device(devices)


def test_bpf_filter_is_bound_to_the_selected_ipv4_address():
    assert build_bpf_filter("192.168.1.121") == "ip and host 192.168.1.121"


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "2001:db8::1"])
def test_bpf_filter_rejects_loopback_or_non_unicast_ipv4(address):
    with pytest.raises(ValueError):
        build_bpf_filter(address)
