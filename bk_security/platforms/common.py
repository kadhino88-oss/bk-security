"""OS-independent interface discovery shared by every platform provider."""
from __future__ import annotations

import socket
from dataclasses import dataclass


@dataclass
class InterfaceInfo:
    name: str
    description: str = ""
    ipv4: str | None = None
    status: str = "unknown"


def discover_interfaces() -> list[InterfaceInfo]:
    try:
        import psutil
        out = []
        stats_by_name = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            ipv4 = None
            for a in addrs:
                if getattr(a, "family", None) == socket.AF_INET:
                    ipv4 = a.address
                    break
            stats = stats_by_name.get(name)
            out.append(InterfaceInfo(name=name, ipv4=ipv4, status="up" if stats and stats.isup else "down"))
        return out
    except Exception:
        return []


def discover_capture_interfaces() -> list[str]:
    """Return packet-capture device names from Scapy, when available."""
    try:
        from scapy.all import get_if_list
        return [str(name) for name in get_if_list()]
    except Exception:
        return []


_WIRELESS_TERMS = ("wi-fi", "wifi", "wireless", "wlan", "802.11")


def discover_capture_devices(loopback_names: set[str]) -> list[dict]:
    """Return Scapy devices with friendly names and local interface metadata."""
    try:
        from scapy.all import conf
        devices = list(conf.ifaces.values())
    except Exception:
        return []

    addresses, stats = {}, {}
    try:
        import psutil
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        pass

    loopbacks = {name.casefold() for name in loopback_names}
    result = []
    for device in devices:
        network_name = str(getattr(device, "network_name", "") or "")
        display_name = str(getattr(device, "name", "") or network_name)
        description = str(getattr(device, "description", "") or "")
        if not network_name:
            continue

        ipv4 = None
        for address in addresses.get(display_name, []):
            if getattr(address, "family", None) == socket.AF_INET:
                ipv4 = address.address
                break
        if ipv4 is None:
            ipv4 = str(getattr(device, "ip", "") or "") or None
        interface_stats = stats.get(display_name)
        label = f"{display_name} {description}".casefold()
        result.append({
            "name": network_name,
            "display_name": display_name,
            "description": description,
            "ipv4": ipv4,
            "status": "up" if interface_stats and interface_stats.isup else "down",
            "is_loopback": network_name.casefold() in loopbacks,
            "is_wireless": any(term in label for term in _WIRELESS_TERMS) or display_name.casefold().startswith("wl"),
        })

    return sorted(result, key=lambda item: (item["status"] != "up", not item["is_wireless"], item["display_name"].casefold()))
