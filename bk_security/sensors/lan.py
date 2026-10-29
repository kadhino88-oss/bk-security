from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timezone
from typing import Callable

import psutil

from ..events.models import SecurityEvent


class LANDiscoverySensor:
    """Explicit, bounded ARP discovery on one selected local interface."""

    def __init__(
        self,
        core,
        host_id: str,
        scanner: Callable[[str, str], list[dict]] | None = None,
        max_hosts: int = 254,
    ) -> None:
        self.core = core
        self.host_id = host_id
        self.scanner = scanner
        self.max_hosts = max(1, min(254, int(max_hosts)))
        self.running = False
        self.last_scan: str | None = None
        self.last_count = 0
        self.interface: str | None = None

    def start(self) -> None:
        # Starting the sensor only enables explicit scans; it does not probe a LAN.
        self.running = True

    def stop(self) -> None:
        self.running = False

    def status(self) -> dict:
        return {
            "running": self.running,
            "interface": self.interface,
            "last_scan": self.last_scan,
            "last_count": self.last_count,
            "mode": "injected" if self.scanner else "arp",
        }

    def _selected_network(self, interface: str, subnet: str) -> ipaddress.IPv4Network:
        if not interface or interface not in psutil.net_if_addrs():
            raise ValueError("Select an existing network interface.")
        stats = psutil.net_if_stats().get(interface)
        if not stats or not stats.isup:
            raise ValueError("The selected network interface is down.")

        local_network = None
        for address in psutil.net_if_addrs()[interface]:
            if address.family != socket.AF_INET or not address.address or not address.netmask:
                continue
            try:
                local_network = ipaddress.ip_interface(f"{address.address}/{address.netmask}").network
            except ValueError:
                continue
            break
        if local_network is None:
            raise ValueError("The selected interface has no usable IPv4 subnet.")

        try:
            requested = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise ValueError("Provide a valid IPv4 subnet.") from exc
        if not isinstance(requested, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 ARP discovery is supported.")
        if requested.network_address.is_loopback or requested.network_address.is_multicast:
            raise ValueError("Loopback and multicast ranges cannot be scanned.")
        if not (requested.is_private or requested.is_link_local):
            raise ValueError("LAN discovery is limited to private or link-local ranges.")
        if not requested.subnet_of(local_network):
            raise ValueError("The requested subnet must be inside the selected interface subnet.")
        if requested.num_addresses > self.max_hosts + 2:
            raise ValueError(f"Subnet is too large; the limit is {self.max_hosts} usable hosts.")
        return requested

    def _arp_scan(self, subnet: str, interface: str) -> list[dict]:
        from ..capture.live import LivePacketCapture

        if not LivePacketCapture.available():
            raise RuntimeError("Live ARP discovery requires Scapy, Npcap, and administrator privileges.")
        try:
            from scapy.all import ARP, Ether, srp
        except ImportError as exc:
            raise RuntimeError("Scapy is unavailable for ARP discovery.") from exc

        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=interface,
            timeout=1,
            retry=0,
            inter=0.02,
            verbose=0,
        )
        return [{"ip": response.psrc, "mac": response.hwsrc} for _, response in answered]

    def discover_once(self, interface: str, subnet: str) -> list[SecurityEvent]:
        if not self.running:
            raise RuntimeError("Start the LAN sensor before requesting a scan.")
        requested = self._selected_network(interface, subnet)
        observations = self.scanner(str(requested), interface) if self.scanner else self._arp_scan(str(requested), interface)
        events: list[SecurityEvent] = []
        seen: set[tuple[str, str]] = set()
        for observation in observations:
            ip = str(observation.get("ip") or "").strip()
            mac = str(observation.get("mac") or "").strip().lower()
            try:
                parsed_ip = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if parsed_ip not in requested or parsed_ip == requested.network_address or parsed_ip == requested.broadcast_address:
                continue
            if not mac or (ip, mac) in seen:
                continue
            seen.add((ip, mac))
            event = SecurityEvent(
                event_type="lan.device",
                source="bk_lan_discovery",
                host_id=self.host_id,
                data={
                    "ip": ip,
                    "mac": mac,
                    "vendor": None,
                    "device_type": "unknown",
                    "hostname": None,
                    "online": True,
                    "interface": interface,
                    "subnet": str(requested),
                },
                network={"interface": interface},
                tags=["lan", "arp", "discovery"],
            )
            self.core.ingest(event)
            events.append(event)

        self.interface = interface
        self.last_scan = datetime.now(timezone.utc).isoformat()
        self.last_count = len(events)
        return events
