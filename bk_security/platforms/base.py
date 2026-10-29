"""Platform provider contract: everything OS-specific the product needs, in one place.

The detection, correlation, incident and SOC layers never import an OS module;
they reach the host through a provider. A provider reports capture
prerequisites and builds response adapters. It never executes anything on its
own, and response adapters stay disabled unless explicitly enabled.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..policy.engine import Action
from .common import discover_capture_devices, discover_capture_interfaces


class PlatformProvider(ABC):
    name: str = "unknown"
    capture_backend: str = "none"

    @abstractmethod
    def is_elevated(self) -> bool: ...

    @abstractmethod
    def loopback_interface(self) -> str: ...

    @abstractmethod
    def capture_prerequisites(self) -> list[str]:
        """Reasons live capture is not ready on this OS (empty when ready). Excludes Scapy itself."""

    @abstractmethod
    def response_adapters(self) -> dict[Action, Any]:
        """Adapters implementing execute/verify/rollback/verify_rollback. Caller decides whether to enable them."""

    def response_validated(self) -> bool:
        """True only once the adapters passed a recorded lab validation on a real host of this OS."""
        return False

    def capture_runtime(self) -> dict:
        try:
            import scapy.all  # noqa: F401
            scapy_available = True
        except Exception:
            scapy_available = False
        capture_interfaces = discover_capture_interfaces() if scapy_available else []
        capture_devices = discover_capture_devices({self.loopback_interface()}) if scapy_available else []
        loopback = self.loopback_interface()
        loopback_available = loopback.casefold() in {name.casefold() for name in capture_interfaces}
        reasons = list(self.capture_prerequisites())
        if not scapy_available:
            reasons.append("Scapy non disponible")
        elif not loopback_available:
            reasons.append("interface loopback non détectée")
        return {
            "platform": self.name,
            "is_windows": self.name == "windows",
            "elevated": self.is_elevated(),
            "npcap_present": False,
            "npcap_path": None,
            "capture_backend": self.capture_backend,
            "scapy_available": scapy_available,
            "capture_interfaces": capture_interfaces,
            "capture_devices": capture_devices,
            "loopback_interface": loopback if loopback_available else None,
            "loopback_available": loopback_available,
            "live_capture_available": not reasons,
            "reasons": reasons,
        }
