"""Non-destructive Windows/Npcap environment diagnostics and interface discovery."""
from __future__ import annotations
import os, platform, shutil, subprocess
from dataclasses import dataclass, asdict

from .platforms.common import (  # noqa: F401 - re-exported for existing callers
    InterfaceInfo, discover_interfaces, discover_capture_interfaces,
    discover_capture_devices as _discover_capture_devices,
)

NPCAP_LOOPBACK_INTERFACE = r"\Device\NPF_Loopback"

@dataclass
class CaptureEnvironment:
    os: str
    is_windows: bool
    elevated: bool
    npcap_present: bool
    npcap_path: str | None
    interfaces: list[InterfaceInfo]
    ready: bool
    reasons: list[str]

def is_elevated() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def find_npcap() -> str | None:
    if os.name != "nt":
        return None
    candidates = [
        os.getenv("NPCAP_DIR"),
        r"C:\Program Files\Npcap",
        r"C:\Windows\System32\Npcap",
    ]
    for path in candidates:
        if path and os.path.isdir(path):
            return os.path.normpath(path)
    return None

def inspect_environment() -> dict:
    npcap=find_npcap()
    interfaces=discover_interfaces()
    reasons=[]
    is_win=os.name == "nt"
    elevated=is_elevated()
    if not is_win: reasons.append("Windows non détecté")
    if is_win and not npcap: reasons.append("Npcap non détecté")
    if is_win and not elevated: reasons.append("privilèges administrateur requis pour la capture")
    if not interfaces: reasons.append("aucune interface réseau détectée")
    return asdict(CaptureEnvironment(platform.system(), is_win, elevated, bool(npcap), npcap, interfaces, not reasons, reasons))

def discover_capture_devices() -> list[dict]:
    """Return Scapy devices with friendly names and local interface metadata."""
    return _discover_capture_devices({NPCAP_LOOPBACK_INTERFACE})

def inspect_capture_runtime() -> dict:
    """Report the prerequisites that matter to the packet capture path."""
    windows = os.name == "nt"
    elevated = is_elevated()
    npcap_path = find_npcap()
    try:
        import scapy.all  # noqa: F401
        scapy_available = True
    except Exception:
        scapy_available = False
    capture_interfaces = discover_capture_interfaces() if scapy_available else []
    capture_devices = discover_capture_devices() if scapy_available else []
    loopback_available = NPCAP_LOOPBACK_INTERFACE in capture_interfaces if windows else False

    reasons = []
    if windows and not npcap_path:
        reasons.append("Npcap non détecté")
    if windows and not elevated:
        reasons.append("privilèges administrateur requis pour la capture live")
    if not scapy_available:
        reasons.append("Scapy non disponible")
    if windows and scapy_available and not loopback_available:
        reasons.append("interface Npcap loopback non détectée")

    return {
        "is_windows": windows,
        "elevated": elevated,
        "npcap_present": bool(npcap_path),
        "npcap_path": npcap_path,
        "scapy_available": scapy_available,
        "capture_interfaces": capture_interfaces,
        "capture_devices": capture_devices,
        "loopback_interface": NPCAP_LOOPBACK_INTERFACE if loopback_available else None,
        "loopback_available": loopback_available,
        "live_capture_available": not reasons,
        "reasons": reasons,
    }
