from __future__ import annotations

import ctypes.util
import os
import shutil
from collections.abc import Callable
from typing import Any

from ..policy.engine import Action
from .base import PlatformProvider
from .linux_adapters import NftBlockAdapter, NftIsolationAdapter
from .macos_adapters import PfBlockAdapter, PfIsolationAdapter
from .process_adapter import ProcessTerminateAdapter

CAP_NET_RAW_BIT = 13


def has_capability(status_text: str, bit: int) -> bool:
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            try:
                return bool(int(line.split(":", 1)[1].strip(), 16) >> bit & 1)
            except ValueError:
                return False
    return False


def _read_proc_status() -> str:
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


class WindowsProvider(PlatformProvider):
    name = "windows"
    capture_backend = "npcap"

    def is_elevated(self) -> bool:
        from .. import platform_windows
        return platform_windows.is_elevated()

    def loopback_interface(self) -> str:
        from .. import platform_windows
        return platform_windows.NPCAP_LOOPBACK_INTERFACE

    def capture_prerequisites(self) -> list[str]:
        from .. import platform_windows
        reasons = []
        if not platform_windows.find_npcap():
            reasons.append("Npcap non détecté")
        if not platform_windows.is_elevated():
            reasons.append("privilèges administrateur requis pour la capture live")
        return reasons

    def capture_runtime(self) -> dict:
        from .. import platform_windows
        return {**platform_windows.inspect_capture_runtime(), "platform": self.name,
                "capture_backend": self.capture_backend}

    def response_adapters(self) -> dict[Action, Any]:
        from ..policy.windows_adapters import build_windows_adapters
        return build_windows_adapters()


class LinuxProvider(PlatformProvider):
    name = "linux"
    capture_backend = "af_packet"

    def __init__(self, *, geteuid: Callable[[], int] | None = None,
                 read_status: Callable[[], str] = _read_proc_status,
                 find_bpf_compiler: Callable[[], bool] | None = None) -> None:
        self._geteuid = geteuid or (lambda: os.geteuid() if hasattr(os, "geteuid") else -1)
        self._read_status = read_status
        self._find_bpf_compiler = find_bpf_compiler or (
            lambda: bool(ctypes.util.find_library("pcap") or shutil.which("tcpdump")))

    def is_elevated(self) -> bool:
        return self._geteuid() == 0 or has_capability(self._read_status(), CAP_NET_RAW_BIT)

    def loopback_interface(self) -> str:
        return "lo"

    def capture_prerequisites(self) -> list[str]:
        reasons = []
        if not self.is_elevated():
            reasons.append("privilèges root ou capability CAP_NET_RAW requis pour la capture live")
        if not self._find_bpf_compiler():
            reasons.append("libpcap ou tcpdump requis pour les filtres BPF")
        return reasons

    def response_adapters(self) -> dict[Action, Any]:
        return {Action.BLOCK: NftBlockAdapter(), Action.ISOLATE: NftIsolationAdapter(),
                Action.TERMINATE_PROCESS: ProcessTerminateAdapter()}


class MacOSProvider(PlatformProvider):
    name = "macos"
    capture_backend = "bpf"

    def __init__(self, *, geteuid: Callable[[], int] | None = None,
                 bpf_readable: Callable[[], bool] | None = None) -> None:
        self._geteuid = geteuid or (lambda: os.geteuid() if hasattr(os, "geteuid") else -1)
        self._bpf_readable = bpf_readable or (
            lambda: any(os.access(f"/dev/bpf{index}", os.R_OK) for index in range(8)))

    def is_elevated(self) -> bool:
        return self._geteuid() == 0

    def loopback_interface(self) -> str:
        return "lo0"

    def capture_prerequisites(self) -> list[str]:
        if self.is_elevated() or self._bpf_readable():
            return []
        return ["accès aux périphériques /dev/bpf* requis (root ou groupe d'accès BPF)"]

    def response_adapters(self) -> dict[Action, Any]:
        return {Action.BLOCK: PfBlockAdapter(), Action.ISOLATE: PfIsolationAdapter(),
                Action.TERMINATE_PROCESS: ProcessTerminateAdapter()}


class UnsupportedProvider(PlatformProvider):
    capture_backend = "none"

    def __init__(self, system: str = "unknown") -> None:
        self.name = system.casefold() or "unknown"

    def is_elevated(self) -> bool:
        return False

    def loopback_interface(self) -> str:
        return "lo"

    def capture_prerequisites(self) -> list[str]:
        return [f"plateforme non prise en charge: {self.name}"]

    def response_adapters(self) -> dict[Action, Any]:
        return {}
