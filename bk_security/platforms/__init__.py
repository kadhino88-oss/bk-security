"""OS abstraction layer. Import OS-specific behaviour only through `current_provider()`."""
from __future__ import annotations

import platform

from .base import PlatformProvider
from .common import InterfaceInfo, discover_interfaces
from .providers import LinuxProvider, MacOSProvider, UnsupportedProvider, WindowsProvider

__all__ = ["PlatformProvider", "InterfaceInfo", "discover_interfaces", "provider_for", "current_provider",
           "inspect_capture_runtime"]


def provider_for(system: str) -> PlatformProvider:
    """Map a platform.system() value to its provider."""
    key = str(system).casefold()
    if key == "windows":
        return WindowsProvider()
    if key == "linux":
        return LinuxProvider()
    if key == "darwin":
        return MacOSProvider()
    return UnsupportedProvider(key)


def current_provider() -> PlatformProvider:
    return provider_for(platform.system())


def inspect_capture_runtime() -> dict:
    return current_provider().capture_runtime()
