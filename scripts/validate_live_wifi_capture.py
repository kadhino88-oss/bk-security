"""Run a short, passive Npcap check on the active Wi-Fi endpoint."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bk_security.capture.live import LivePacketCapture
from bk_security.capture.pipeline import PacketPipeline
from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.platform_windows import discover_capture_devices, find_npcap, is_elevated

CAPTURE_SECONDS = 5.0
WIFI_DISPLAY_NAME = "Wi-Fi"


def select_wifi_device(devices: list[dict]) -> dict:
    """Select exactly one active Wi-Fi Npcap device with a usable IPv4 address."""
    candidates = [
        device for device in devices
        if str(device.get("display_name", "")).casefold() == WIFI_DISPLAY_NAME.casefold()
        and device.get("name")
        and device.get("is_wireless") is True
        and str(device.get("status", "")).casefold() == "up"
        and device.get("ipv4")
    ]
    if len(candidates) != 1:
        raise RuntimeError(
            f"Expected exactly one active Npcap device named {WIFI_DISPLAY_NAME}; found {len(candidates)}."
        )

    selected = dict(candidates[0])
    try:
        address = ipaddress.ip_address(str(selected["ipv4"]))
    except ValueError as exc:
        raise RuntimeError("The active Wi-Fi device has no valid IPv4 address.") from exc
    if address.version != 4 or address.is_loopback or address.is_unspecified or address.is_multicast:
        raise RuntimeError("The active Wi-Fi address is not a usable unicast IPv4 address.")
    selected["ipv4"] = str(address)
    return selected


def build_bpf_filter(ipv4: str) -> str:
    """Build a filter limited to IPv4 packets involving the Wi-Fi endpoint."""
    address = ipaddress.ip_address(ipv4)
    if address.version != 4 or address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("A usable unicast IPv4 address is required.")
    return f"ip and host {address}"


def main() -> int:
    if os.getenv("BK_SECURITY_WINDOWS_RESPONSE") != "0":
        print("Refusing to run: BK_SECURITY_WINDOWS_RESPONSE must be explicitly set to 0.", file=sys.stderr)
        return 2
    if os.name != "nt":
        print("Refusing to run: this check is Windows-only.", file=sys.stderr)
        return 2
    if not find_npcap():
        print("Npcap was not detected; no capture was started.", file=sys.stderr)
        return 2
    if not is_elevated():
        print("Live Npcap capture needs an elevated PowerShell session; no capture was started.", file=sys.stderr)
        return 2

    try:
        device = select_wifi_device(discover_capture_devices())
        bpf_filter = build_bpf_filter(device["ipv4"])
    except RuntimeError as exc:
        print(f"No capture was started: {exc}", file=sys.stderr)
        return 2

    if not LivePacketCapture.available():
        print("Scapy/Npcap capture is unavailable; no capture was started.", file=sys.stderr)
        return 2

    result: dict = {
        "status": "failed",
        "interface": device["name"],
        "display_name": device["display_name"],
        "interface_ipv4": device["ipv4"],
        "bpf_filter": bpf_filter,
        "capture_window_seconds": CAPTURE_SECONDS,
        "capture_started": False,
        "network_packet_events": 0,
        "raw_packet_storage": False,
        "response_adapters_enabled": False,
        "database": "temporary SQLite",
    }

    with tempfile.TemporaryDirectory(prefix="bk-security-wifi-validation-") as temporary:
        database_path = Path(temporary) / "wifi-validation.sqlite3"
        store = SecurityStore(str(database_path))
        core = SecurityCore(store)
        capture: LivePacketCapture | None = None
        try:
            if core.response.adapters:
                raise RuntimeError("Response adapters must remain disabled for this validation.")

            pipeline = PacketPipeline(
                host_id="phase6-local-wifi",
                callback=core.ingest,
                max_events_per_second=100,
            )
            capture = LivePacketCapture(
                pipeline.observe,
                interface=device["name"],
                local_ips={device["ipv4"]},
                bpf_filter=bpf_filter,
            )
            capture.start()
            result["capture_started"] = True
            deadline = time.monotonic() + CAPTURE_SECONDS
            while time.monotonic() < deadline:
                time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
            capture.stop()

            matching_events = [
                event for event in core.events
                if event.event_type == "network.packet"
                and event.source == "bk_network_capture"
                and device["ipv4"] in {event.network.get("src_ip"), event.network.get("dst_ip")}
            ]
            result["network_packet_events"] = len(matching_events)
            result["status"] = "passed" if matching_events else "inconclusive"
            if not matching_events:
                result["reason"] = "No matching IPv4 packet was observed during the passive capture window."
        except Exception as exc:
            result["reason"] = f"{type(exc).__name__}: {exc}"
        finally:
            if capture is not None and capture.running:
                try:
                    capture.stop()
                except Exception as exc:
                    result["status"] = "failed"
                    result["stop_error"] = f"{type(exc).__name__}: {exc}"
            store.close()

    result["temporary_database_removed"] = not database_path.exists()
    result["network_scope"] = "IPv4 packets involving the selected Wi-Fi endpoint only"
    result["probe_traffic_generated"] = False
    result["raw_packet_storage"] = False
    result["response_adapters_enabled"] = False
    print(json.dumps(result, indent=2))
    return {"passed": 0, "inconclusive": 3, "failed": 1}.get(result["status"], 1)


if __name__ == "__main__":
    raise SystemExit(main())
