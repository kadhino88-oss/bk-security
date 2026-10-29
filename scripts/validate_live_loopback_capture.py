"""Bounded, non-persistent Npcap loopback capture check for Phase 6.

Run only from an elevated PowerShell session after reviewing the Phase 6 report.
The probe is sent to 127.0.0.1:9, captured only on Npcap loopback, and kept in
memory. It does not start the API, write to the database, or enable response
adapters.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bk_security.capture.live import LivePacketCapture
from bk_security.capture.pipeline import PacketPipeline
from bk_security.platform_windows import find_npcap, is_elevated
from scapy.all import get_if_list

LOOPBACK_INTERFACE = r"\Device\NPF_Loopback"
BPF_FILTER = "udp and host 127.0.0.1"
PROBE_PORT = 9


def main() -> int:
    if os.getenv("BK_SECURITY_WINDOWS_RESPONSE", "0") != "0":
        print("Refusing to run: set BK_SECURITY_WINDOWS_RESPONSE=0 first.", file=sys.stderr)
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
    if LOOPBACK_INTERFACE not in {str(name) for name in get_if_list()}:
        print("Npcap loopback interface was not found; no capture was started.", file=sys.stderr)
        return 2
    if not LivePacketCapture.available():
        print("Scapy/Npcap capture is unavailable; no capture was started.", file=sys.stderr)
        return 2

    events = []
    pipeline = PacketPipeline(
        host_id="phase6-local-loopback",
        callback=events.append,
        max_events_per_second=20,
    )
    capture = LivePacketCapture(
        pipeline.observe,
        interface=LOOPBACK_INTERFACE,
        local_ips={"127.0.0.1"},
        bpf_filter=BPF_FILTER,
    )
    try:
        capture.start()
        time.sleep(0.25)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.sendto(b"BK Security Phase 6 loopback probe", ("127.0.0.1", PROBE_PORT))
        deadline = time.monotonic() + 3.0
        while not events and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        capture.stop()

    matches = [
        event for event in events
        if event.event_type == "network.packet"
        and event.network.get("src_ip") == "127.0.0.1"
        and event.network.get("dst_ip") == "127.0.0.1"
        and event.network.get("dst_port") == PROBE_PORT
    ]
    if not matches:
        print(json.dumps({
            "status": "failed",
            "reason": "No matching localhost UDP observation reached the packet pipeline.",
            "captured_observations": len(events),
            "interface": LOOPBACK_INTERFACE,
            "database_persistence": False,
            "response_adapters_enabled": False,
        }, indent=2))
        return 1

    print(json.dumps({
        "status": "passed",
        "interface": LOOPBACK_INTERFACE,
        "bpf_filter": BPF_FILTER,
        "probe_destination": "127.0.0.1:9/udp",
        "pipeline_events": len(events),
        "matched_loopback_events": len(matches),
        "event_timestamp": matches[0].timestamp,
        "raw_packet_storage": False,
        "database_persistence": False,
        "response_adapters_enabled": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
