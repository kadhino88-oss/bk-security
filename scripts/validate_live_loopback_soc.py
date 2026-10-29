from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bk_security.ai.contracts import InvestigationRequest
from bk_security.capture.live import LivePacketCapture
from bk_security.capture.pipeline import PacketPipeline
from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.policy.engine import Action
from bk_security.platform_windows import find_npcap, is_elevated
from scapy.all import get_if_list

LOOPBACK_INTERFACE = r"\Device\NPF_Loopback"
BPF_FILTER = "udp and dst port 4444 and host 127.0.0.1"
PROBE_PORT = 4444


def main() -> int:
    if os.getenv("BK_SECURITY_WINDOWS_RESPONSE", "0") != "0":
        print("Refusing to run: BK_SECURITY_WINDOWS_RESPONSE must be 0.", file=sys.stderr)
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

    with tempfile.TemporaryDirectory(prefix="bk-security-phase6-") as temporary:
        store = SecurityStore(str(Path(temporary) / "phase6.sqlite3"))
        core = SecurityCore(store)
        if core.response.adapters:
            core.store.close()
            raise RuntimeError("Response adapters must remain disabled for this validation.")

        pipeline = PacketPipeline(
            host_id="phase6-local-loopback",
            callback=core.ingest,
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
                probe.sendto(b"BK Security Phase 6 local detection probe", ("127.0.0.1", PROBE_PORT))

            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not any(
                event.event_type == "network.packet"
                and event.network.get("dst_port") == PROBE_PORT
                for event in core.events
            ):
                time.sleep(0.05)
        finally:
            capture.stop()

        try:
            packet_events = [
                event for event in core.events
                if event.event_type == "network.packet"
                and event.network.get("src_ip") == "127.0.0.1"
                and event.network.get("dst_ip") == "127.0.0.1"
                and event.network.get("dst_port") == PROBE_PORT
            ]
            if not packet_events:
                raise RuntimeError("The loopback packet did not reach SecurityCore.")
            packet_event = packet_events[0]

            alerts = [
                alert for alert in core.alerts
                if packet_event.event_id in alert.source_event_ids
            ]
            if not alerts:
                raise RuntimeError("The live loopback event did not create a detection alert.")
            alert = alerts[0]

            incident = next(
                (item for item in core.incidents if alert.alert_id in item.alert_ids),
                None,
            )
            if incident is None or not incident.threat_family_id:
                raise RuntimeError("The live detection did not reach an incident with Threat Family.")

            investigation = core.ai.investigate(InvestigationRequest(
                alert,
                [packet_event],
                {"incident_id": incident.incident_id},
            ))
            if (
                not investigation.valid
                or investigation.source_alert_id != alert.alert_id
                or packet_event.event_id not in investigation.source_event_ids
                or incident.incident_id not in investigation.source_incident_ids
                or not investigation.evidence
            ):
                raise RuntimeError("AI SOC evidence/provenance validation failed.")

            plan = core.plan_response(
                Action.BLOCK,
                "203.0.113.77",
                "Phase 6 localhost packet dry-run",
                actor="phase6-analyst",
                actor_role="analyst",
                dry_run=True,
                alert_id=alert.alert_id,
                incident_id=incident.incident_id,
                evidence_ids=[alert.alert_id],
                ai_recommendation=Action.BLOCK,
            )
            if not plan.get("dry_run"):
                raise RuntimeError("Response plan was not created in dry-run mode.")
            if plan.get("action") == Action.BLOCK.value and not plan.get("requires_approval"):
                raise RuntimeError("A protected BLOCK plan did not require approval.")
            if core.response.executions:
                raise RuntimeError("The dry-run unexpectedly created a response execution.")

            audit_actions = {entry.get("action") for entry in core.store.list_audit(1000)}
            if not {"response_policy_decision", "response_plan"}.issubset(audit_actions):
                raise RuntimeError("Policy/plan audit entries were not persisted to the temporary database.")

            print(json.dumps({
                "status": "passed",
                "interface": LOOPBACK_INTERFACE,
                "bpf_filter": BPF_FILTER,
                "probe_destination": "127.0.0.1:4444/udp",
                "capture_events": len(packet_events),
                "detection_alert": {
                    "type": alert.alert_type,
                    "severity": alert.severity,
                    "source_event_linked": packet_event.event_id in alert.source_event_ids,
                },
                "incident": {
                    "created": True,
                    "threat_family_id": incident.threat_family_id,
                },
                "ai_investigation": {
                    "valid": investigation.valid,
                    "evidence_count": len(investigation.evidence),
                    "alert_event_incident_provenance": True,
                },
                "response_plan": {
                    "action": plan["action"],
                    "dry_run": plan["dry_run"],
                    "policy_decision": plan["policy_decision"],
                    "execution_started": False,
                    "response_adapters_enabled": False,
                },
                "database": "temporary SQLite, removed when the script exits",
                "raw_packet_storage": False,
                "network_scope": "localhost loopback only",
            }, indent=2))
            return 0
        finally:
            core.store.close()


if __name__ == "__main__":
    raise SystemExit(main())

