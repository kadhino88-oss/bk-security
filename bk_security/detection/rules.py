from __future__ import annotations

import math
from typing import Any

from ..events.models import SecurityAlert, SecurityEvent


def _dns_anomaly(domain: str) -> tuple[int, str] | None:
    labels = [label for label in domain.strip(".").lower().split(".") if label]
    candidates = labels[:-1] if len(labels) > 1 else labels
    if not candidates:
        return None
    longest = max(candidates, key=len)
    if len(longest) >= 32:
        return 70, "oversized_dns_label"
    if len(longest) < 18:
        return None
    frequencies = {character: longest.count(character) for character in set(longest)}
    entropy = -sum((count / len(longest)) * math.log2(count / len(longest)) for count in frequencies.values())
    digit_ratio = sum(character.isdigit() for character in longest) / len(longest)
    if entropy >= 3.7 and digit_ratio >= 0.2:
        return 65, "high_entropy_dns_label"
    if len(longest) >= 24 and entropy >= 3.8:
        return 60, "high_entropy_dns_label"
    return None
from .risk import RiskEngine, RiskFactors

SUSPICIOUS_PROCESSES = {
    "cmd.exe": 35, "powershell.exe": 40, "wscript.exe": 45,
    "cscript.exe": 45, "mshta.exe": 55, "regsvr32.exe": 55,
    "certutil.exe": 50, "bitsadmin.exe": 50, "rundll32.exe": 45,
    "msiexec.exe": 30, "schtasks.exe": 35, "at.exe": 35,
}

SUSPICIOUS_PORTS = {
    4444: (55, "T1059"), 4445: (55, "T1059"), 1337: (40, None),
    31337: (65, None), 6666: (50, None), 6667: (35, None),
    5900: (25, "T1021"), 5901: (25, "T1021"), 1080: (30, None),
    8080: (15, None), 9001: (25, None), 9050: (25, None),
}


class DetectionEngine:
    def __init__(self, risk: RiskEngine | None = None) -> None:
        self.risk = risk or RiskEngine()

    def evaluate(self, event: SecurityEvent) -> list[SecurityAlert]:
        if event.event_type == "network.dns":
            domain = str(event.data.get("domain") or "").lower().rstrip(".")
            finding = _dns_anomaly(domain)
            if not finding:
                return []
            score, reason = finding
            event.data["dns_anomaly"] = reason
            event.data["behavior_score"] = max(float(event.data.get("behavior_score", 0)), score)
            evidence = [{"field": "destination_domain", "value": domain}, {"field": "anomaly", "value": reason}]
            return [SecurityAlert(
                alert_type="DNS_ANOMALY", title="Suspicious DNS domain pattern",
                severity=self.risk.severity(score), host_id=event.host_id,
                confidence=0.78, risk_score=score,
                reason="The queried domain has a high-entropy or unusually long label.",
                evidence=evidence, mitre_techniques=["T1568.003"],
                source_event_ids=[event.event_id],
                timestamp=event.timestamp,
            )]
        if event.event_type not in {"network.packet", "endpoint.socket", "endpoint.process"}:
            return []
        data: dict[str, Any] = event.data
        alerts: list[SecurityAlert] = []
        process = str(data.get("process_name") or data.get("name") or event.process.get("name") or "").lower()
        dst_port = data.get("dst_port") or event.network.get("dst_port")

        process_factor = SUSPICIOUS_PROCESSES.get(process, 0)
        if event.event_type == "endpoint.process" and process in {"powershell.exe", "cmd.exe"}:
            command_line = data.get("cmdline") or event.process.get("cmdline") or []
            if not isinstance(command_line, (tuple, list)):
                command_line = [command_line]
            command = " ".join(str(part) for part in command_line).lower()
            suspicious_execution = any(marker in command for marker in (
                "-encodedcommand", " -enc ", "downloadstring", "downloadfile",
                "frombase64string", "invoke-webrequest", "start-bitstransfer",
                "windowstyle hidden", " -nop ",
            ))
            process_factor = process_factor + (25 if suspicious_execution else -process_factor)
        port_factor, mitre = SUSPICIOUS_PORTS.get(dst_port, (0, None)) if event.event_type != "endpoint.process" else (0, None)
        behavior = float(data.get("behavior_score", 0))
        indicator = float(data.get("indicator_score", 0))
        destination = float(data.get("destination_score", 0))

        score = self.risk.score(RiskFactors(
            indicator=indicator,
            behavior=behavior,
            process=process_factor,
            destination=destination,
        ))

        # A first-seen destination is telemetry, not an alert by itself.
        # Repetitive behavior is emitted once when the rolling threshold is crossed.
        behavior_reasons = set(data.get("behavior_reasons") or [])
        meaningful_behavior = behavior >= 20 and bool(behavior_reasons - {"new_destination"})
        if process_factor or port_factor or meaningful_behavior or indicator or destination:
            # Port/process evidence is intentionally additive; it does not equal compromise.
            score = max(score, min(100, port_factor + process_factor // 2))
            severity = self.risk.severity(score)
            process_name = process
            evidence = [{"field": "process", "value": process_name}] if process_name else []
            if data.get("pid") is not None:
                evidence.append({"field": "process_id", "value": data["pid"]})
            if data.get("exe") or data.get("process_exe"):
                evidence.append({"field": "process_path", "value": data.get("exe") or data.get("process_exe")})
            if dst_port is not None:
                evidence.append({"field": "destination_port", "value": dst_port})
            if data.get("domain"):
                evidence.append({"field": "destination_domain", "value": data["domain"]})
            alerts.append(SecurityAlert(
                alert_type=("SUSPICIOUS_PROCESS_EXECUTION" if event.event_type == "endpoint.process" else "SUSPICIOUS_NETWORK_BEHAVIOR"),
                title=("Suspicious process execution" if event.event_type == "endpoint.process" else "Suspicious outbound network behavior"),
                severity=severity,
                host_id=event.host_id,
                confidence=min(0.99, 0.35 + score / 150),
                risk_score=score,
                reason="Multiple security indicators require contextual investigation.",
                evidence=evidence + ([{"field":"destination_ip","value":data.get("dst_ip") or event.network.get("dst_ip")}] if data.get("dst_ip") or event.network.get("dst_ip") else []),
                mitre_techniques=sorted(set(([mitre] if mitre else []) + list(event.data.get("mitre_techniques", [])))),
                source_event_ids=list(dict.fromkeys([event.event_id, *event.data.get("related_event_ids", [])])),
                timestamp=event.timestamp,
            ))
        return alerts
