from pathlib import Path
from datetime import datetime
import shutil

ROOT = Path.cwd()
CORE = ROOT / "bk_security" / "core.py"
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP = ROOT / f"backup-threat-family-core-{stamp}"
BACKUP.mkdir(parents=True, exist_ok=False)
shutil.copy2(CORE, BACKUP / "core.py")

core = CORE.read_text(encoding="utf-8")

# hashlib
if "import hashlib" not in core:
    marker = "import threading\n"
    if marker not in core:
        raise SystemExit("ERREUR: import threading introuvable")
    core = core.replace(marker, marker + "import hashlib\n", 1)

# Helper Threat Family
if "def _threat_fingerprint(" not in core:
    anchor = "    def _on_event(self, event: SecurityEvent) -> None:\n"

    if anchor not in core:
        raise SystemExit("ERREUR: vraie signature _on_event introuvable")

    helper = '''    @staticmethod
    def _threat_fingerprint(alert: SecurityAlert) -> tuple[str, str]:
        """Return a stable identity for a recurring threat.

        PID, timestamp and severity are deliberately excluded. Separate
        incidents can therefore belong to the same recurring threat family.
        """
        process_names: set[str] = set()
        destinations: set[str] = set()
        ports: set[str] = set()

        for item in alert.evidence:
            field_name = str(item.get("field") or "").strip().lower()
            value = item.get("value")

            if value is None or value == "":
                continue

            normalized = str(value).strip().lower()

            if field_name == "process":
                process_names.add(normalized)
            elif field_name in {"destination_ip", "destination_domain"}:
                destinations.add(normalized)
            elif field_name == "destination_port":
                ports.add(normalized)

        payload = "|".join([
            f"host={str(alert.host_id).strip().lower()}",
            f"type={str(alert.alert_type).strip().upper()}",
            f"process={','.join(sorted(process_names))}",
            f"destination={','.join(sorted(destinations))}",
            f"port={','.join(sorted(ports))}",
            f"mitre={','.join(sorted(str(x).strip().upper() for x in alert.mitre_techniques if x))}",
        ])

        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"tf-{digest[:20]}", digest

    def _attach_threat_family(
        self,
        incident: SecurityIncident,
        alert: SecurityAlert,
    ) -> None:
        family_id, fingerprint = self._threat_fingerprint(alert)
        incident.threat_family_id = family_id
        incident.threat_fingerprint = fingerprint

'''

    core = core.replace(anchor, helper + anchor, 1)

# Attach to NEW incidents.
marker = '''                incident = SecurityIncident(
                    title=alert.title,
                    host_id=event.host_id,
                    severity=alert.severity,
                    risk_score=alert.risk_score,
                )
                self.incidents.append(incident)
'''

if "_attach_threat_family(incident, alert)" not in core:
    if marker not in core:
        raise SystemExit(
            "ERREUR: bloc exact de création SecurityIncident introuvable"
        )

    replacement = '''                incident = SecurityIncident(
                    title=alert.title,
                    host_id=event.host_id,
                    severity=alert.severity,
                    risk_score=alert.risk_score,
                )
                self._attach_threat_family(incident, alert)
                self.incidents.append(incident)
'''

    core = core.replace(marker, replacement, 1)

CORE.write_text(core, encoding="utf-8")

print("")
print("============================================")
print(" BK SECURITY - THREAT FAMILY")
print("============================================")
print("Core modifie : OK")
print("Fingerprint : SHA-256")
print("PID exclu : OK")
print("Timestamp exclu : OK")
print("Severity exclue : OK")
print("Incidents fusionnes : NON")
print(f"Backup : {BACKUP}")
print("")
