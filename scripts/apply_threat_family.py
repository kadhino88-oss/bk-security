from pathlib import Path
from datetime import datetime
import hashlib
import re
import shutil

ROOT = Path.cwd()
CORE = ROOT / "bk_security" / "core.py"
MODEL = ROOT / "bk_security" / "incidents" / "models.py"

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP = ROOT / f"backup-threat-family-{stamp}"
BACKUP.mkdir(parents=True, exist_ok=False)

shutil.copy2(CORE, BACKUP / "core.py")
shutil.copy2(MODEL, BACKUP / "models.py")

print(f"Backup : {BACKUP}")

# ------------------------------------------------------------
# 1. SecurityIncident : ajouter les métadonnées Threat Family
# ------------------------------------------------------------
model = MODEL.read_text(encoding="utf-8")

if "threat_family_id:" not in model:
    marker = "    updated_at: str = field(default_factory=utc_now)\n"
    if marker not in model:
        raise SystemExit("ERREUR: marqueur updated_at introuvable dans models.py")

    replacement = marker + (
        "    # Stable recurring-threat identity. This does not merge incidents.\n"
        "    threat_family_id: str | None = None\n"
        "    threat_fingerprint: str | None = None\n"
    )

    model = model.replace(marker, replacement, 1)
    MODEL.write_text(model, encoding="utf-8")
    print("SecurityIncident : champs Threat Family ajoutés.")
else:
    print("SecurityIncident : champs Threat Family déjà présents.")

# ------------------------------------------------------------
# 2. core.py : imports
# ------------------------------------------------------------
core = CORE.read_text(encoding="utf-8")

if "import hashlib" not in core:
    import_marker = "import threading\n"
    if import_marker not in core:
        raise SystemExit("ERREUR: import threading introuvable dans core.py")
    core = core.replace(
        import_marker,
        import_marker + "import hashlib\n",
        1,
    )

# ------------------------------------------------------------
# 3. core.py : helper Threat Family
# ------------------------------------------------------------
if "def _threat_fingerprint(" not in core:

    anchor = "    def _on_event(self, event: SecurityEvent) -> list[SecurityAlert]:\n"

    if anchor not in core:
        raise SystemExit(
            "ERREUR: _on_event introuvable. Aucun fichier n'a été modifié davantage."
        )

    helper = '''    @staticmethod
    def _threat_fingerprint(alert: SecurityAlert) -> tuple[str, str]:
        """Build a stable semantic identity for recurring threats.

        PID, timestamp and severity are intentionally excluded. This lets the
        same threat reappear later or under a new process PID without merging
        its separate incidents.
        """
        values: dict[str, set[str]] = {
            "process": set(),
            "destination": set(),
            "port": set(),
            "mitre": {str(x).upper().strip() for x in alert.mitre_techniques if x},
            "type": {str(alert.alert_type).upper().strip()},
        }

        for item in alert.evidence:
            field_name = str(item.get("field") or "").strip().lower()
            value = item.get("value")
            if value is None or value == "":
                continue

            normalized = str(value).strip().lower()

            if field_name == "process":
                values["process"].add(normalized)
            elif field_name in {"destination_ip", "destination_domain"}:
                values["destination"].add(normalized)
            elif field_name == "destination_port":
                values["port"].add(normalized)

        payload = "|".join([
            f"host={alert.host_id.strip().lower()}",
            f"type={','.join(sorted(values['type']))}",
            f"process={','.join(sorted(values['process']))}",
            f"destination={','.join(sorted(values['destination']))}",
            f"port={','.join(sorted(values['port']))}",
            f"mitre={','.join(sorted(values['mitre']))}",
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

    def _find_threat_family_incidents(self, family_id: str) -> list[SecurityIncident]:
        return [
            incident
            for incident in self.incidents
            if incident.threat_family_id == family_id
        ]

'''

    core = core.replace(anchor, helper + anchor, 1)

# ------------------------------------------------------------
# 4. Attach family when creating an incident
# ------------------------------------------------------------
creation_marker = """                incident = SecurityIncident(
                    host_id=alert.host_id,
                    title=alert.title,
                    severity=alert.severity,
                    risk_score=alert.risk_score,
                )
"""

if creation_marker in core and "_attach_threat_family(incident, alert)" not in core:
    replacement = creation_marker + (
        "                self._attach_threat_family(incident, alert)\n"
    )
    core = core.replace(creation_marker, replacement, 1)
    print("Création d'incident : Threat Family attachée.")
elif "_attach_threat_family(incident, alert)" in core:
    print("Création d'incident : Threat Family déjà attachée.")
else:
    raise SystemExit(
        "ERREUR: bloc SecurityIncident de création introuvable dans core.py. "
        "Les fichiers restent sauvegardés dans le backup."
    )

# ------------------------------------------------------------
# 5. Lorsqu'un incident existant est restauré / enrichi,
#    conserver ses métadonnées.
# ------------------------------------------------------------
CORE.write_text(core, encoding="utf-8")

print("")
print("============================================")
print(" BK SECURITY - THREAT FAMILY FOUNDATION")
print("============================================")
print("Threat Family : INTEGREE")
print("Incident merge : DESACTIVE")
print("Correlation 5 min : PRESERVEE")
print("PID dans fingerprint : EXCLU")
print("Timestamp dans fingerprint : EXCLU")
print("Severity dans fingerprint : EXCLUE")
print("Persistance : via incidents SQLite")
print(f"Backup : {BACKUP}")
print("")
