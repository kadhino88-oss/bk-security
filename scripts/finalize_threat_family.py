from pathlib import Path
from datetime import datetime
import shutil

ROOT = Path.cwd()
CORE = ROOT / "bk_security" / "core.py"
MODEL = ROOT / "bk_security" / "incidents" / "models.py"
TEST = ROOT / "tests" / "test_threat_family.py"

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP = ROOT / f"backup-threat-family-final-{stamp}"
BACKUP.mkdir(parents=True, exist_ok=False)

shutil.copy2(CORE, BACKUP / "core.py")
shutil.copy2(MODEL, BACKUP / "models.py")

if TEST.exists():
    shutil.copy2(TEST, BACKUP / "test_threat_family.py")

print(f"Backup : {BACKUP}")

# ============================================================
# SECURITY INCIDENT MODEL
# ============================================================

model = MODEL.read_text(encoding="utf-8")

if "threat_family_id:" not in model:
    marker = "    updated_at: str = field(default_factory=utc_now)\n"

    if marker not in model:
        raise SystemExit("ERREUR: updated_at introuvable dans SecurityIncident")

    model = model.replace(
        marker,
        marker +
        "    threat_family_id: str | None = None\n"
        "    threat_fingerprint: str | None = None\n",
        1,
    )

    MODEL.write_text(model, encoding="utf-8")
    print("SecurityIncident : champs Threat Family OK")
else:
    print("SecurityIncident : déjà équipé")

# ============================================================
# CORE
# ============================================================

core = CORE.read_text(encoding="utf-8")

if "import hashlib" not in core:
    marker = "import threading\n"
    if marker not in core:
        raise SystemExit("ERREUR: import threading introuvable")

    core = core.replace(
        marker,
        marker + "import hashlib\n",
        1,
    )

# ------------------------------------------------------------
# Threat fingerprint
# ------------------------------------------------------------

if "def _threat_fingerprint(" not in core:

    anchor = "    def _on_event(self, event: SecurityEvent) -> None:\n"

    if anchor not in core:
        raise SystemExit(
            "ERREUR: signature actuelle de _on_event introuvable"
        )

    helper = '''    @staticmethod
    def _threat_fingerprint(alert: SecurityAlert) -> tuple[str, str]:
        """Stable recurring-threat identity.

        Deliberately excludes PID, timestamp and severity.
        Separate incidents can therefore belong to one recurring
        threat family without being merged together.
        """
        process: set[str] = set()
        destinations: set[str] = set()
        ports: set[str] = set()
        domains: set[str] = set()

        for item in alert.evidence:
            field_name = str(item.get("field") or "").strip().lower()
            value = item.get("value")

            if value is None or str(value).strip() == "":
                continue

            normalized = str(value).strip().lower()

            if field_name == "process":
                process.add(normalized)
            elif field_name in {"destination_ip", "destination_domain"}:
                destinations.add(normalized)
            elif field_name == "destination_port":
                ports.add(normalized)
            elif field_name == "domain":
                domains.add(normalized)

        mitre = sorted(
            str(value).strip().upper()
            for value in alert.mitre_techniques
            if value
        )

        payload = "|".join([
            f"host={str(alert.host_id).strip().lower()}",
            f"type={str(alert.alert_type).strip().upper()}",
            f"process={','.join(sorted(process))}",
            f"destination={','.join(sorted(destinations))}",
            f"port={','.join(sorted(ports))}",
            f"domain={','.join(sorted(domains))}",
            f"mitre={','.join(mitre)}",
        ])

        fingerprint = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

        return f"tf-{fingerprint[:20]}", fingerprint

    def _attach_threat_family(
        self,
        incident: SecurityIncident,
        alert: SecurityAlert,
    ) -> None:
        family_id, fingerprint = self._threat_fingerprint(alert)
        incident.threat_family_id = family_id
        incident.threat_fingerprint = fingerprint

    def get_threat_family(
        self,
        threat_family_id: str,
    ) -> list[SecurityIncident]:
        """Return all incidents belonging to one recurring threat family."""
        return [
            incident
            for incident in self.incidents
            if incident.threat_family_id == threat_family_id
        ]

'''

    core = core.replace(anchor, helper + anchor, 1)
    print("Threat fingerprint : ajouté")
else:
    print("Threat fingerprint : déjà présent")

# ------------------------------------------------------------
# Attach family to newly created incidents
# ------------------------------------------------------------

creation = '''                incident = SecurityIncident(
                    title=alert.title,
                    host_id=event.host_id,
                    severity=alert.severity,
                    risk_score=alert.risk_score,
                )
'''

if "_attach_threat_family(incident, alert)" not in core:

    if creation not in core:
        raise SystemExit(
            "ERREUR: bloc SecurityIncident de création introuvable"
        )

    core = core.replace(
        creation,
        creation +
        "                self._attach_threat_family(incident, alert)\n",
        1,
    )

    print("Incident -> Threat Family : attaché")
else:
    print("Incident -> Threat Family : déjà attaché")

CORE.write_text(core, encoding="utf-8")

# ============================================================
# TESTS ENTERPRISE
# ============================================================

TEST.write_text(r'''from datetime import datetime, timedelta, timezone

from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.events.models import SecurityEvent


def _packet(
    host: str,
    timestamp: str,
    pid: int,
    destination: str = "203.0.113.50",
):
    return SecurityEvent(
        event_type="network.packet",
        source="test",
        host_id=host,
        timestamp=timestamp,
        data={
            "dst_ip": destination,
            "dst_port": 4444,
            "process_name": "powershell.exe",
            "process_id": pid,
        },
    )


def test_threat_family_same_condition_different_pid():
    core = SecurityCore()

    base = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)

    first = core.ingest(
        _packet(
            "family-host",
            base.isoformat(),
            6156,
        )
    )

    second = core.ingest(
        _packet(
            "family-host",
            (base + timedelta(minutes=45)).isoformat(),
            9952,
        )
    )

    assert first
    assert second

    assert len(core.incidents) == 2

    first_incident = core.incidents[-2]
    second_incident = core.incidents[-1]

    assert first_incident.incident_id != second_incident.incident_id
    assert first_incident.threat_family_id
    assert second_incident.threat_family_id
    assert (
        first_incident.threat_family_id
        == second_incident.threat_family_id
    )


def test_threat_family_different_destination_is_distinct():
    core = SecurityCore()

    base = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)

    first = core.ingest(
        _packet(
            "family-host-destination",
            base.isoformat(),
            1001,
            "203.0.113.50",
        )
    )

    second = core.ingest(
        _packet(
            "family-host-destination",
            (base + timedelta(minutes=45)).isoformat(),
            1002,
            "203.0.113.60",
        )
    )

    assert first
    assert second
    assert len(core.incidents) == 2

    assert (
        core.incidents[-2].threat_family_id
        != core.incidents[-1].threat_family_id
    )


def test_threat_family_survives_sqlite_restart(tmp_path):
    database = str(tmp_path / "threat-family.sqlite3")

    base = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)

    first = SecurityCore(SecurityStore(database))

    alerts = first.ingest(
        _packet(
            "persistent-family-host",
            base.isoformat(),
            7001,
        )
    )

    assert alerts
    assert first.incidents

    family_id = first.incidents[-1].threat_family_id
    fingerprint = first.incidents[-1].threat_fingerprint

    first.store.close()

    restarted = SecurityCore(SecurityStore(database))

    restored = next(
        item
        for item in restarted.incidents
        if item.incident_id == first.incidents[-1].incident_id
    )

    assert restored.threat_family_id == family_id
    assert restored.threat_fingerprint == fingerprint


def test_resolved_incident_gets_new_incident_same_family(tmp_path):
    database = str(tmp_path / "threat-family-lifecycle.sqlite3")

    base = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)

    core = SecurityCore(SecurityStore(database))

    first_alerts = core.ingest(
        _packet(
            "lifecycle-family-host",
            base.isoformat(),
            8001,
        )
    )

    assert first_alerts
    first_incident = core.incidents[-1]

    core.transition_incident(
        first_incident.incident_id,
        "INVESTIGATING",
        "test",
    )

    core.transition_incident(
        first_incident.incident_id,
        "RESOLVED",
        "test",
    )

    second_alerts = core.ingest(
        _packet(
            "lifecycle-family-host",
            (base + timedelta(hours=2)).isoformat(),
            8002,
        )
    )

    assert second_alerts

    second_incident = core.incidents[-1]

    assert second_incident.incident_id != first_incident.incident_id
    assert second_incident.threat_family_id == first_incident.threat_family_id
''', encoding="utf-8")

print("Tests Threat Family : installés")

# ============================================================
# VALIDATION
# ============================================================

print("")
print("=== SYNTAX CHECK ===")

import subprocess
import sys

for target in (
    "bk_security/incidents/models.py",
    "bk_security/core.py",
    "tests/test_threat_family.py",
):
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", target],
        cwd=ROOT,
    )

    if result.returncode != 0:
        raise SystemExit(
            f"ERREUR syntaxe : {target}"
        )

print("Syntaxe : OK")

print("")
print("=== THREAT FAMILY TESTS ===")

result = subprocess.run(
    [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/test_threat_family.py",
        "--basetemp="
        + str(
            ROOT
            / "build"
            / "threat-family-test-temp"
        ),
    ],
    cwd=ROOT,
)

if result.returncode != 0:
    raise SystemExit(
        "ERREUR : tests Threat Family échoués"
    )

print("")
print("=== FULL REGRESSION ===")

result = subprocess.run(
    [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--basetemp="
        + str(
            ROOT
            / "build"
            / "full-test-temp"
        ),
    ],
    cwd=ROOT,
)

if result.returncode != 0:
    raise SystemExit(
        "ERREUR : regression complète échouée"
    )

print("")
print("============================================")
print(" BK SECURITY - THREAT FAMILY FINALISEE")
print("============================================")
print("Incidents temporels : PRESERVES")
print("Threat Family : ACTIVE")
print("PID exclu : OK")
print("Timestamp exclu : OK")
print("Severity exclue : OK")
print("Destination differente : FAMILLE DIFFERENTE")
print("PID different : MEME FAMILLE")
print("SQLite restart : OK")
print("Lifecycle resolved/reopen : OK")
print("Regression complete : OK")
print(f"Backup : {BACKUP}")
print("")
