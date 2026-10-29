from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard" / "src" / "main.jsx"

def test_dashboard_uses_same_origin_api():
    source = DASHBOARD.read_text(encoding="utf-8")
    assert "const API = window.location.origin;" in source
    assert "http://127.0.0.1:8000" not in source
    assert "http://localhost:8000" not in source

def test_dashboard_websocket_uses_current_origin_protocol():
    source = DASHBOARD.read_text(encoding="utf-8")
    assert "window.location.protocol === 'https:' ? 'wss:' : 'ws:'" in source
    assert "window.location.host" in source


def test_dashboard_integrates_response_history_and_forced_dry_run_plan_path():
    source = DASHBOARD.read_text(encoding="utf-8")
    response_activity = (ROOT / "dashboard" / "src" / "response-activity.js").read_text(encoding="utf-8")
    assert '<ResponseDesk token={token} role={role} incidents={openIncidents} />' in source
    assert "Prepare dry-run plan" in source
    assert "cannot approve, execute, block, isolate, or terminate a target" in source
    assert "`${api}/api/v1/response/actions`" in response_activity
    assert "`${api}/api/v1/response/audit`" in response_activity
    assert "dry_run: true" in response_activity
    assert "evidence_ids: evidenceIds" in response_activity
    assert "evidence_ids: [incidentId]" not in response_activity
    assert "incidentEvidenceIds(incident).length > 0" in source


def test_dashboard_displays_the_exact_required_orbis_attribution():
    source = DASHBOARD.read_text(encoding="utf-8")
    assert "Based on PCYBOX Orbis by (Mister-iks) - " in source
    assert 'href="https://github.com/Mister-iks/pcybox-orbis"' in source
    assert "target=\"_blank\" rel=\"noreferrer\"" in source
