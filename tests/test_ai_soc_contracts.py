from __future__ import annotations

from fastapi.testclient import TestClient

from bk_security.ai.contracts import InvestigationRequest, InvestigationResult, SecurityWorker
from bk_security.ai.orchestrator import SecurityOrchestrator
from bk_security.api.app import app, core as api_core
from bk_security.auth.security import issue_token
from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.events.models import SecurityAlert, SecurityEvent


class FixedWorker(SecurityWorker):
    def __init__(self, name, disposition, evidence=True):
        self.name = name
        self.disposition = disposition
        self.with_evidence = evidence

    def investigate(self, request):
        return InvestigationResult(
            self.disposition,
            0.84,
            f"{self.name} finding",
            findings=["Finding linked to the submitted case."],
            evidence=([{"field": "test_indicator", "value": "known"}] if self.with_evidence else []),
            recommended_actions=["Review the linked event."],
        )


def _request(with_source=True, with_evidence=True):
    event = SecurityEvent(
        event_type="network.packet", source="test", host_id="contract-host",
        data={"dst_ip": "203.0.113.7"}, network={"dst_ip": "203.0.113.7"},
    )
    alert = SecurityAlert(
        alert_type="SUSPICIOUS_NETWORK_BEHAVIOR", title="Suspicious network activity",
        severity="high", host_id=event.host_id, confidence=0.9, risk_score=80,
        reason="Test evidence", evidence=([{"field": "destination_ip", "value": "203.0.113.7"}] if with_evidence else []),
        mitre_techniques=["T1041"], source_event_ids=([event.event_id] if with_source else []),
    )
    return InvestigationRequest(alert, [event] if with_source else [], {"incident_id": "incident-test"})


def test_worker_contract_returns_structured_traceable_conclusion():
    request = _request()
    result = SecurityOrchestrator([FixedWorker("contract_worker", "suspicious")]).investigate(request)
    payload = result.to_dict()
    assert result.valid is True
    assert result.disposition == "suspicious"
    assert result.confidence == 0.84
    assert result.source_alert_id == request.alert.alert_id
    assert result.source_event_ids == [request.alert.source_event_ids[0]]
    assert result.source_incident_ids == ["incident-test"]
    assert result.evidence
    assert result.sources[0] == {"type": "alert", "alert_id": request.alert.alert_id}
    assert "T1041" in result.mitre_techniques
    assert payload["recommended_actions"]
    assert payload["worker_results"][0]["valid"] is True


def test_untraceable_worker_conclusion_is_marked_invalid():
    request = _request(with_source=False, with_evidence=False)
    result = SecurityOrchestrator([FixedWorker("untraceable", "malicious", evidence=False)]).investigate(request)
    assert result.disposition == "needs_review"
    assert result.valid is False
    assert "evidence_missing" in result.validation_errors
    assert "source_event_provenance_missing_or_unknown" in result.validation_errors


def test_conflicting_worker_conclusions_are_marked_for_review():
    request = _request()
    result = SecurityOrchestrator([
        FixedWorker("benign_worker", "benign"),
        FixedWorker("malicious_worker", "malicious"),
    ]).investigate(request)
    assert result.valid is True
    assert result.disposition == "needs_review"
    assert result.conflicts
    assert result.limitations


def test_event_to_investigation_contract_preserves_critical_links(tmp_path):
    core = SecurityCore(SecurityStore(str(tmp_path / "ai-contract.sqlite3")))
    event = SecurityEvent(
        event_type="endpoint.process", source="golden-test", host_id="contract-host",
        timestamp="2026-10-06T12:00:00+00:00",
        data={"name": "powershell.exe", "process_name": "powershell.exe", "pid": 1234,
              "cmdline": ["powershell.exe", "-EncodedCommand", "redacted"]},
        process={"name": "powershell.exe", "pid": 1234},
    )
    try:
        alerts = core.ingest(event)
        assert alerts
        alert = alerts[0]
        incident = next(item for item in core.incidents if alert.alert_id in item.alert_ids)
        result = core.ai.investigate(InvestigationRequest(alert, [event], {"incident_id": incident.incident_id}))
        assert event.event_id in alert.source_event_ids
        assert alert.timestamp == event.timestamp
        assert alert.host_id == incident.host_id == event.host_id
        assert alert.risk_score == incident.risk_score
        assert alert.evidence
        assert alert.mitre_techniques
        assert incident.threat_family_id
        assert alert.alert_id in incident.alert_ids
        assert result.valid is True
        assert result.source_alert_id == alert.alert_id
        assert event.event_id in result.source_event_ids
        assert result.source_incident_ids == [incident.incident_id]
        assert result.evidence
        assert set(alert.mitre_techniques).issubset(set(result.mitre_techniques))
    finally:
        core.store.close()


def test_viewer_can_investigate_but_cannot_start_repair_action():
    event = SecurityEvent(
        event_type="endpoint.process", source="api-contract-test", host_id="api-contract-host",
        data={"name": "powershell.exe", "process_name": "powershell.exe", "pid": 4321,
              "cmdline": ["powershell.exe", "-EncodedCommand", "redacted"]},
        process={"name": "powershell.exe", "pid": 4321},
    )
    alerts = api_core.ingest(event)
    assert alerts
    token = issue_token("read-only-analyst", "viewer")
    headers = {"Authorization": f"Bearer {token}"}
    client = TestClient(app)

    investigated = client.post(f"/api/v1/alerts/{alerts[0].alert_id}/investigate", headers=headers)
    assert investigated.status_code == 200
    assert investigated.json()["valid"] is True
    api_incident = next(item for item in api_core.incidents if alerts[0].alert_id in item.alert_ids)
    assert investigated.json()["source_incident_ids"] == [api_incident.incident_id]

    refused = client.post(
        "/api/v1/reliability/repair",
        json={"action": "rebuild_cache_index", "target": "correlation"},
        headers=headers,
    )
    assert refused.status_code == 403


def test_incident_investigation_api_returns_traceability_for_viewer():
    event = SecurityEvent(
        event_type="endpoint.process", source="incident-api-test", host_id="incident-api-host",
        data={"name": "powershell.exe", "process_name": "powershell.exe", "pid": 8765,
              "cmdline": ["powershell.exe", "-EncodedCommand", "redacted"]},
        process={"name": "powershell.exe", "pid": 8765},
    )
    alerts = api_core.ingest(event)
    assert alerts
    incident = next(item for item in reversed(api_core.incidents) if alerts[0].alert_id in item.alert_ids)
    token = issue_token("read-only-analyst", "viewer")
    response = TestClient(app).get(
        f"/api/v1/incidents/{incident.incident_id}/investigate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["traceability"]["incident_id"] == incident.incident_id
    assert alerts[0].alert_id in payload["traceability"]["alert_ids"]
    assert event.event_id in payload["traceability"]["event_ids"]
    assert payload["investigations"][0]["valid"] is True
    assert payload["investigations"][0]["source_incident_ids"] == [incident.incident_id]
    persisted_event = TestClient(app).get(
        f"/api/v1/events?event_id={event.event_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert persisted_event.status_code == 200
    assert persisted_event.json()["events"][0]["event_id"] == event.event_id


def test_reliability_api_exposes_integrity_and_guards_diagnostics_by_role():
    client = TestClient(app)
    viewer = {"Authorization": f"Bearer {issue_token('read-only-analyst', 'viewer')}"}
    analyst = {"Authorization": f"Bearer {issue_token('soc-analyst', 'analyst')}"}

    integrity = client.get("/api/v1/reliability/integrity", headers=viewer)
    assert integrity.status_code == 200
    report = integrity.json()
    assert report["status"] == "SAFE"
    assert report["integrity_score"] == 100
    assert "configuration" in report["components"]
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["integrity_score"] == 100

    refused = client.get("/api/v1/reliability/diagnosis", headers=viewer)
    assert refused.status_code == 403
    diagnosis = client.get("/api/v1/reliability/diagnosis", headers=analyst)
    assert diagnosis.status_code == 200
    assert diagnosis.json()["code_modification_allowed"] is False

    audit = client.get("/api/v1/reliability/audit", headers=analyst)
    assert audit.status_code == 200
    assert audit.json()["valid"] is True
    assert any(item["action"] == "diagnostic" for item in audit.json()["entries"])
