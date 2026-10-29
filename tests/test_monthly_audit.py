from datetime import datetime, timezone
import json
import re

import pytest
from fastapi.testclient import TestClient

import bk_security.api.app as api_module
from bk_security.auth.security import issue_token
from bk_security.database import SecurityStore
from bk_security.deployment import DeploymentContext
from bk_security.events.models import SecurityAlert, SecurityEvent
from bk_security.incidents.models import SecurityIncident
from bk_security.monthly_audit import build_monthly_audit, month_bounds
from bk_security.reliability import ReliabilityLedger


def _headers(role="viewer"):
    return {"Authorization": f"Bearer {issue_token('monthly-audit-test', role)}"}


def test_month_bounds_are_utc_half_open_and_validate_calendar_month():
    start, end = month_bounds("2026-12")
    assert start.isoformat() == "2026-12-01T00:00:00+00:00"
    assert end.isoformat() == "2027-01-01T00:00:00+00:00"
    for value in ("2026-00", "2026-13", "26-10", "2026-2"):
        with pytest.raises(ValueError):
            month_bounds(value)


def test_monthly_report_aggregates_without_exposing_raw_payload_or_overclaiming(tmp_path):
    store = SecurityStore(str(tmp_path / "monthly-report.db"), max_events=20, max_alerts=20)
    ledger = ReliabilityLedger(store)
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    try:
        real_event = SecurityEvent(
            event_type="network.packet", source="test-sensor", host_id="private-host",
            data={"customer": "PRIVATE-CUSTOMER-NAME"},
        )
        simulated_event = SecurityEvent(
            event_type="network.dns", source="simulation-test", host_id="simulated-host",
            data={"simulation": True},
        )
        old_event = SecurityEvent(
            event_type="network.packet", source="old-source", host_id="old-host",
            timestamp="2020-01-01T00:00:00+00:00",
        )
        store.persist_ingest(real_event)
        store.persist_ingest(simulated_event)
        store.persist_ingest(old_event)
        alert = SecurityAlert(
            alert_type="SUSPICIOUS_NETWORK_BEHAVIOR", title="Suspicious activity",
            severity="high", host_id="private-host", confidence=.9, risk_score=90,
            reason="test", timestamp=datetime.now(timezone.utc).isoformat(),
        )
        store.save_alert(alert)
        incident = SecurityIncident(
            host_id="private-host", title="Suspicious activity", severity="high", risk_score=90,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        store.save_incident(incident)
        store.save_response_action({
            "action_id": "dry-run-1", "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "block", "dry_run": True, "status": "dry_run",
        })
        store.save_response_action({
            "action_id": "verified-block-1", "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "block", "execution_attempted": True, "status": "executed",
            "verification": {"verified": True},
        })
        store.save_response_action({
            "action_id": "fallback-timestamp-1", "timestamp": "invalid",
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "action": "alert", "execution_attempted": True, "status": "failed",
        })
        store.audit("analyst", "incident_status_transition", incident.incident_id, {"from": "INVESTIGATING", "to": "RESOLVED"})
        ledger.append("admin", "repair_succeeded", "pipeline", {"action": "relaunch_pipeline"})

        report = build_monthly_audit(store, month, ledger)
        encoded = json.dumps(report)
        assert report["events"]["records_in_period"] == 2
        assert report["events"]["simulation_marked"] == 1
        assert report["alerts"]["records_in_period"] == 1
        assert report["incidents"]["created_in_period"] == 1
        assert report["incidents"]["marked_resolved_or_closed_in_period"] == 1
        assert report["response"]["dry_run_records"] == 1
        assert report["response"]["verified_executions"] == 1
        assert report["response"]["execution_attempts"] == 2
        assert report["response"]["verified_block_or_isolate_actions"] == 1
        assert report["response"]["safe_platform_repairs"]["records_in_period"] == 1
        assert report["operational_audit"]["entries_in_period"] == 1
        assert report["outcomes"]["attacks_avoided"] == {"count": None, "status": "not_measured"}
        assert report["outcomes"]["threat_remediations"]["count"] is None
        assert report["outcomes"]["reliability_audit_chain"] == "valid"
        assert report["coverage"]["completeness"] == "not_proven"
        assert "PRIVATE-CUSTOMER-NAME" not in encoded
        assert "private-host" not in encoded
    finally:
        store.close()


def test_monthly_report_marks_a_source_that_hits_its_retention_limit(tmp_path):
    store = SecurityStore(str(tmp_path / "bounded-report.db"), max_events=2, max_alerts=20)
    try:
        for index in range(2):
            store.persist_ingest(SecurityEvent(
                event_type="network.packet", source="test", host_id=f"host-{index}"
            ))
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        report = build_monthly_audit(store, month)
        assert report["coverage"]["events"]["may_be_truncated"] is True
        assert report["coverage"]["possible_truncation"] is True
        assert report["outcomes"]["reliability_audit_chain"] == "not_checked"
    finally:
        store.close()


def test_monthly_audit_route_requires_auth_and_reports_utc_period(tmp_path, monkeypatch):
    store = SecurityStore(str(tmp_path / "route-report.db"))
    monkeypatch.setattr(api_module.core, "store", store)
    try:
        client = TestClient(api_module.app)
        assert client.get("/api/v1/audit/monthly?month=2026-10").status_code == 401
        invalid = client.get("/api/v1/audit/monthly?month=2026-13", headers=_headers())
        assert invalid.status_code == 422
        valid = client.get("/api/v1/audit/monthly?month=2026-10", headers=_headers())
        assert valid.status_code == 200, valid.text
        body = valid.json()
        assert body["period"]["month"] == "2026-10"
        assert body["period"]["timezone"] == "UTC"
        assert body["scope"]["profile"] == "local_v1"
        assert body["outcomes"]["attacks_avoided"]["status"] == "not_measured"
    finally:
        store.close()


def test_monthly_audit_api_uses_the_selected_customer_database_scope(tmp_path, monkeypatch):
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    deployment_id = "b63f5975-1ad9-4cdd-b65c-8ee87c05b24b"

    def dedicated_store(filename, customer_ref):
        context = DeploymentContext(
            profile="dedicated_customer", customer_ref=customer_ref,
            deployment_id=deployment_id, region="eu-ch",
        )
        store = SecurityStore(str(tmp_path / filename), deployment_context=context)
        store.persist_ingest(SecurityEvent(
            event_type="network.packet", source="scope-api-test",
            host_id=f"host-{customer_ref}", timestamp=f"{month}-15T12:00:00+00:00",
        ))
        return store

    first = dedicated_store("customer-one.db", "customer-one")
    second = dedicated_store("customer-two.db", "customer-two")
    monkeypatch.setattr(api_module.core, "store", first)
    try:
        client = TestClient(api_module.app)
        one = client.get(f"/api/v1/audit/monthly?month={month}", headers=_headers()).json()
        assert one["scope"]["customer_ref"] == "customer-one"
        assert one["events"]["records_in_period"] == 1

        monkeypatch.setattr(api_module.core, "store", second)
        two = client.get(f"/api/v1/audit/monthly?month={month}", headers=_headers()).json()
        assert two["scope"]["customer_ref"] == "customer-two"
        assert two["events"]["records_in_period"] == 1
        assert one["scope"]["customer_ref"] != two["scope"]["customer_ref"]
    finally:
        first.close()
        second.close()


def test_built_dashboard_serves_the_monthly_audit_component():
    client = TestClient(api_module.app)
    root = client.get("/")
    assert root.status_code == 200
    javascript = re.search(r'<script[^>]+src="([^"]+\.js)"', root.text)
    stylesheet = re.search(r'<link[^>]+href="([^"]+\.css)"', root.text)
    assert javascript and stylesheet
    js_response = client.get("/" + javascript.group(1).removeprefix("./"))
    css_response = client.get("/" + stylesheet.group(1).removeprefix("./"))
    assert js_response.status_code == 200
    assert css_response.status_code == 200
    assert "Monthly security audit" in js_response.text
    assert "Deployment scope:" in js_response.text
    assert "database binding only; host and region not attested" in js_response.text
    assert "Attacks avoided:" in js_response.text
    assert ".monthly-audit" in css_response.text
