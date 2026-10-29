from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import bk_security.api.app as api_module
from bk_security.auth.security import issue_token
from bk_security.events.models import SecurityAlert, SecurityEvent
from bk_security.incidents.models import SecurityIncident
from bk_security.policy.engine import Action
from bk_security.policy.response import ResponseEngine


class FakeResponseAdapter:
    def __init__(self, verified=True):
        self.calls = []
        self.verified = verified

    def execute(self, target, action, reason):
        self.calls.append(("execute", target, action.value, reason))
        return {"accepted": True, "target": target, "reversible": True}

    def verify(self, target, action, result):
        return {"verified": self.verified}

    def rollback(self, execution):
        self.calls.append(("rollback", execution["target"]))
        return {"restored": True}

    def verify_rollback(self, execution, result):
        return {"verified": True}


@pytest.fixture
def client(monkeypatch):
    old_response = api_module.core.response
    api_module.core.response = ResponseEngine()
    try:
        yield TestClient(api_module.app)
    finally:
        api_module.core.response = old_response


def headers(role):
    return {"Authorization": f"Bearer {issue_token(f'test-{role}', role)}"}


def create_plan(client, *, dry_run=False, evidence=None, idempotency_key=None):
    body = {
        "action": "block",
        "target": "203.0.113.24",
        "reason": "validated test IOC",
        "dry_run": dry_run,
        "risk_level": "critical",
        "evidence_ids": evidence or [],
    }
    request_headers = headers("analyst")
    if idempotency_key:
        request_headers["Idempotency-Key"] = idempotency_key
    response = client.post("/api/v1/response/plan", headers=request_headers, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_response_routes_expose_separated_plan_approval_execution_and_audit():
    paths = set(api_module.app.openapi()["paths"])
    assert {
        "/api/v1/response/plan",
        "/api/v1/response/approve/{plan_id}",
        "/api/v1/response/approve-rollback/{execution_id}",
        "/api/v1/response/execute",
        "/api/v1/response/rollback/{execution_id}",
        "/api/v1/response/actions",
        "/api/v1/response/audit",
    } <= paths


def test_rbac_denies_wrong_role_and_sensitive_execution_without_approval(client):
    plan = create_plan(client)
    execution = {"plan_id": plan["plan_id"], "dry_run": False}
    assert client.post("/api/v1/response/execute", headers=headers("analyst"), json=execution).status_code == 403
    assert client.post("/api/v1/response/execute", headers=headers("responder"), json=execution).status_code == 409
    assert client.post(
        f"/api/v1/response/approve/{plan['plan_id']}",
        headers=headers("analyst"),
    ).status_code == 403


def test_dry_run_is_non_destructive_and_does_not_need_a_live_approval(client):
    adapter = FakeResponseAdapter()
    api_module.core.response.adapters[Action.BLOCK] = adapter
    plan = create_plan(client, dry_run=True)
    result = client.post(
        "/api/v1/response/execute", headers=headers("responder"),
        json={"plan_id": plan["plan_id"], "dry_run": True},
    )
    assert result.status_code == 200
    assert result.json()["status"] == "dry_run"
    assert adapter.calls == []


def test_policy_selected_incident_plan_is_dry_run_linked_and_visible_in_actions_and_audit(client):
    evidence = SecurityEvent(
        event_type="network.packet",
        source="response-desk-test",
        host_id="host-response-desk",
    )
    alert = SecurityAlert(
        alert_type="SUSPICIOUS_NETWORK_BEHAVIOR",
        title="Suspicious outbound network behavior",
        severity="critical",
        host_id="host-response-desk",
        confidence=0.95,
        risk_score=98,
        reason="Test alert linked to actual event evidence.",
        source_event_ids=[evidence.event_id],
        alert_id="alert-response-desk-test",
    )
    incident = SecurityIncident(
        host_id="host-response-desk",
        title="Suspicious outbound network behavior",
        severity="critical",
        risk_score=98,
        alert_ids=[alert.alert_id],
    )
    api_module.core.events.append(evidence)
    api_module.core.alerts.append(alert)
    api_module.core.incidents.append(incident)
    adapter = FakeResponseAdapter()
    api_module.core.response.adapters[Action.BLOCK] = adapter
    try:
        planned = client.post(
            "/api/v1/response/plan",
            headers=headers("analyst"),
            json={
                "target": incident.host_id,
                "reason": f"Dry-run review: {incident.title}",
                "dry_run": True,
                "risk_level": "info",
                "risk_score": 0,
                "incident_id": incident.incident_id,
                "evidence_ids": incident.alert_ids,
            },
        )
        assert planned.status_code == 200, planned.text
        plan = planned.json()
        assert plan["action"] == "require_approval"
        assert plan["policy_decision"]["severity"] == "critical"
        assert plan["requires_approval"] is True
        assert plan["dry_run"] is True
        assert plan["incident_id"] == incident.incident_id
        assert plan["evidence_ids"] == incident.alert_ids

        execution = client.post(
            "/api/v1/response/execute",
            headers=headers("responder"),
            json={"plan_id": plan["plan_id"], "dry_run": True},
        )
        assert execution.status_code == 200
        assert execution.json()["status"] == "dry_run"
        assert adapter.calls == []

        actions = client.get("/api/v1/response/actions", headers=headers("viewer")).json()["actions"]
        assert any(item.get("plan_id") == plan["plan_id"] for item in actions)
        audit = client.get("/api/v1/response/audit", headers=headers("viewer")).json()["audit"]
        plan_audit = next(item for item in audit if item["action"] == "response_plan" and item["data"].get("plan_id") == plan["plan_id"])
        assert plan_audit["data"]["incident_id"] == incident.incident_id
        assert plan_audit["data"]["evidence_ids"] == incident.alert_ids
    finally:
        api_module.core.incidents.remove(incident)
        api_module.core.alerts.remove(alert)
        api_module.core.events.remove(evidence)


def test_approved_execution_is_verified_idempotent_and_fully_audited(client):
    adapter = FakeResponseAdapter()
    api_module.core.response.adapters[Action.BLOCK] = adapter
    evidence = SecurityEvent(event_type="network.dns", source="test", host_id="api-host")
    api_module.core.events.append(evidence)
    plan = create_plan(client, evidence=[evidence.event_id])
    approval = client.post(
        f"/api/v1/response/approve/{plan['plan_id']}", headers=headers("approver")
    )
    assert approval.status_code == 200
    result = client.post(
        "/api/v1/response/execute", headers=headers("responder"),
        json={"plan_id": plan["plan_id"], "dry_run": False},
    )
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "executed"
    assert result.json()["verification"]["verified"] is True
    replay = client.post(
        "/api/v1/response/execute", headers=headers("responder"),
        json={"plan_id": plan["plan_id"], "dry_run": False},
    )
    assert replay.status_code == 200
    assert replay.json()["idempotent_replay"] is True
    assert len([call for call in adapter.calls if call[0] == "execute"]) == 1

    audit = client.get("/api/v1/response/audit", headers=headers("viewer")).json()["audit"]
    stages = {item["action"] for item in audit}
    assert {"response_policy_decision", "response_plan", "response_approval",
            "response_execution_started", "response_execute", "response_verification"} <= stages
    execute_entry = next(item for item in audit if item["action"] == "response_execute")
    assert execute_entry["actor"] == "test-responder"
    assert execute_entry["data"]["evidence_ids"] == [evidence.event_id]
    assert execute_entry["data"]["reason"] == "validated test IOC"


def test_verification_failure_returns_http_error_and_explicit_degraded_state(client):
    api_module.core.response.adapters[Action.BLOCK] = FakeResponseAdapter(verified=False)
    plan = create_plan(client)
    assert client.post(
        f"/api/v1/response/approve/{plan['plan_id']}", headers=headers("approver")
    ).status_code == 200
    result = client.post(
        "/api/v1/response/execute", headers=headers("responder"),
        json={"plan_id": plan["plan_id"], "dry_run": False},
    )
    assert result.status_code == 502
    assert result.json()["detail"]["status"] == "degraded"
    assert result.json()["detail"]["verified"] is False


def test_rollback_requires_separate_approval_and_verifies_restoration(client):
    adapter = FakeResponseAdapter()
    api_module.core.response.adapters[Action.BLOCK] = adapter
    plan = create_plan(client)
    api_module.core.approve_response(plan["plan_id"], actor="test-approver", role="approver")
    api_module.core.execute_response(
        plan["plan_id"], plan["plan_id"], actor="test-responder", actor_role="responder", dry_run=False,
    )
    assert client.post(
        f"/api/v1/response/rollback/{plan['plan_id']}", headers=headers("responder")
    ).status_code == 409
    assert client.post(
        f"/api/v1/response/approve-rollback/{plan['plan_id']}", headers=headers("approver")
    ).status_code == 200
    rollback = client.post(
        f"/api/v1/response/rollback/{plan['plan_id']}", headers=headers("responder")
    )
    assert rollback.status_code == 200
    assert rollback.json()["status"] == "rolled_back"
    assert rollback.json()["verified"] is True


def test_invalid_target_and_unknown_evidence_return_contract_errors(client):
    invalid = client.post(
        "/api/v1/response/plan", headers=headers("analyst"),
        json={"action": "block", "target": "not-an-ip", "reason": "test", "risk_level": "critical"},
    )
    assert invalid.status_code == 422
    missing_evidence = client.post(
        "/api/v1/response/plan", headers=headers("analyst"),
        json={"action": "alert", "target": "host", "reason": "test",
              "risk_level": "critical", "evidence_ids": [str(uuid4())]},
    )
    assert missing_evidence.status_code == 404


def test_plan_idempotency_key_reuses_same_plan_and_rejects_changed_contents(client):
    plan = create_plan(client, idempotency_key="phase5-retry-01")
    repeated = create_plan(client, idempotency_key="phase5-retry-01")
    assert repeated["plan_id"] == plan["plan_id"]
    changed = client.post(
        "/api/v1/response/plan",
        headers={**headers("analyst"), "Idempotency-Key": "phase5-retry-01"},
        json={"action": "block", "target": "203.0.113.99", "reason": "changed request",
              "dry_run": False, "risk_level": "critical"},
    )
    assert changed.status_code == 409
