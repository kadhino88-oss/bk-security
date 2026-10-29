from __future__ import annotations

import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import bk_security.api.app as api_module
from bk_security.auth.security import issue_token, verify_token
from bk_security.database import SecurityStore
from bk_security.deployment import DeploymentContext


@pytest.fixture
def plane(monkeypatch, tmp_path):
    context = DeploymentContext(profile="dedicated_customer", customer_ref="customer-one",
                                deployment_id=str(uuid4()), region="eu-ch")
    store = SecurityStore(path=str(tmp_path / "customer-one.db"), deployment_context=context)
    monkeypatch.setattr(api_module, "deployment_context", context)
    monkeypatch.setattr(api_module.core, "store", store)
    monkeypatch.delenv("BK_SECURITY_INGEST_DB", raising=False)
    yield context, store, TestClient(api_module.app)
    store.close()


def _auth(context, store, username, role):
    token = issue_token(username, role, deployment_context=context)
    session = verify_token(token, deployment_context=context)
    store.register_auth_session(session.token_id, username, session.expires_at)
    return {"Authorization": f"Bearer {token}"}


def _envelope(context, envelope_id="env-00001", agent="analyst", **event_over):
    event = {"event_type": "network.connection", "source": "agent", "host_id": "host-9"}
    event.update(event_over)
    return {"schema_version": 1, "envelope_id": envelope_id, "agent_id": agent,
            "customer_ref": context.customer_ref, "deployment_id": context.deployment_id,
            "sequence": 1, "event": event}


def test_ingest_routes_require_authentication(plane):
    _, _, client = plane
    assert client.post("/api/v1/ingest/envelopes", json={}).status_code == 401
    assert client.post("/api/v1/ingest/drain").status_code == 401
    assert client.get("/api/v1/ingest/stats").status_code == 401


def test_roles_are_enforced(plane):
    context, store, client = plane
    viewer = _auth(context, store, "viewer", "viewer")
    analyst = _auth(context, store, "analyst", "analyst")
    assert client.post("/api/v1/ingest/envelopes", headers=viewer, json=_envelope(context)).status_code == 403
    assert client.post("/api/v1/ingest/drain", headers=analyst).status_code == 403
    assert client.get("/api/v1/ingest/stats", headers=viewer).status_code == 200


def test_local_profile_refuses_envelope_ingestion(monkeypatch, tmp_path):
    monkeypatch.setattr(api_module, "deployment_context", DeploymentContext())
    headers = {"Authorization": f"Bearer {issue_token('analyst', 'analyst')}"}
    response = TestClient(api_module.app).post("/api/v1/ingest/envelopes", headers=headers, json={})
    assert response.status_code == 409


def test_submit_dedupe_drain_reaches_the_core_pipeline(plane):
    context, store, client = plane
    analyst = _auth(context, store, "analyst", "analyst")
    admin = _auth(context, store, "admin", "admin")
    body = _envelope(context)
    first = client.post("/api/v1/ingest/envelopes", headers=analyst, json=body)
    assert first.status_code == 202 and first.json()["status"] == "accepted"
    assert client.post("/api/v1/ingest/envelopes", headers=analyst, json=body).json()["status"] == "duplicate"
    assert client.get("/api/v1/ingest/stats", headers=analyst).json()["pending"] == 1

    before = len(api_module.core.events)
    drained = client.post("/api/v1/ingest/drain", headers=admin)
    assert drained.json() == {"processed": 1, "failed": 0}
    assert len(api_module.core.events) == before + 1
    assert api_module.core.events[-1].host_id == "host-9"
    assert any(row["action"] == "ingest_queue_drained" for row in store.list_audit())


def test_cross_tenant_and_mismatched_agent_envelopes_are_quarantined_and_audited(plane):
    context, store, client = plane
    analyst = _auth(context, store, "analyst", "analyst")
    foreign = _envelope(context, "env-x0001")
    foreign["customer_ref"] = "customer-two"
    response = client.post("/api/v1/ingest/envelopes", headers=analyst, json=foreign)
    assert response.status_code == 422 and response.json()["reason"] == "tenant_mismatch"
    spoofed = client.post("/api/v1/ingest/envelopes", headers=analyst, json=_envelope(context, "env-y0001", agent="admin"))
    assert spoofed.json()["reason"] == "agent_mismatch"
    assert client.get("/api/v1/ingest/stats", headers=analyst).json()["quarantined"] == 2
    audited = [row for row in store.list_audit() if row["action"] == "ingest_envelope_quarantined"]
    assert len(audited) == 2


def test_malformed_body_is_quarantined(plane):
    context, store, client = plane
    analyst = _auth(context, store, "analyst", "analyst")
    response = client.post("/api/v1/ingest/envelopes", headers=analyst, content=b"{nope",
                           )
    assert response.status_code == 422 and response.json()["reason"] == "malformed"


def test_agent_quota_returns_429_with_retry_after(plane, monkeypatch):
    context, store, client = plane
    monkeypatch.setenv("BK_SECURITY_INGEST_AGENT_BURST", "1")
    monkeypatch.setenv("BK_SECURITY_INGEST_AGENT_RATE", "0.1")
    monkeypatch.setenv("BK_SECURITY_INGEST_DB", str(store.path) + ".quota.db")
    analyst = _auth(context, store, "analyst", "analyst")
    assert client.post("/api/v1/ingest/envelopes", headers=analyst, json=_envelope(context, "quota-001")).status_code == 202
    limited = client.post("/api/v1/ingest/envelopes", headers=analyst, json=_envelope(context, "quota-002"))
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1


def test_backpressure_returns_503(plane, monkeypatch):
    context, store, client = plane
    monkeypatch.setenv("BK_SECURITY_INGEST_MAX_DEPTH", "1")
    monkeypatch.setenv("BK_SECURITY_INGEST_DB", str(store.path) + ".depth.db")
    analyst = _auth(context, store, "analyst", "analyst")
    assert client.post("/api/v1/ingest/envelopes", headers=analyst, json=_envelope(context, "depth-001")).status_code == 202
    full = client.post("/api/v1/ingest/envelopes", headers=analyst, json=_envelope(context, "depth-002"))
    assert full.status_code == 503 and full.headers["Retry-After"]


def test_simulation_marked_envelopes_are_quarantined_in_production(plane, monkeypatch):
    context, store, client = plane
    monkeypatch.setenv("BK_SECURITY_AUTH_SECRET", "x" * 32)
    analyst = _auth(context, store, "analyst", "analyst")
    monkeypatch.setenv("BK_SECURITY_ENV", "production")
    body = _envelope(context, "sim-00001", tags=["simulation"])
    response = client.post("/api/v1/ingest/envelopes", headers=analyst, content=json.dumps(body))
    assert response.status_code == 422 and response.json()["reason"] == "simulation_in_production"
    assert client.get("/api/v1/ingest/stats", headers=analyst).json()["pending"] == 0


def test_queue_is_a_separate_file_beside_each_customer_database(plane):
    context, store, client = plane
    analyst = _auth(context, store, "analyst", "analyst")
    client.post("/api/v1/ingest/envelopes", headers=analyst, json=_envelope(context))
    from pathlib import Path
    assert Path(store.path + ".ingest.db").exists()


def test_envelope_cannot_overwrite_existing_evidence_or_forge_server_fields(plane):
    context, store, client = plane
    analyst = _auth(context, store, "analyst", "analyst")
    admin = _auth(context, store, "admin", "admin")
    original = client.post("/api/v1/events", headers=admin, json={
        "event_type": "network.connection", "source": "sensor", "host_id": "victim-host",
        "data": {"note": "ORIGINAL EVIDENCE"}})
    event_id = original.json()["event"]["event_id"]
    forged = _envelope(context, "forge-0001", event_id=event_id, data={"note": "ATTACKER REPLACEMENT"})
    response = client.post("/api/v1/ingest/envelopes", headers=analyst, json=forged)
    assert response.status_code == 422 and response.json()["reason"] == "server_owned_field"
    client.post("/api/v1/ingest/drain", headers=admin)
    assert store.get_event(event_id)["data"]["note"] == "ORIGINAL EVIDENCE"


def test_simulation_guard_cannot_be_bypassed_with_wrong_types_in_production(plane, monkeypatch):
    context, store, client = plane
    monkeypatch.setenv("BK_SECURITY_AUTH_SECRET", "x" * 32)
    analyst = _auth(context, store, "analyst", "analyst")
    monkeypatch.setenv("BK_SECURITY_ENV", "production")
    response = client.post("/api/v1/ingest/envelopes", headers=analyst,
                           json=_envelope(context, "sim-00002", tags="simulation"))
    assert response.status_code == 422 and response.json()["reason"] == "bad_event"
    assert client.get("/api/v1/ingest/stats", headers=analyst).json()["pending"] == 0


def test_invalid_ingestion_settings_return_503_not_500(plane, monkeypatch):
    context, store, client = plane
    monkeypatch.setenv("BK_SECURITY_INGEST_AGENT_RATE", "abc")
    analyst = _auth(context, store, "analyst", "analyst")
    response = client.post("/api/v1/ingest/envelopes", headers=analyst, json=_envelope(context))
    assert response.status_code == 503 and "BK_SECURITY_INGEST_AGENT_RATE" in response.json()["detail"]


def test_shared_queue_path_cannot_mix_customers(plane, monkeypatch, tmp_path):
    context, store, client = plane
    analyst = _auth(context, store, "analyst", "analyst")
    monkeypatch.setenv("BK_SECURITY_INGEST_DB", str(tmp_path / "shared.ingest.db"))
    assert client.post("/api/v1/ingest/envelopes", headers=analyst, json=_envelope(context)).status_code == 202
    other = DeploymentContext(profile="dedicated_customer", customer_ref="customer-two",
                              deployment_id=str(uuid4()), region="eu-ch")
    other_store = SecurityStore(path=str(tmp_path / "customer-two.db"), deployment_context=other)
    monkeypatch.setattr(api_module, "deployment_context", other)
    monkeypatch.setattr(api_module.core, "store", other_store)
    admin = _auth(other, other_store, "admin", "admin")
    assert client.post("/api/v1/ingest/drain", headers=admin).status_code == 503
    assert other_store.list_events(10) == []
    other_store.close()


def test_blocking_ingestion_work_runs_off_the_event_loop():
    import inspect
    routes = {route.path: route.endpoint for route in api_module.app.routes if hasattr(route, "endpoint")}
    assert not inspect.iscoroutinefunction(routes["/api/v1/ingest/drain"])
    assert not inspect.iscoroutinefunction(routes["/api/v1/ingest/stats"])
