from __future__ import annotations

from uuid import uuid4

import pytest

from bk_security.database import SecurityStore
from bk_security.deployment import DeploymentContext
from bk_security.events.models import SecurityAlert, SecurityEvent
from bk_security.incidents.models import SecurityIncident
from bk_security.monthly_audit import build_monthly_audit


def _context(customer_ref="customer-42", region="eu-ch", deployment_id=None):
    return DeploymentContext(
        profile="dedicated_customer",
        customer_ref=customer_ref,
        deployment_id=deployment_id or str(uuid4()),
        region=region,
    )


def test_local_profile_rejects_ignored_dedicated_identity_settings():
    assert DeploymentContext.from_environment({}).profile == "local_v1"
    with pytest.raises(ValueError, match="require BK_SECURITY_DEPLOYMENT_PROFILE"):
        DeploymentContext.from_environment({"BK_SECURITY_CUSTOMER_REF": "customer-42"})


def test_dedicated_profile_requires_opaque_customer_region_and_uuid():
    with pytest.raises(ValueError, match="missing required identity settings"):
        DeploymentContext.from_environment({"BK_SECURITY_DEPLOYMENT_PROFILE": "dedicated_customer"})
    context = DeploymentContext.from_environment({
        "BK_SECURITY_DEPLOYMENT_PROFILE": "dedicated_customer",
        "BK_SECURITY_CUSTOMER_REF": "customer-42",
        "BK_SECURITY_DEPLOYMENT_ID": str(uuid4()).upper(),
        "BK_SECURITY_REGION": "EU-CH",
    })
    assert context.customer_ref == "customer-42"
    assert context.region == "eu-ch"
    assert context.reporting_scope()["region_attestation"] == "not_verified"
    for values in (
        {"BK_SECURITY_CUSTOMER_REF": "Customer Name"},
        {"BK_SECURITY_DEPLOYMENT_ID": "not-a-uuid"},
        {"BK_SECURITY_REGION": "eu/ch"},
    ):
        settings = {
            "BK_SECURITY_DEPLOYMENT_PROFILE": "dedicated_customer",
            "BK_SECURITY_CUSTOMER_REF": "customer-42",
            "BK_SECURITY_DEPLOYMENT_ID": str(uuid4()),
            "BK_SECURITY_REGION": "eu-ch",
            **values,
        }
        with pytest.raises(ValueError):
            DeploymentContext.from_environment(settings)


def test_dedicated_deployment_rejects_ephemeral_in_memory_database():
    with pytest.raises(ValueError, match="persistent SQLite database file"):
        SecurityStore(":memory:", deployment_context=_context())


def test_database_is_bound_to_one_exact_customer_deployment(tmp_path):
    database = str(tmp_path / "dedicated.db")
    context = _context()
    first = SecurityStore(database, deployment_context=context)
    first.close()

    restarted = SecurityStore(database, deployment_context=context)
    assert restarted.deployment_context.reporting_scope()["scope_enforcement"] == "database_startup_binding_only"
    restarted.close()

    with pytest.raises(RuntimeError, match="different customer deployment"):
        SecurityStore(database, deployment_context=_context(customer_ref="other-customer"))
    with pytest.raises(RuntimeError, match="different customer deployment"):
        SecurityStore(database, deployment_context=_context(deployment_id=str(uuid4())))


def test_store_inherits_configured_deployment_identity_without_explicit_context(tmp_path, monkeypatch):
    database = str(tmp_path / "environment-bound.db")
    deployment_id = str(uuid4())
    monkeypatch.setenv("BK_SECURITY_DEPLOYMENT_PROFILE", "dedicated_customer")
    monkeypatch.setenv("BK_SECURITY_CUSTOMER_REF", "customer-42")
    monkeypatch.setenv("BK_SECURITY_DEPLOYMENT_ID", deployment_id)
    monkeypatch.setenv("BK_SECURITY_REGION", "eu-ch")

    store = SecurityStore(database)
    try:
        assert store.deployment_context.database_binding() == (
            "dedicated_customer", "customer-42", deployment_id, "eu-ch"
        )
    finally:
        store.close()

    monkeypatch.setenv("BK_SECURITY_CUSTOMER_REF", "another-customer")
    with pytest.raises(RuntimeError, match="different customer deployment"):
        SecurityStore(database)


def test_explicit_store_context_cannot_override_process_customer_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("BK_SECURITY_DEPLOYMENT_PROFILE", "dedicated_customer")
    monkeypatch.setenv("BK_SECURITY_CUSTOMER_REF", "customer-one")
    monkeypatch.setenv("BK_SECURITY_DEPLOYMENT_ID", "b63f5975-1ad9-4cdd-b65c-8ee87c05b24b")
    monkeypatch.setenv("BK_SECURITY_REGION", "eu-ch")
    with pytest.raises(ValueError, match="cannot override the process"):
        SecurityStore(
            str(tmp_path / "wrong-context.db"),
            deployment_context=_context(customer_ref="customer-two"),
        )


def test_store_rechecks_identity_when_database_path_changes_after_startup(tmp_path):
    first_database = str(tmp_path / "first-customer.db")
    second_database = str(tmp_path / "second-customer.db")
    first = SecurityStore(first_database, deployment_context=_context(customer_ref="customer-one"))
    second = SecurityStore(second_database, deployment_context=_context(customer_ref="customer-two"))
    try:
        first.path = second_database
        with pytest.raises(RuntimeError, match="different customer deployment"):
            first.list_events()
    finally:
        first.path = first_database
        first.close()
        second.close()


def test_two_dedicated_local_databases_keep_security_records_separate(tmp_path):
    first = SecurityStore(
        str(tmp_path / "customer-one.db"),
        deployment_context=_context(customer_ref="customer-one"),
    )
    second = SecurityStore(
        str(tmp_path / "customer-two.db"),
        deployment_context=_context(customer_ref="customer-two"),
    )
    stores = ((first, "customer-one"), (second, "customer-two"))
    try:
        for store, customer in stores:
            event = SecurityEvent(
                event_type="network.packet", source="isolation-test",
                host_id=f"host-{customer}", data={"marker": customer},
            )
            store.persist_ingest(event)
            store.save_alert(SecurityAlert(
                alert_type="SUSPICIOUS_NETWORK_BEHAVIOR", title=f"Alert {customer}",
                severity="medium", host_id=f"host-{customer}", confidence=.8,
                risk_score=55, reason="isolation-test",
            ))
            store.save_incident(SecurityIncident(
                host_id=f"host-{customer}", title=f"Incident {customer}",
                severity="medium", risk_score=55,
            ))
            store.save_response_action({
                "action_id": f"response-{customer}", "status": "dry_run",
                "action": "alert", "dry_run": True,
            })
            store.audit("test-operator", f"audit-{customer}")

        for store, own_customer in stores:
            foreign_customer = "customer-two" if own_customer == "customer-one" else "customer-one"
            assert [event["data"]["marker"] for event in store.list_events()] == [own_customer]
            assert [alert["title"] for alert in store.list_alerts()] == [f"Alert {own_customer}"]
            assert [incident["title"] for incident in store.list_incidents()] == [f"Incident {own_customer}"]
            assert [action["action_id"] for action in store.list_response_actions()] == [f"response-{own_customer}"]
            assert [entry["action"] for entry in store.list_audit()] == [f"audit-{own_customer}"]
            assert foreign_customer not in str(store.list_events() + store.list_alerts() + store.list_incidents())
    finally:
        first.close()
        second.close()


def test_dedicated_deployment_refuses_to_claim_an_unbound_populated_database(tmp_path):
    database = str(tmp_path / "legacy.db")
    legacy = SecurityStore(database)
    legacy.persist_ingest(SecurityEvent(event_type="system.process", source="test", host_id="host-1"))
    legacy.close()

    with pytest.raises(RuntimeError, match="fresh or empty SQLite database"):
        SecurityStore(database, deployment_context=_context())


def test_monthly_report_identifies_declared_scope_without_claiming_region_attestation(tmp_path):
    store = SecurityStore(
        str(tmp_path / "report.db"), deployment_context=_context()
    )
    try:
        report = build_monthly_audit(store, "2026-10")
        assert report["scope"]["profile"] == "dedicated_customer"
        assert report["scope"]["customer_ref"] == "customer-42"
        assert report["scope"]["region_attestation"] == "not_verified"
        assert report["scope"]["scope_enforcement"] == "database_startup_binding_only"
    finally:
        store.close()
