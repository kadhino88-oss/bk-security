import json

from fastapi.testclient import TestClient

import bk_security.api.app as api_module
from bk_security.auth.security import issue_token
from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.deployment import DeploymentContext
from bk_security.events.models import SecurityEvent
from bk_security.events.sanitization import REDACTED, sanitize_sensitive_payload


def test_sensitive_payload_sanitizer_redacts_nested_values_and_inline_credentials():
    source = {
        "dst_port": 4444,
        "token_count": 3,
        "password": "payload-password",
        "nested": [{"access_token": "nested-token", "status": "preserved"}],
        "url": "https://example.test/?access_token=url-token&keep=visible",
        "message": "Authorization: Bearer inline-token",
        "private_key_pem": "raw-private-key",
        "session_key": "session-key-value",
        "pem_blob": "-----begin rsa private key-----\nprivate material\n-----end rsa private key-----",
        "cmdline": ["agent", "--api-key", "argument-key", "--session-key=session-value", "--mode=scan"],
    }

    sanitized = sanitize_sensitive_payload(source)

    assert sanitized["dst_port"] == 4444
    assert sanitized["token_count"] == 3
    assert sanitized["password"] == REDACTED
    assert sanitized["private_key_pem"] == REDACTED
    assert sanitized["session_key"] == REDACTED
    assert sanitized["pem_blob"] == REDACTED
    assert sanitized["nested"] == [{"access_token": REDACTED, "status": "preserved"}]
    assert sanitized["url"] == "https://example.test/?access_token=<redacted>&keep=visible"
    assert sanitized["cmdline"] == [
        "agent", "--api-key=<redacted>", "<redacted>",
        "--session-key=<redacted>", "--mode=scan",
    ]
    assert "inline-token" not in json.dumps(sanitized)
    assert source["password"] == "payload-password"


def test_core_ingestion_redacts_sensitive_data_before_alerts_and_database(tmp_path):
    store = SecurityStore(str(tmp_path / "redaction.db"))
    core = SecurityCore(store)
    secret_values = [
        "payload-password", "nested-token", "url-token", "inline-token",
        "argument-key", "inline-key", "header-token", "enrichment-key",
    ]
    event = SecurityEvent(
        event_type="network.packet", source="redaction-test", host_id="host-redaction",
        data={
            "dst_ip": "203.0.113.12", "dst_port": 4444, "process_name": "powershell.exe",
            "password": secret_values[0],
            "nested": [{"access_token": secret_values[1], "status": "preserved"}],
            "url": f"https://example.test/?access_token={secret_values[2]}&keep=visible",
            "message": f"Authorization: Bearer {secret_values[3]}",
        },
        process={"name": "powershell.exe", "cmdline": [
            "powershell.exe", "--api-key", secret_values[4], "--password=" + secret_values[5],
            "--mode=scan",
        ]},
        network={"headers": {"Authorization": "Bearer " + secret_values[6]}},
        enrichment={"metadata": {"api_key": secret_values[7]}},
    )

    core.ingest(event)
    stored = store.get_event(event.event_id)
    combined = json.dumps({"event": event.to_dict(), "stored": stored, "alerts": [a.to_dict() for a in core.alerts]})

    assert all(value not in combined for value in secret_values)
    assert event.data["dst_port"] == 4444
    assert event.process["cmdline"][-1] == "--mode=scan"
    assert stored["data"]["password"] == REDACTED
    assert stored["network"]["headers"]["Authorization"] == REDACTED
    assert stored["enrichment"]["metadata"]["api_key"] == REDACTED
    store.close()


def test_api_returns_only_sanitized_event_payload(monkeypatch, tmp_path):
    context = DeploymentContext()
    store = SecurityStore(str(tmp_path / "api-redaction.db"), deployment_context=context)
    core = SecurityCore(store)
    monkeypatch.setattr(api_module, "core", core)
    monkeypatch.setattr(api_module, "deployment_context", context)
    token = issue_token("analyst", "analyst", deployment_context=context)

    client = TestClient(api_module.app)
    response = client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "event_type": "network.connection", "source": "api-redaction-test",
            "host_id": "host-api-redaction", "data": {"password": "api-password", "port": 443},
            "network": {"headers": {"Authorization": "Bearer api-header-token"}},
        },
    )

    assert response.status_code == 200
    assert "api-password" not in response.text
    assert "api-header-token" not in response.text
    assert response.json()["event"]["data"]["password"] == REDACTED
    store.close()
