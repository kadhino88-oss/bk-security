from fastapi.testclient import TestClient

from bk_security.api.app import app


def test_internal_shutdown_requires_a_loopback_peer_and_runtime_token(monkeypatch):
    monkeypatch.setenv("BK_SECURITY_INTERNAL_SHUTDOWN_TOKEN", "test-only-runtime-token")
    calls = []
    monkeypatch.setattr(app.state, "request_shutdown", lambda: calls.append("shutdown"), raising=False)
    local = TestClient(app, client=("127.0.0.1", 12345))
    denied = local.post("/internal/shutdown")
    assert denied.status_code == 403
    accepted = local.post(
        "/internal/shutdown",
        headers={"X-BK-Internal-Shutdown": "test-only-runtime-token"},
    )
    assert accepted.status_code == 200
    assert accepted.json() == {"status": "shutdown_requested"}
    assert calls == ["shutdown"]

    remote = TestClient(app, client=("198.51.100.8", 12345))
    assert remote.post(
        "/internal/shutdown",
        headers={"X-BK-Internal-Shutdown": "test-only-runtime-token"},
    ).status_code == 403
