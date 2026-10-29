from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import asyncio
import time

from fastapi import HTTPException
from pydantic import ValidationError
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.websockets import WebSocketDisconnect

import bk_security.api.app as api_module
from bk_security.api.app import EventIn, LOGIN_LIMITER, Login, login
from bk_security.api.hardening import RequestSizeLimitMiddleware, SecurityHeadersMiddleware, SlidingWindowRateLimiter
from bk_security.auth.security import AuthError, _secret, issue_token, verify_token
from bk_security.database import SecurityStore
from bk_security.deployment import DeploymentContext


def test_sliding_window_limiter_bounds_keys_and_resets_successful_login():
    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=30, max_keys=2)
    assert limiter.allow("client-a")[0]
    assert limiter.allow("client-a")[0]
    allowed, retry_after = limiter.allow("client-a")
    assert allowed is False and 0 < retry_after <= 30
    limiter.reset("client-a")
    assert limiter.allow("client-a")[0]
    limiter.allow("client-b")
    limiter.allow("client-c")
    assert limiter.tracked_keys <= 2


def _request(client_ip: str) -> Request:
    return Request({
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/api/v1/auth/login",
        "raw_path": b"/api/v1/auth/login", "query_string": b"", "headers": [],
        "server": ("127.0.0.1", 8000), "client": (client_ip, 12345),
    })


def test_api_login_rate_limit_blocks_repeated_invalid_credentials():
    client_ip = "198.51.100.234"

    async def scenario():
        for _ in range(LOGIN_LIMITER.limit):
            with pytest.raises(HTTPException) as invalid:
                await login(Login(username="unknown-user", password="invalid"), _request(client_ip))
            assert invalid.value.status_code == 401
        with pytest.raises(HTTPException) as limited:
            await login(Login(username="unknown-user", password="invalid"), _request(client_ip))
        assert limited.value.status_code == 429
        assert int(limited.value.headers["Retry-After"]) >= 1

    asyncio.run(scenario())


def test_event_schema_rejects_unknown_types_and_oversized_data():
    with pytest.raises(ValidationError):
        EventIn(event_type="unknown.event", source="test", host_id="h1")
    with pytest.raises(ValidationError):
        EventIn(
            event_type="network.packet", source="test", host_id="h1",
            data={"payload": "x" * 66_000},
        )


def test_production_auth_secret_requires_minimum_length(monkeypatch):
    monkeypatch.setenv("BK_SECURITY_ENV", "production")
    monkeypatch.setenv("BK_SECURITY_AUTH_SECRET", "short-secret")
    with pytest.raises(RuntimeError, match="32 UTF-8 bytes"):
        _secret()
    monkeypatch.setenv("BK_SECURITY_AUTH_SECRET", "s" * 32)
    assert len(_secret()) == 32


def test_authentication_tokens_are_bound_to_a_dedicated_customer_deployment(monkeypatch):
    first = DeploymentContext(
        profile="dedicated_customer", customer_ref="customer-one",
        deployment_id="b63f5975-1ad9-4cdd-b65c-8ee87c05b24b", region="eu-ch",
    )
    another_deployment = DeploymentContext(
        profile="dedicated_customer", customer_ref="customer-two",
        deployment_id="be7ba020-8dd2-4a9f-b552-6f9c8bc9c0bc", region="eu-ch",
    )
    token = issue_token("analyst", "analyst", deployment_context=first)
    assert verify_token(token, deployment_context=first).username == "analyst"
    with pytest.raises(AuthError, match="deployment scope mismatch"):
        verify_token(token, deployment_context=another_deployment)
    with pytest.raises(AuthError, match="cannot be used in local V1"):
        verify_token(token, deployment_context=DeploymentContext())

    local_token = issue_token("analyst", "analyst", deployment_context=DeploymentContext())
    with pytest.raises(AuthError, match="deployment scope mismatch"):
        verify_token(local_token, deployment_context=first)

    monkeypatch.setattr(api_module, "deployment_context", first)
    token_from_other_plane = issue_token(
        "analyst", "analyst", deployment_context=another_deployment,
    )
    with pytest.raises(HTTPException) as denied:
        api_module.principal(f"Bearer {token_from_other_plane}")
    assert denied.value.status_code == 401


def test_login_issues_a_token_scoped_to_the_dedicated_process(monkeypatch):
    context = DeploymentContext(
        profile="dedicated_customer", customer_ref="customer-one",
        deployment_id="b63f5975-1ad9-4cdd-b65c-8ee87c05b24b", region="eu-ch",
    )
    monkeypatch.setattr(api_module, "deployment_context", context)
    monkeypatch.setitem(api_module.USERS, "analyst", ("test-password", "analyst"))
    monkeypatch.setattr(api_module.core.store, "register_auth_session", lambda *args, **kwargs: None)
    monkeypatch.setattr(api_module.core.store, "audit", lambda *args, **kwargs: None)

    response = asyncio.run(login(
        Login(username="analyst", password="test-password"),
        _request("198.51.100.235"),
    ))
    principal = verify_token(response["access_token"], deployment_context=context)
    assert principal.username == "analyst"
    assert principal.role == "analyst"
    assert principal.token_id


def test_dedicated_login_session_is_persisted_and_logout_revokes_it(monkeypatch, tmp_path):
    context = DeploymentContext(
        profile="dedicated_customer", customer_ref="customer-one",
        deployment_id="b63f5975-1ad9-4cdd-b65c-8ee87c05b24b", region="eu-ch",
    )
    database_path = str(tmp_path / "customer-one.db")
    store = SecurityStore(path=database_path, deployment_context=context)
    monkeypatch.setattr(api_module.core, "store", store)
    monkeypatch.setattr(api_module, "deployment_context", context)
    monkeypatch.setitem(api_module.USERS, "analyst", ("test-password", "analyst"))

    response = asyncio.run(login(
        Login(username="analyst", password="test-password"),
        _request("198.51.100.236"),
    ))
    token = response["access_token"]
    session = verify_token(token, deployment_context=context)
    assert session.token_id
    assert store.auth_session_status(session.token_id) == "active"
    assert api_module.principal(f"Bearer {token}").username == "analyst"

    result = asyncio.run(api_module.logout(session))
    assert result == {"status": "logged_out", "revoked": True}
    assert store.auth_session_status(session.token_id) == "revoked"
    with pytest.raises(HTTPException) as denied:
        api_module.principal(f"Bearer {token}")
    assert denied.value.status_code == 401
    assert any(entry["action"] == "logout" for entry in store.list_audit())
    store.close()
    reopened = SecurityStore(path=database_path, deployment_context=context)
    assert reopened.auth_session_status(session.token_id) == "revoked"
    reopened.close()


def test_admin_can_list_and_revoke_all_active_user_sessions_via_api(monkeypatch, tmp_path):
    context = DeploymentContext(
        profile="dedicated_customer", customer_ref="customer-one",
        deployment_id="b63f5975-1ad9-4cdd-b65c-8ee87c05b24b", region="eu-ch",
    )
    store = SecurityStore(path=str(tmp_path / "customer-one.db"), deployment_context=context)
    monkeypatch.setattr(api_module, "deployment_context", context)
    monkeypatch.setattr(api_module.core, "store", store)
    now = int(time.time())
    analyst_tokens = [issue_token("analyst", "analyst", deployment_context=context) for _ in range(2)]
    viewer_token = issue_token("viewer", "viewer", deployment_context=context)
    admin_token = issue_token("admin", "admin", deployment_context=context)
    for token in analyst_tokens:
        session = verify_token(token, deployment_context=context)
        store.register_auth_session(session.token_id, session.username, session.expires_at)
    for token in (viewer_token, admin_token):
        session = verify_token(token, deployment_context=context)
        store.register_auth_session(session.token_id, session.username, session.expires_at)

    client = TestClient(api_module.app)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_tokens[0]}"}
    listed = client.get("/api/v1/auth/sessions", headers=admin_headers)
    assert listed.status_code == 200
    sessions = listed.json()["sessions"]
    assert [(item["username"], item["active_sessions"]) for item in sessions] == [
        ("admin", 1), ("analyst", 2), ("viewer", 1),
    ]
    assert all(item["latest_expiration"] > now for item in sessions)
    assert "token_id" not in listed.text and "jti" not in listed.text
    assert client.get("/api/v1/auth/sessions", headers=analyst_headers).status_code == 403
    assert client.post("/api/v1/auth/sessions/analyst/revoke", headers=analyst_headers).status_code == 403

    with client.websocket_connect(f"/ws/soc?token={analyst_tokens[0]}") as websocket:
        assert websocket.receive_json()["type"] == "soc.snapshot"
        revoked = client.post("/api/v1/auth/sessions/analyst/revoke", headers=admin_headers)
        assert revoked.status_code == 200
        assert revoked.json() == {"username": "analyst", "revoked_sessions": 2}
        assert client.post("/api/v1/auth/sessions/analyst/revoke", headers=admin_headers).json()["revoked_sessions"] == 0
        assert all(store.auth_session_status(verify_token(token, deployment_context=context).token_id) == "revoked"
                   for token in analyst_tokens)
        assert store.auth_session_status(verify_token(viewer_token, deployment_context=context).token_id) == "active"
        assert api_module.principal(f"Bearer {admin_token}").username == "admin"
        assert client.get("/api/v1/auth/sessions", headers=analyst_headers).status_code == 401
        with pytest.raises(WebSocketDisconnect) as disconnected:
            websocket.receive_json()
        assert disconnected.value.code == 1008
    audit = store.list_audit(limit=10)
    assert any(item["action"] == "auth_sessions_revoked" and item["data"]["sessions_revoked"] == 2
               for item in audit)
    store.close()


def test_request_size_middleware_rejects_content_length_before_route():
    downstream = False
    sent = []

    async def app(scope, receive, send):
        nonlocal downstream
        downstream = True

    async def receive():
        raise AssertionError("An oversized declared body should be rejected without reading it")

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "method": "POST",
        "headers": [(b"content-length", b"1025")],
    }
    asyncio.run(RequestSizeLimitMiddleware(app, 1024)(scope, receive, send))
    assert downstream is False
    assert sent[0]["status"] == 413


def test_request_size_middleware_rejects_chunked_body_over_limit():
    sent = []
    messages = iter([
        {"type": "http.request", "body": b"a" * 600, "more_body": True},
        {"type": "http.request", "body": b"b" * 500, "more_body": False},
    ])

    async def app(scope, receive, send):
        raise AssertionError("An oversized chunked body must not reach the route")

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "headers": []}
    asyncio.run(RequestSizeLimitMiddleware(app, 1024)(scope, receive, send))
    assert sent[0]["status"] == 413


def test_security_headers_middleware_adds_browser_isolation_headers():
    sent = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(SecurityHeadersMiddleware(app)({"type": "http"}, receive, send))
    headers = dict(sent[0]["headers"])
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert headers[b"x-frame-options"] == b"DENY"
    assert headers[b"referrer-policy"] == b"no-referrer"
    assert headers[b"x-permitted-cross-domain-policies"] == b"none"
    assert b"frame-ancestors 'none'" in headers[b"content-security-policy"]


def test_security_headers_include_csp_and_cross_domain_policy():
    source = (ROOT / 'bk_security' / 'api' / 'hardening.py').read_text(encoding='utf-8')
    assert "content-security-policy" in source
    assert "frame-ancestors 'none'" in source
    assert "x-permitted-cross-domain-policies" in source
