"""Exercise authenticated BK Security persistence across two API processes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
import uuid


ROOT = Path(__file__).resolve().parents[1]
STARTUP_TIMEOUT_SECONDS = 60


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _request(base_url: str, path: str, *, method: str = "GET", payload=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(base_url + path, data=body, headers=headers, method=method)
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _text(base_url: str, path: str) -> str:
    with urlopen(base_url + path, timeout=20) as response:
        if response.status != 200:
            raise AssertionError(f"Dashboard resource returned HTTP {response.status}: {path}")
        return response.read().decode("utf-8")


def _served_asset_path(index_html: str, extension: str) -> str:
    if extension == ".js":
        pattern = r"<script\b[^>]*\bsrc=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']"
    elif extension == ".css":
        pattern = r"<link\b[^>]*\bhref=[\"']([^\"']+\.css(?:\?[^\"']*)?)[\"']"
    else:
        raise ValueError("Only JavaScript and CSS dashboard assets are supported.")
    match = re.search(pattern, index_html, flags=re.IGNORECASE)
    if not match:
        raise AssertionError(f"Dashboard index does not reference a {extension} asset")
    reference = urlsplit(match.group(1))
    if reference.scheme or reference.netloc:
        raise AssertionError("Dashboard E2E assets must be served locally")
    path = "/" + reference.path.lstrip("./")
    return path + (("?" + reference.query) if reference.query else "")


def _start_server(port: int, env: dict[str, str]) -> subprocess.Popen:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "bk_security.api.app:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"BK Security API exited during startup (code {process.returncode})")
        try:
            _request(base_url, "/health")
            return process
        except (URLError, TimeoutError, ConnectionError, OSError):
            time.sleep(0.2)
    process.terminate()
    process.wait(timeout=5)
    raise TimeoutError(f"BK Security API did not become healthy within {STARTUP_TIMEOUT_SECONDS} seconds")


def _stop_server(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _login(base_url: str, username: str = "admin", password: str = "e2e-admin-secret") -> str:
    response = _request(
        base_url,
        "/api/v1/auth/login",
        method="POST",
        payload={"username": username, "password": password},
    )
    return response["access_token"]


def main() -> None:
    test_data = Path(os.getenv("BK_SECURITY_E2E_DATA_DIR", str(ROOT / "test-data")))
    test_data.mkdir(exist_ok=True)
    database = test_data / f"restart-e2e-{uuid.uuid4().hex}.sqlite3"
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    host_id = f"host-restart-e2e-{uuid.uuid4().hex[:8]}"
    env = os.environ.copy()
    env.update({
        "BK_SECURITY_DB": str(database),
        "BK_SECURITY_ADMIN_PASSWORD": "e2e-admin-secret",
        "BK_SECURITY_RESPONDER_PASSWORD": "e2e-responder-secret",
        "BK_SECURITY_AUTH_SECRET": uuid.uuid4().hex + uuid.uuid4().hex,
        "BK_SECURITY_CAPTURE_MODE": "simulation",
    })

    server = _start_server(port, env)
    try:
        dashboard = _text(base_url, "/")
        dashboard_js = _text(base_url, _served_asset_path(dashboard, ".js"))
        dashboard_css = _text(base_url, _served_asset_path(dashboard, ".css"))
        if '<div id="root"></div>' not in dashboard or "Security Operations Center" not in dashboard_js or ".incident-row" not in dashboard_css:
            raise AssertionError("The served SOC dashboard shell/assets do not expose the expected V1 panels")
        token = _login(base_url)
        dns = _request(base_url, "/api/v1/events", method="POST", token=token, payload={
            "event_type": "network.dns", "source": "restart-e2e", "host_id": host_id,
            "data": {"domain": "restart-e2e.example", "answers": ["203.0.113.77"]},
        })["event"]
        first_packet = _request(base_url, "/api/v1/events", method="POST", token=token, payload={
            "event_type": "network.packet", "source": "restart-e2e", "host_id": host_id,
            "data": {"dst_ip": "203.0.113.77", "dst_port": 4444, "process_name": "powershell.exe"},
        })
        if not first_packet["alerts"]:
            raise AssertionError("The suspicious packet did not create an alert")
        if first_packet["event"]["data"].get("domain") != "restart-e2e.example":
            raise AssertionError("DNS address context did not enrich the packet")
        alert_id = first_packet["alerts"][0]["alert_id"]
        investigation = _request(base_url, f"/api/v1/alerts/{alert_id}/investigate", method="POST", token=token)
        if (
            not investigation.get("summary")
            or not investigation.get("findings")
            or investigation.get("valid") is not True
            or investigation.get("source_alert_id") != alert_id
            or not investigation.get("source_event_ids")
            or not investigation.get("evidence")
        ):
            raise AssertionError("AI SOC investigation returned no evidence-based findings")
        plan = _request(base_url, "/api/v1/response/plan", method="POST", token=token, payload={
            "action": "block", "target": "203.0.113.77", "reason": "restart persistence validation", "dry_run": True,
        })
        if not plan.get("requires_approval") or not plan.get("dry_run"):
            raise AssertionError("Response policy did not enforce approval and dry-run planning")
        incident_before = _request(base_url, "/api/v1/incidents", token=token)["incidents"]
        if not incident_before:
            raise AssertionError("The suspicious packet did not create an incident")
        incident_id = incident_before[0]["incident_id"]
        incident_investigation = _request(
            base_url, f"/api/v1/incidents/{incident_id}/investigate", method="GET", token=token,
        )
        if (
            incident_investigation.get("traceability", {}).get("incident_id") != incident_id
            or not incident_investigation.get("investigations")
            or incident_id not in incident_investigation["investigations"][0].get("source_incident_ids", [])
        ):
            raise AssertionError("AI SOC incident investigation lost incident provenance")
        if "T1059" not in incident_before[0].get("mitre_techniques", []):
            raise AssertionError("MITRE context did not reach the consolidated incident")
        viewer_token = _request(base_url, "/api/v1/auth/login", method="POST", payload={
            "username": "viewer", "password": "viewer-dev-only",
        })["access_token"]
        try:
            _request(base_url, f"/api/v1/incidents/{incident_id}/status", method="PATCH",
                     token=viewer_token, payload={"status": "INVESTIGATING"})
        except HTTPError as exc:
            if exc.code != 403:
                raise
        else:
            raise AssertionError("Viewer role unexpectedly changed incident status")
        transitioned = _request(base_url, f"/api/v1/incidents/{incident_id}/status", method="PATCH", token=token,
                               payload={"status": "INVESTIGATING"})["incident"]
        if transitioned["status"] != "INVESTIGATING":
            raise AssertionError("Incident lifecycle did not accept NEW -> INVESTIGATING")

        responder_token = _login(base_url, "responder", "e2e-responder-secret")
        response = _request(base_url, "/api/v1/response/execute", method="POST", token=responder_token, payload={
            "plan_id": plan["plan_id"], "dry_run": True,
        })
        if response["status"] != "dry_run":
            raise AssertionError("The response execution did not remain in dry-run mode")
        response_id = response["execution_id"]
    finally:
        _stop_server(server)

    server = _start_server(port, env)
    try:
        token = _login(base_url)
        events = _request(
            base_url,
            "/api/v1/events?" + urlencode({"event_id": dns["event_id"]}),
            token=token,
        )["events"]
        alerts = _request(base_url, "/api/v1/alerts", token=token)["alerts"]
        incidents = _request(base_url, "/api/v1/incidents", token=token)["incidents"]
        hosts = _request(base_url, "/api/v1/hosts", token=token)["hosts"]
        actions = _request(base_url, "/api/v1/response/actions", token=token)["actions"]
        if dns["event_id"] not in {event["event_id"] for event in events}:
            raise AssertionError("Persisted DNS event missing after restart")
        if not alerts or not incidents or incident_id not in {item["incident_id"] for item in incidents}:
            raise AssertionError("Persisted alert or incident missing after restart")
        restored_incident = next(item for item in incidents if item["incident_id"] == incident_id)
        if restored_incident["status"] != "INVESTIGATING":
            raise AssertionError("Incident lifecycle status was not restored after restart")
        if host_id not in {item["host_id"] for item in hosts}:
            raise AssertionError("Host event history missing after restart")
        if response_id not in {item["execution_id"] for item in actions}:
            raise AssertionError("Persisted response action missing after restart")

        second_packet = _request(base_url, "/api/v1/events", method="POST", token=token, payload={
            "event_type": "network.packet", "source": "restart-e2e", "host_id": host_id,
            "data": {"dst_ip": "203.0.113.77", "dst_port": 4444, "process_name": "powershell.exe"},
        })["event"]
        if second_packet["data"].get("domain") != "restart-e2e.example":
            raise AssertionError("Restored DNS context did not enrich the post-restart packet")
        if dns["event_id"] not in second_packet["data"].get("related_event_ids", []):
            raise AssertionError("Restored DNS event was not linked as packet evidence")
        incident_after = _request(base_url, "/api/v1/incidents", token=token)["incidents"]
        if len(incident_after) != len(incidents) or incident_after[0]["incident_id"] != incident_id:
            raise AssertionError("The post-restart signal did not rejoin the active incident")

        from websockets.sync.client import connect

        ws_url = f"ws://127.0.0.1:{port}/ws/soc?{urlencode({'token': token})}"
        with connect(ws_url, open_timeout=5) as websocket:
            snapshot = json.loads(websocket.recv(timeout=5))
        if snapshot.get("type") != "soc.snapshot" or incident_id not in {
            item["incident_id"] for item in snapshot.get("incidents", [])
        }:
            raise AssertionError("SOC WebSocket did not publish the restored incident")

        resolved = _request(base_url, f"/api/v1/incidents/{incident_id}/status", method="PATCH", token=token,
                            payload={"status": "RESOLVED"})["incident"]
        if resolved["status"] != "RESOLVED":
            raise AssertionError("Incident lifecycle did not accept INVESTIGATING -> RESOLVED")
        new_packet = _request(base_url, "/api/v1/events", method="POST", token=token, payload={
            "event_type": "network.packet", "source": "restart-e2e", "host_id": host_id,
            "data": {"dst_ip": "203.0.113.77", "dst_port": 4444, "process_name": "powershell.exe"},
        })
        new_incident_id = new_packet["alerts"][0]["correlation_id"]
        if new_incident_id == incident_id:
            raise AssertionError("A new signal was incorrectly attached to a resolved incident")

        capabilities = _request(base_url, "/api/v1/capture/capabilities", token=token)
        if not capabilities.get("interfaces") or "MULTI_SIGNAL_ATTACK" not in capabilities.get("simulation_scenarios", []):
            raise AssertionError("Capture capabilities did not expose interfaces and simulation scenarios")
        _request(base_url, "/api/v1/sensors/endpoint_process/start", method="POST", token=token)
        process_deadline = time.monotonic() + 20
        process_snapshot = {"processes": [], "sensor": {"running": False}}
        while time.monotonic() < process_deadline:
            process_snapshot = _request(base_url, "/api/v1/processes", token=token)
            if process_snapshot.get("processes") and not process_snapshot.get("sensor", {}).get("initializing"):
                break
            time.sleep(0.2)
        if not process_snapshot.get("processes") or not process_snapshot["sensor"].get("running"):
            raise AssertionError("Periodic endpoint process collection did not produce a process view")
        _request(base_url, "/api/v1/sensors/endpoint_process/stop", method="POST", token=token)
        _request(base_url, "/api/v1/sensors/socket_attribution/start", method="POST", token=token)
        socket_deadline = time.monotonic() + 20
        sockets = {"connections": [], "sensor": {"initializing": True}}
        while time.monotonic() < socket_deadline:
            sockets = _request(base_url, "/api/v1/processes/sockets", token=token)
            if not sockets.get("sensor", {}).get("initializing"):
                break
            time.sleep(0.2)
        if not isinstance(sockets.get("connections"), list):
            raise AssertionError("Socket attribution endpoint did not return its current connection view")
        _request(base_url, "/api/v1/sensors/socket_attribution/stop", method="POST", token=token)
        for path in ("/api/v1/dns/events", "/api/v1/mitre", "/api/v1/threat-intelligence/matches", "/api/v1/settings"):
            _request(base_url, path, token=token)

        # The desktop lifespan may already own the default simulation sensor.
        # Stop it before asking the API to select a named deterministic case.
        _request(base_url, "/api/v1/capture/stop", method="POST", token=token)
        capture = _request(base_url, "/api/v1/capture/start", method="POST", token=token, payload={
            "mode": "simulation", "scenario": "MULTI_SIGNAL_ATTACK",
        })
        if capture.get("sensor", {}).get("scenario") != "MULTI_SIGNAL_ATTACK":
            raise AssertionError("Simulation capture did not select the requested scenario")
        simulated_events = _request(base_url, "/api/v1/events", token=token)["events"]
        if not any(item.get("event_type") == "network.packet" and item.get("source") == "bk_network_capture"
                   and item.get("data", {}).get("simulation") for item in simulated_events):
            raise AssertionError("Simulation packet did not reach the normalized event API")
        _request(base_url, "/api/v1/capture/stop", method="POST", token=token)
    finally:
        _stop_server(server)

    print("PASS: API restart, incident lifecycle, process/socket sensors, all SOC views, simulation capture, DNS/correlation and WebSocket")


if __name__ == "__main__":
    main()
