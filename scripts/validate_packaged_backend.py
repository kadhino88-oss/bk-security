from __future__ import annotations

import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HTTP_REQUEST_TIMEOUT_SECONDS = 30


def _request(url: str, *, method: str = "GET", payload: dict | None = None, token: str = "", shutdown: str = ""):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if shutdown:
        headers["X-BK-Internal-Shutdown"] = shutdown
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=HTTP_REQUEST_TIMEOUT_SECONDS) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def _start(executable: Path, env: dict[str, str], base_url: str, manifest: dict) -> subprocess.Popen:
    process = subprocess.Popen(
        [str(executable)],
        cwd=executable.parent,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        deadline = time.monotonic() + 60
        last_status = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"Packaged backend exited during startup (code {process.returncode}).")
            try:
                status, body = _request(f"{base_url}/health")
                last_status = status
                if status == 200:
                    health = json.loads(body)
                    if (
                        health.get("product") != "BK Security"
                        or health.get("version") != manifest["version"]
                        or health.get("build_id") != manifest["build_id"]
                    ):
                        raise RuntimeError("Packaged backend health identity differs from its release manifest.")
                    return process
            except (URLError, TimeoutError, json.JSONDecodeError):
                pass
            time.sleep(0.25)
        raise RuntimeError(f"Packaged backend readiness timed out (last HTTP status: {last_status}).")
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        raise


def _login_and_check_dashboard(base_url: str, password: str, expected_build_id: str) -> None:
    status, body = _request(
        f"{base_url}/api/v1/auth/login",
        method="POST",
        payload={"username": "admin", "password": password},
    )
    if status != 200:
        raise RuntimeError("Packaged backend refused its temporary production test credentials.")
    token = json.loads(body)["access_token"]
    status, _ = _request(f"{base_url}/api/v1/overview", token=token)
    if status != 200:
        raise RuntimeError("Packaged backend authenticated API smoke test failed.")
    status, body = _request(f"{base_url}/api/v1/capture/capabilities", token=token)
    if status != 200:
        raise RuntimeError("Packaged backend capture readiness smoke test failed.")
    capture = json.loads(body).get("status", {})
    if capture.get("running") or capture.get("mode") != "stopped":
        raise RuntimeError("Packaged backend did not remain stopped without an operator capture action.")
    status, body = _request(f"{base_url}/")
    if status != 200 or b'<div id="root"></div>' not in body:
        raise RuntimeError("Packaged backend did not serve the dashboard entry point.")
    html = body.decode("utf-8", errors="replace")
    if expected_build_id not in html and "assets/" not in html:
        raise RuntimeError("Packaged dashboard references were not found.")


def validate(executable: Path, manifest_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("windows_response_enabled") is not False:
        raise RuntimeError("Packaged runtime smoke test requires Windows responses disabled.")
    if manifest.get("capture_mode_default") != "stopped":
        raise RuntimeError("Packaged runtime smoke test requires stopped capture as the default mode.")
    if not executable.is_file():
        raise FileNotFoundError(f"Packaged backend executable is missing: {executable}")

    passwords = {name: secrets.token_urlsafe(24) for name in ("admin", "analyst", "viewer", "approver", "responder")}
    shutdown_token = secrets.token_hex(32)
    auth_secret = secrets.token_hex(32)
    with tempfile.TemporaryDirectory(prefix="bk-security-packaged-runtime-") as temporary:
        database = Path(temporary) / "security.sqlite3"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        base_url = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env.update({
            "BK_SECURITY_ENV": "production",
            "BK_SECURITY_HOST": "127.0.0.1",
            "BK_SECURITY_PORT": str(port),
            "BK_SECURITY_VERSION": manifest["version"],
            "BK_SECURITY_BUILD_ID": manifest["build_id"],
            "BK_SECURITY_CAPTURE_MODE": "stopped",
            "BK_SECURITY_CAPTURE_INTERFACE": "",
            "BK_SECURITY_CAPTURE_SCENARIO": "normal_traffic",
            "BK_SECURITY_WINDOWS_RESPONSE": "0",
            "BK_SECURITY_CORS_ORIGINS": "",
            "BK_SECURITY_AUTH_SECRET": auth_secret,
            "BK_SECURITY_INTERNAL_SHUTDOWN_TOKEN": shutdown_token,
            "BK_SECURITY_DB": str(database),
            "BK_SECURITY_ADMIN_PASSWORD": passwords["admin"],
            "BK_SECURITY_ANALYST_PASSWORD": passwords["analyst"],
            "BK_SECURITY_VIEWER_PASSWORD": passwords["viewer"],
            "BK_SECURITY_APPROVER_PASSWORD": passwords["approver"],
            "BK_SECURITY_RESPONDER_PASSWORD": passwords["responder"],
        })

        for run in (1, 2):
            process = _start(executable, env, base_url, manifest)
            try:
                _login_and_check_dashboard(base_url, passwords["admin"], manifest["build_id"])
                status, _ = _request(f"{base_url}/internal/shutdown", method="POST", shutdown=shutdown_token)
                if status != 200:
                    raise RuntimeError("Authenticated graceful shutdown endpoint failed.")
                process.wait(timeout=15)
                if process.returncode != 0:
                    raise RuntimeError(f"Packaged backend graceful shutdown returned {process.returncode}.")
            finally:
                if process.poll() is None:
                    try:
                        _request(f"{base_url}/internal/shutdown", method="POST", shutdown=shutdown_token)
                        process.wait(timeout=5)
                    except Exception:
                        process.kill()
                        process.wait(timeout=5)

            if not database.is_file():
                raise RuntimeError("Packaged backend did not create its configured SQLite database.")
            with closing(sqlite3.connect(database)) as connection:
                check = connection.execute("PRAGMA quick_check").fetchone()
                logins = connection.execute("SELECT count(*) FROM audit WHERE action='login'").fetchone()[0]
            if not check or check[0] != "ok" or logins < run:
                raise RuntimeError("Packaged backend persistence/recovery check failed.")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: validate_packaged_backend.py <backend.exe> <release-manifest.json>")
    validate(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
    print("Packaged backend: production config, stopped capture startup, API/dashboard, graceful restart and SQLite recovery passed.")
    print("BK_SECURITY_WINDOWS_RESPONSE=0 throughout; no real adapter or network capture was enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
