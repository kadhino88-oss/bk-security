"""Local IPC for the privileged response executor: authenticated, JSON-only (never pickle).

multiprocessing.connection performs an HMAC challenge with a shared key before any message is exchanged, and we only
use send_bytes/recv_bytes, so the pickle channel it also offers is never used.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from multiprocessing.connection import Client, Listener
from pathlib import Path
from typing import Any

MAX_MESSAGE_BYTES = 1024 * 1024
MIN_KEY_CHARS = 32


class ServiceKeyError(ValueError):
    pass


def load_key(env) -> bytes:
    key_path = str(env.get("BK_SECURITY_RESPONSE_KEY_FILE", "")).strip()
    if key_path:
        try:
            key = Path(key_path).read_bytes().decode("utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise ServiceKeyError("BK_SECURITY_RESPONSE_KEY_FILE could not be read.") from exc
    else:
        key = str(env.get("BK_SECURITY_RESPONSE_KEY", "")).strip()
    if len(key) < MIN_KEY_CHARS:
        raise ServiceKeyError(f"BK_SECURITY_RESPONSE_KEY must contain at least {MIN_KEY_CHARS} characters.")
    return key.encode("utf-8")


def default_address(key: bytes) -> str:
    """Per-install address derived from the key: a named pipe on Windows, a 0700-directory socket elsewhere."""
    token = hashlib.sha256(key).hexdigest()[:16]
    if os.name == "nt":
        return rf"\\.\pipe\bk-security-response-{token}"
    directory = os.path.join(tempfile.gettempdir(), f"bk-security-{os.getuid()}")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    return os.path.join(directory, f"response-{token}.sock")


def resolve_address(env, key: bytes) -> str:
    return str(env.get("BK_SECURITY_RESPONSE_ADDRESS", "")).strip() or default_address(key)


def family_for(address: str) -> str:
    return "AF_PIPE" if os.name == "nt" else "AF_UNIX"


def make_listener(address: str, key: bytes) -> Listener:
    if os.name != "nt" and os.path.exists(address):
        os.unlink(address)
    return Listener(address, family_for(address), authkey=key)


def send_json(connection, payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValueError("Service message must be a JSON object.")
    data = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError("Service message exceeds maximum size.")
    connection.send_bytes(data)


def recv_json(connection, timeout: float | None = None) -> dict[str, Any]:
    if timeout is not None and not connection.poll(timeout):
        raise TimeoutError("response service did not answer in time")
    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field.")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("Non-finite JSON number.")

    data = json.loads(
        connection.recv_bytes(MAX_MESSAGE_BYTES).decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_constant,
    )
    if not isinstance(data, dict):
        raise ValueError("Malformed service message.")
    return data


def call(address: str, key: bytes, payload: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
    connection = Client(address, family_for(address), authkey=key)
    try:
        send_json(connection, payload)
        return recv_json(connection, timeout)
    finally:
        connection.close()
