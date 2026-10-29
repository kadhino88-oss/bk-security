"""Fail-closed validation for runtime settings that affect production security."""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from urllib.parse import urlsplit
from .deployment import DeploymentContext


ROLE_PASSWORDS = (
    "BK_SECURITY_ADMIN_PASSWORD",
    "BK_SECURITY_ANALYST_PASSWORD",
    "BK_SECURITY_VIEWER_PASSWORD",
    "BK_SECURITY_APPROVER_PASSWORD",
    "BK_SECURITY_RESPONDER_PASSWORD",
)


def effective_capture_mode(env: Mapping[str, str]) -> str:
    """Production must never start synthetic capture, even with stale env settings."""
    mode = env.get("BK_SECURITY_CAPTURE_MODE", "stopped").strip().lower() or "stopped"
    production = env.get("BK_SECURITY_ENV", "").strip().lower() == "production"
    return "stopped" if production and mode == "simulation" else mode


def production_configuration_errors(env: Mapping[str, str]) -> list[str]:
    """Return safe, value-free diagnostics for an incomplete production env."""
    if env.get("BK_SECURITY_ENV", "").strip().lower() != "production":
        return []

    errors: list[str] = []
    try:
        DeploymentContext.from_environment(env)
    except ValueError as exc:
        errors.append(str(exc))
    passwords = [env.get(name, "") for name in ROLE_PASSWORDS]
    if any(len(value.encode("utf-8")) < 12 for value in passwords):
        errors.append("All five production role passwords must contain at least 12 UTF-8 bytes.")
    if any(value.endswith("-dev-only") for value in passwords):
        errors.append("Development-only role passwords are not allowed in production.")
    if any(len(set(value)) < 6 for value in passwords):
        errors.append("Production role passwords must not be trivial repeated-character values.")
    if len(set(passwords)) != len(passwords):
        errors.append("Production role passwords must be unique and non-empty.")

    secret = env.get("BK_SECURITY_AUTH_SECRET", "")
    if len(secret.encode("utf-8")) < 32 or secret == "CHANGE-ME-BK-SECURITY" or len(set(secret)) < 12:
        errors.append("BK_SECURITY_AUTH_SECRET must contain at least 32 UTF-8 bytes.")

    if "BK_SECURITY_CORS_ORIGINS" not in env:
        errors.append("BK_SECURITY_CORS_ORIGINS must be explicitly configured (empty is allowed for the desktop app).")
    origins = [item.strip() for item in env.get("BK_SECURITY_CORS_ORIGINS", "").split(",") if item.strip()]
    if "*" in origins:
        errors.append("Wildcard CORS origins are not allowed in production.")
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            errors.append("BK_SECURITY_CORS_ORIGINS contains an invalid origin.")
            break

    mode = env.get("BK_SECURITY_CAPTURE_MODE", "").strip().lower()
    if mode not in {"live", "stopped"}:
        errors.append("Production BK_SECURITY_CAPTURE_MODE must be live or stopped; simulation is disabled.")
    if mode == "live" and not env.get("BK_SECURITY_CAPTURE_INTERFACE", "").strip():
        errors.append("Live capture requires an explicitly selected BK_SECURITY_CAPTURE_INTERFACE.")

    host = env.get("BK_SECURITY_HOST", "127.0.0.1").strip().lower()
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"
    if not is_loopback:
        errors.append("Production BK_SECURITY_HOST must be a loopback address.")

    if env.get("BK_SECURITY_WINDOWS_RESPONSE", "0") != "0":
        errors.append("BK_SECURITY_WINDOWS_RESPONSE must remain 0 in this V1 release.")
    if env.get("BK_SECURITY_OS_RESPONSE", "0") != "0":
        errors.append("BK_SECURITY_OS_RESPONSE must remain 0 until the platform response adapters are lab-validated.")

    from .ingestion.settings import ingestion_settings
    try:
        ingestion_settings(env)
    except ValueError as exc:
        errors.append(str(exc))

    return errors
