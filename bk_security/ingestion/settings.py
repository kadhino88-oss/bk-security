"""Environment settings for the ingestion queue, validated without echoing values."""
from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

_INTEGERS = {
    "BK_SECURITY_INGEST_MAX_DEPTH": ("max_depth", 100_000),
    "BK_SECURITY_INGEST_AGENT_BURST": ("agent_burst", 200),
    "BK_SECURITY_INGEST_MAX_ATTEMPTS": ("max_attempts", 3),
    "BK_SECURITY_INGEST_MAX_QUARANTINE": ("max_quarantine", 10_000),
}
_FLOATS = {
    "BK_SECURITY_INGEST_AGENT_RATE": ("agent_rate", 100.0),
    "BK_SECURITY_INGEST_LEASE_SECONDS": ("lease_seconds", 30.0),
    "BK_SECURITY_INGEST_RETENTION_SECONDS": ("retention_seconds", 7 * 86_400.0),
}


def ingestion_settings(env: Mapping[str, str]) -> dict[str, Any]:
    """Return IngestionQueue keyword arguments; raise ValueError naming only the bad variable."""
    settings: dict[str, Any] = {}
    for name, (key, default) in _INTEGERS.items():
        raw = str(env.get(name, "")).strip()
        try:
            value = int(raw) if raw else default
        except ValueError:
            raise ValueError(f"{name} must be a positive integer.") from None
        if value < 1:
            raise ValueError(f"{name} must be a positive integer.")
        settings[key] = value
    for name, (key, default) in _FLOATS.items():
        raw = str(env.get(name, "")).strip()
        try:
            value = float(raw) if raw else default
        except ValueError:
            raise ValueError(f"{name} must be a positive number.") from None
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be a positive number.")
        settings[key] = value
    return settings
