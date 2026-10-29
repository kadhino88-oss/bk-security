from __future__ import annotations

from collections.abc import Mapping
from typing import Any


_SIMULATION_KEYS = {"simulation", "simulated", "simulation_ioc"}


def _contains_simulation_marker(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).strip().casefold() in _SIMULATION_KEYS and item is True:
                return True
            if isinstance(item, (Mapping, list, tuple)) and _contains_simulation_marker(item):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_simulation_marker(item) for item in value)
    return False


def is_simulation_record(record: Any) -> bool:
    """Identify records carrying explicit simulation provenance."""
    if isinstance(record, Mapping):
        data = record.get("data", {})
        tags = record.get("tags", [])
        source = record.get("source", "")
    else:
        data = getattr(record, "data", {})
        tags = getattr(record, "tags", [])
        source = getattr(record, "source", "")

    if _contains_simulation_marker(data):
        return True
    if any(str(tag).strip().casefold() in {"simulation", "simulated"} for tag in tags or []):
        return True
    return "simulation" in str(source).casefold()
