from __future__ import annotations
from collections import OrderedDict, deque
from dataclasses import dataclass
from time import time
from ..events.models import SecurityEvent

@dataclass(slots=True)
class BehaviorFinding:
    score: float
    reasons: list[str]

class BehaviorEngine:
    """Small deterministic rolling baseline for V1. No AI is required to flag deviations."""
    def __init__(
        self,
        window_seconds: int = 60,
        beacon_threshold: int = 30,
        max_hosts: int = 512,
        max_flows: int = 5000,
        max_destinations_per_host: int = 256,
    ) -> None:
        self.window_seconds = window_seconds
        self.beacon_threshold = max(1, min(128, int(beacon_threshold)))
        self.max_hosts = max(1, int(max_hosts))
        self.max_flows = max(1, int(max_flows))
        self.max_destinations_per_host = max(1, int(max_destinations_per_host))
        self._flows: OrderedDict[tuple[str, str, int], deque[float]] = OrderedDict()
        self._known_destinations: OrderedDict[str, OrderedDict[str, None]] = OrderedDict()

    def evaluate(self, event: SecurityEvent) -> BehaviorFinding:
        if event.event_type != "network.packet":
            return BehaviorFinding(0, [])
        d = event.data
        dst = str(d.get("dst_ip") or "")
        port = int(d.get("dst_port") or 0)
        process = str(d.get("process_name") or "unknown").lower()
        if not dst:
            return BehaviorFinding(0, [])
        now = time()
        destinations = self._known_destinations.setdefault(event.host_id, OrderedDict())
        self._known_destinations.move_to_end(event.host_id)
        while len(self._known_destinations) > self.max_hosts:
            self._known_destinations.popitem(last=False)
        is_new_destination = dst not in destinations
        destinations[dst] = None
        destinations.move_to_end(dst)
        while len(destinations) > self.max_destinations_per_host:
            destinations.popitem(last=False)

        key = (event.host_id, dst, port)
        q = self._flows.get(key)
        if q is None:
            q = deque()
            self._flows[key] = q
        self._flows.move_to_end(key)
        while len(self._flows) > self.max_flows:
            self._flows.popitem(last=False)
        q.append(now)
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        while len(q) > self.beacon_threshold + 35:
            q.popleft()
        score, reasons = 0.0, []
        if is_new_destination:
            score += 12
            reasons.append("new_destination")
        if len(q) == self.beacon_threshold:
            score += 50
            reasons.append("repetitive_connection_pattern")
        if process in {"powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe"} and port not in {80, 443}:
            score += 25
            reasons.append("script_process_unusual_port")
        return BehaviorFinding(min(100, score), reasons)
