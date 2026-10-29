from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid

from ..events.models import SecurityAlert


@dataclass(slots=True)
class CorrelationResult:
    incident_key: str
    score_bonus: int
    related_alert_ids: list[str]
    reason: str


@dataclass(slots=True)
class _CorrelationCluster:
    key: str
    last_seen: float
    alert_ids: deque[str] = field(default_factory=deque)
    processes: set[str] = field(default_factory=set)
    destinations: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    severe_alerts: int = 0


class CorrelationEngine:
    """Groups related alerts for the same host inside a bounded time window.

    Process and destination evidence link alerts into one incident. Host identity
    partitions clusters, while expiry creates a fresh incident after inactivity.
    """

    def __init__(self, max_alerts_per_host: int = 100, window_seconds: int = 300, max_hosts: int = 1000) -> None:
        self.window_seconds = max(1, int(window_seconds))
        self.max_alerts_per_host = max(1, int(max_alerts_per_host))
        self.max_hosts = max(1, int(max_hosts))
        self._by_host: OrderedDict[str, deque[_CorrelationCluster]] = OrderedDict()

    def restore(self, alerts: list[SecurityAlert], incident_ids: set[str], now: float | None = None) -> None:
        """Rebuild active time-window clusters from persisted alert evidence."""
        current = now if now is not None else datetime.now(timezone.utc).timestamp()
        grouped: dict[tuple[str, str], list[SecurityAlert]] = {}
        for alert in alerts:
            incident_id = alert.correlation_id
            if not incident_id or incident_id not in incident_ids:
                continue
            timestamp = self._ts(alert.timestamp)
            if timestamp > current or current - timestamp > self.window_seconds:
                continue
            grouped.setdefault((alert.host_id, incident_id), []).append(alert)

        for (host_id, incident_id), records in grouped.items():
            records.sort(key=lambda item: self._ts(item.timestamp))
            cluster = _CorrelationCluster(key=incident_id, last_seen=self._ts(records[-1].timestamp))
            for alert in records[-self.max_alerts_per_host:]:
                processes, destinations, techniques = self._evidence(alert)
                cluster.processes.update(processes)
                cluster.destinations.update(destinations)
                cluster.techniques.update(techniques)
                cluster.alert_ids.append(alert.alert_id)
                if alert.severity in {"medium", "high", "critical"}:
                    cluster.severe_alerts += 1
            clusters = self._by_host.setdefault(host_id, deque())
            clusters.append(cluster)
            self._by_host.move_to_end(host_id)
            while len(clusters) > self.max_alerts_per_host:
                clusters.popleft()
            while len(self._by_host) > self.max_hosts:
                self._by_host.popitem(last=False)

    def discard_incident(self, incident_id: str) -> None:
        """Remove a terminal incident's cluster so later signals start a new case."""
        for host_id in list(self._by_host):
            retained = deque(cluster for cluster in self._by_host[host_id] if cluster.key != incident_id)
            if retained:
                self._by_host[host_id] = retained
            else:
                self._by_host.pop(host_id, None)

    def _ts(self, value: str) -> float:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except (AttributeError, TypeError, ValueError, OverflowError):
            return datetime.now(timezone.utc).timestamp()

    @staticmethod
    def _evidence(alert: SecurityAlert) -> tuple[set[str], set[str], set[str]]:
        processes: set[str] = set()
        destinations: set[str] = set()
        for item in alert.evidence:
            field_name = item.get("field")
            value = item.get("value")
            if value is None or value == "":
                continue
            normalized = str(value).strip().lower()
            if field_name == "process":
                processes.add(normalized)
            elif field_name in {"destination_ip", "destination_domain"}:
                destinations.add(normalized)
            elif field_name == "destination_port":
                destinations.add(f"port:{normalized}")
        return processes, destinations, {str(x).upper() for x in alert.mitre_techniques if x}

    def add(self, alert: SecurityAlert) -> CorrelationResult:
        now = self._ts(alert.timestamp)
        clusters = self._by_host.setdefault(alert.host_id, deque())
        self._by_host.move_to_end(alert.host_id)
        while len(self._by_host) > self.max_hosts:
            self._by_host.popitem(last=False)
        clusters = self._by_host.get(alert.host_id, deque())

        # Remove expired clusters regardless of their creation order. Delayed
        # telemetry can update an older cluster after a newer one was created.
        clusters = deque(c for c in clusters if now - c.last_seen <= self.window_seconds)
        self._by_host[alert.host_id] = clusters

        processes, destinations, techniques = self._evidence(alert)
        candidates: list[tuple[int, float, _CorrelationCluster]] = []
        for cluster in clusters:
            elapsed = now - cluster.last_seen
            if elapsed < 0 or elapsed > self.window_seconds:
                continue
            process_match = bool(processes & cluster.processes)
            destination_match = bool(destinations & cluster.destinations)
            if process_match or destination_match:
                overlap = int(process_match) + int(destination_match)
                candidates.append((overlap, cluster.last_seen, cluster))

        if candidates:
            # Prefer the closest existing cluster; ties go to the most recently
            # active one to keep incident membership deterministic.
            cluster = max(candidates, key=lambda item: (item[0], item[1]))[2]
            is_correlated = True
        else:
            cluster = _CorrelationCluster(
                key=f"host:{alert.host_id}:incident:{uuid.uuid4()}",
                last_seen=now,
            )
            clusters.append(cluster)
            while len(clusters) > self.max_alerts_per_host:
                clusters.popleft()
            is_correlated = False

        cluster.last_seen = max(cluster.last_seen, now)
        cluster.processes.update(processes)
        cluster.destinations.update(destinations)
        cluster.techniques.update(techniques)
        cluster.alert_ids.append(alert.alert_id)
        while len(cluster.alert_ids) > self.max_alerts_per_host:
            cluster.alert_ids.popleft()
        if alert.severity in {"medium", "high", "critical"}:
            cluster.severe_alerts += 1

        dimensions = sum(bool(values) for values in (cluster.processes, cluster.destinations, cluster.techniques))
        score_bonus = 0
        if is_correlated:
            score_bonus = min(30, max(0, (cluster.severe_alerts - 1) * 5) + max(0, dimensions - 1) * 3)
        reason = "multi_signal_correlation" if is_correlated and dimensions > 1 else (
            "related_alerts" if is_correlated else "single_alert"
        )
        return CorrelationResult(
            incident_key=cluster.key,
            score_bonus=score_bonus,
            related_alert_ids=list(cluster.alert_ids)[-10:],
            reason=reason,
        )
