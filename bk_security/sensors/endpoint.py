from __future__ import annotations
from collections import OrderedDict
from datetime import datetime, timezone
import threading
import psutil
from bk_security.events.adapters import process_to_event
from bk_security.events.sanitization import sanitize_command_line
from bk_security.detection.rules import SUSPICIOUS_PROCESSES
from .periodic import PeriodicSensor

def _safe_command_line(value) -> list[str] | None:
    return sanitize_command_line(value)

class EndpointProcessSensor(PeriodicSensor):
    """Periodically samples process metadata and emits only new or changed rows."""
    def __init__(self, core, host_id="local-host", interval_seconds=30, max_processes=20_000):
        super().__init__(interval_seconds)
        self.core, self.host_id = core, host_id
        self.max_processes = max(1, int(max_processes))
        self.records: OrderedDict[int, dict] = OrderedDict()
        self._fingerprints: OrderedDict[int, tuple] = OrderedDict()
        self._snapshot_lock = threading.Lock()
        self.last_snapshot: str | None = None
        self.events_emitted = 0

    def snapshot(self):
        with self._snapshot_lock:
            return self._collect_snapshot()

    def _collect_snapshot(self):
        events = []
        for process in psutil.process_iter([
            "pid", "name", "exe", "cmdline", "ppid", "username", "create_time",
            "cpu_percent", "memory_info", "status",
        ]):
            try:
                info = dict(process.info)
                pid = int(info.get("pid") or 0)
                if pid <= 0:
                    continue
                info["cmdline"] = _safe_command_line(info.get("cmdline"))
                memory = info.get("memory_info")
                if memory is not None:
                    info["memory_bytes"] = int(getattr(memory, "rss", 0) or 0)
                info["cpu_percent"] = float(info.get("cpu_percent") or 0.0)
                info["observed_at"] = datetime.now(timezone.utc).isoformat()
                fingerprint = (
                    info.get("create_time"), info.get("name"), info.get("exe"),
                    tuple(info.get("cmdline") or ()), info.get("ppid"), info.get("username"),
                )
                self.records[pid] = info
                self.records.move_to_end(pid)
                while len(self.records) > self.max_processes:
                    evicted_pid, _ = self.records.popitem(last=False)
                    self._fingerprints.pop(evicted_pid, None)
                previous = self._fingerprints.get(pid)
                if previous != fingerprint:
                    self._fingerprints[pid] = fingerprint
                    self._fingerprints.move_to_end(pid)
                    process_name = str(info.get("name") or "").lower()
                    if process_name in SUSPICIOUS_PROCESSES:
                        event = process_to_event(info, self.host_id)
                        event.data["change"] = "started" if previous is None else "metadata_changed"
                        self.core.ingest(event)
                        events.append(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
            except (TypeError, ValueError, OverflowError): continue
        self.last_snapshot = datetime.now(timezone.utc).isoformat()
        self.events_emitted += len(events)
        return events

    def status(self):
        return {
            **super().status(),
            "host_id": self.host_id,
            "processes": len(self.records),
            "events_emitted": self.events_emitted,
            "last_snapshot": self.last_snapshot,
        }
