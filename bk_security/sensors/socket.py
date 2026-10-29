from __future__ import annotations

from collections import OrderedDict
import socket
from datetime import datetime, timezone
import threading

import psutil

from ..events.models import SecurityEvent
from .periodic import PeriodicSensor


class SocketAttributionSensor(PeriodicSensor):
    """Periodically maps active sockets to processes and emits changed rows only."""

    def __init__(self, host_id="local-host", core=None, interval_seconds=30, max_connections=20_000):
        super().__init__(interval_seconds)
        self.host_id, self.core = host_id, core
        self.max_connections = max(1, int(max_connections))
        self.connections: OrderedDict[str, dict] = OrderedDict()
        self._fingerprints: dict[str, tuple] = {}
        self._snapshot_lock = threading.Lock()
        self.last_snapshot: str | None = None
        self.events_emitted = 0

    @staticmethod
    def _address(address):
        if not address:
            return None
        return [str(value) for value in address]

    def snapshot(self):
        with self._snapshot_lock:
            return self._collect_snapshot()

    def _collect_snapshot(self):
        events = []
        current: OrderedDict[str, dict] = OrderedDict()
        for connection in psutil.net_connections(kind="inet"):
            try:
                pid = connection.pid
                process = psutil.Process(pid) if pid else None
                def process_value(attribute):
                    if process is None:
                        return None
                    try:
                        return getattr(process, attribute)()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        return None
                name = process_value("name")
                exe = process_value("exe")
                username = process_value("username")
                local = self._address(connection.laddr)
                remote = self._address(connection.raddr)
                src_ip = local[0] if local else None
                src_port = int(local[1]) if local and len(local) > 1 else None
                dst_ip = remote[0] if remote else None
                dst_port = int(remote[1]) if remote and len(remote) > 1 else None
                protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
                status = str(connection.status or "unknown")
                key = f"{pid or 0}|{src_ip or ''}|{src_port or 0}|{dst_ip or ''}|{dst_port or 0}|{protocol}"
                observed_at = datetime.now(timezone.utc).isoformat()
                data = {
                    "pid": pid, "status": status, "family": str(connection.family),
                    "type": str(connection.type), "local": local, "remote": remote,
                    "process_name": name, "process_exe": exe, "username": username,
                    "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                    "dst_port": dst_port, "protocol": protocol, "observed_at": observed_at,
                }
                current[key] = data
                fingerprint = (status, name, exe, username)
                if self._fingerprints.get(key) != fingerprint:
                    process_data = {"pid": pid, "name": name, "exe": exe, "username": username}
                    network_data = {
                        "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                        "dst_port": dst_port, "protocol": protocol,
                    }
                    event = SecurityEvent(
                        event_type="endpoint.socket", source="bk_socket_sensor", host_id=self.host_id,
                        data=data, process=process_data if pid or name else {}, network=network_data,
                    )
                    if self.core:
                        self.core.ingest(event)
                    events.append(event)
                    self._fingerprints[key] = fingerprint
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError, OverflowError):
                continue

        self.connections = current
        if len(self.connections) > self.max_connections:
            while len(self.connections) > self.max_connections:
                evicted_key, _ = self.connections.popitem(last=False)
                self._fingerprints.pop(evicted_key, None)
        active_keys = set(self.connections)
        for key in list(self._fingerprints):
            if key not in active_keys:
                self._fingerprints.pop(key, None)
        self.last_snapshot = datetime.now(timezone.utc).isoformat()
        self.events_emitted += len(events)
        return events

    def status(self):
        return {
            **super().status(), "host_id": self.host_id,
            "connections": len(self.connections), "events_emitted": self.events_emitted,
            "last_snapshot": self.last_snapshot,
        }
