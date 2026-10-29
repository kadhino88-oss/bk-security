from __future__ import annotations

import json
import logging
import os
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Protocol
from ..deployment import DeploymentContext

_STOP_WRITER = object()


@dataclass(slots=True)
class _PendingIngest:
    event: dict[str, Any] | None
    alerts: list[dict[str, Any]] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class _FlushBarrier:
    ready: threading.Event = field(default_factory=threading.Event)


class SecurityRepository(Protocol):
    """Storage contract used by the BK Security core."""

    def save_event(self, event: Any) -> None: ...
    def persist_ingest(self, event: Any, alerts=(), incidents=()) -> None: ...
    def list_events(self, limit: int = 100) -> list[dict[str, Any]]: ...
    def trim_retention(self) -> None: ...
    def get_event(self, event_id: str) -> dict[str, Any] | None: ...
    def save_alert(self, alert: Any) -> None: ...
    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]: ...
    def get_alert(self, alert_id: str) -> dict[str, Any] | None: ...
    def save_incident(self, incident: Any) -> None: ...
    def record_incident_transition(self, incident: Any, actor: str, previous: str, target: str) -> None: ...
    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]: ...
    def get_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def save_host(self, host: Any) -> None: ...
    def list_hosts(self, limit: int = 1000) -> list[dict[str, Any]]: ...
    def save_response_action(self, action: Any) -> None: ...
    def list_response_actions(self, limit: int = 500) -> list[dict[str, Any]]: ...
    def audit(self, actor: str, action: str, target: str | None = None, data: dict | None = None) -> None: ...
    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]: ...
    def register_auth_session(self, token_id: str, username: str, expires_at: int) -> None: ...
    def auth_session_status(self, token_id: str) -> str: ...
    def revoke_auth_session(self, token_id: str) -> bool: ...
    def list_active_auth_sessions(self) -> list[dict[str, Any]]: ...
    def revoke_auth_sessions(self, username: str) -> int: ...
    def save_autonomy_policy(self, data: dict[str, Any]) -> None: ...
    def load_autonomy_policy(self) -> dict[str, Any] | None: ...


def _payload(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if not isinstance(value, dict):
        raise TypeError("Repository records must be dictionaries or expose to_dict()")
    return value


class SecurityStore:
    """SQLite/WAL repository with bounded asynchronous batched ingest writes."""

    prune_interval = 256
    write_batch_size = 128
    batch_window_seconds = 0.01
    writer_idle_seconds = 0.1

    def __init__(
        self,
        path: str | None = None,
        *,
        max_events: int = 50_000,
        max_alerts: int = 10_000,
        max_pending_writes: int = 4096,
        deployment_context: DeploymentContext | None = None,
    ):
        self.path = path or os.getenv(
            "BK_SECURITY_DB", str(Path.home() / ".bk-security" / "security.db")
        )
        self.max_events = max(1, int(max_events))
        self.max_alerts = max(1, int(max_alerts))
        # Every repository created by a process inherits its configured data
        # plane by default. Otherwise a CLI, worker, or utility that forgets to
        # pass the context could silently open the same file as local V1 and
        # bypass the dedicated-deployment startup binding.
        configured_context = DeploymentContext.from_environment(os.environ)
        if (
            deployment_context is not None
            and configured_context.profile == "dedicated_customer"
            and deployment_context != configured_context
        ):
            raise ValueError(
                "A SecurityStore cannot override the process's dedicated customer deployment identity."
            )
        self.deployment_context = deployment_context or configured_context
        if self.deployment_context.profile == "dedicated_customer" and self.path == ":memory:":
            raise ValueError(
                "Dedicated customer deployment requires a persistent SQLite database file."
            )
        self._lock = threading.RLock()
        self._event_writes = 0
        self._alert_writes = 0
        self._ingest_batches = 0
        self._ingests_written = 0
        self._pending: queue.Queue[_PendingIngest | _FlushBarrier | object] = queue.Queue(
            maxsize=max(1, int(max_pending_writes))
        )
        self._writer_lock = threading.Lock()
        self._writer: threading.Thread | None = None
        self._closed = False
        self._writer_error: str | None = None
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if self.deployment_context.profile == "dedicated_customer":
            self._bind_dedicated_deployment()
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS events ("
                "event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, host_id TEXT NOT NULL, data TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_host_time "
                "ON events(host_id, timestamp)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS alerts ("
                "alert_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, host_id TEXT NOT NULL, "
                "correlation_id TEXT, data TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_host_time "
                "ON alerts(host_id, timestamp)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_correlation "
                "ON alerts(correlation_id)"
            )
            connection.execute("CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, data TEXT)")
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS audit_no_update "
                "BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS audit_no_delete "
                "BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS hosts ("
                "host_id TEXT PRIMARY KEY, last_seen TEXT NOT NULL, data TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS response_actions ("
                "action_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_response_actions_time "
                "ON response_actions(timestamp)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS auth_sessions ("
                "token_id TEXT PRIMARY KEY, username TEXT NOT NULL, "
                "expires_at INTEGER NOT NULL, revoked_at TEXT)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS autonomy_policy ("
                "id INTEGER PRIMARY KEY CHECK (id = 1), data TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry "
                "ON auth_sessions(expires_at)"
            )
            # Production provenance filtering needs referenced source events to
            # remain queryable until SecurityCore has separated simulation history.
            if os.getenv("BK_SECURITY_ENV", "").strip().lower() != "production":
                self._trim(connection, "events", self.max_events)
            self._trim(connection, "alerts", self.max_alerts)

    def _bind_dedicated_deployment(self) -> None:
        """Bind one SQLite file to one immutable customer/region deployment."""
        expected = self.deployment_context.database_binding()
        with self._connect(verify_deployment=False) as connection:
            # Serialize first-use binding so two processes cannot race different
            # customer identities into the same previously unbound database.
            connection.execute("BEGIN IMMEDIATE")
            tables = {
                str(row[0]) for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            binding_exists = "deployment_binding" in tables
            if binding_exists:
                row = connection.execute(
                    "SELECT profile, customer_ref, deployment_id, region "
                    "FROM deployment_binding WHERE singleton=1"
                ).fetchone()
                if row is not None:
                    if tuple(row) != expected:
                        raise RuntimeError(
                            "SQLite database is already bound to a different customer deployment."
                        )
                    return
                tables.remove("deployment_binding")

            if self._has_table_records(connection, tables):
                raise RuntimeError(
                    "Dedicated customer data plane requires a fresh or empty SQLite database; "
                    "unbound existing data was not assigned to a customer."
                )

            connection.execute(
                "CREATE TABLE IF NOT EXISTS deployment_binding ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "profile TEXT NOT NULL, customer_ref TEXT NOT NULL, "
                "deployment_id TEXT NOT NULL, region TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO deployment_binding "
                "(singleton, profile, customer_ref, deployment_id, region) "
                "VALUES (1, ?, ?, ?, ?)",
                expected,
            )

    @staticmethod
    def _has_table_records(connection: sqlite3.Connection, tables: set[str]) -> bool:
        for table in tables:
            if table.startswith("sqlite_"):
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            if connection.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone() is not None:
                return True
        return False

    @contextmanager
    def _connect(self, *, verify_deployment: bool = True) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5.0)
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            if verify_deployment and self.deployment_context.profile == "dedicated_customer":
                table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='deployment_binding'"
                ).fetchone()
                if table is None:
                    raise RuntimeError(
                        "Active SQLite database does not contain the expected customer deployment binding."
                    )
                row = connection.execute(
                    "SELECT profile, customer_ref, deployment_id, region "
                    "FROM deployment_binding WHERE singleton=1"
                ).fetchone()
                if row is None or tuple(row) != self.deployment_context.database_binding():
                    raise RuntimeError(
                        "Active SQLite database is bound to a different customer deployment."
                    )
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _start_writer_locked(self) -> None:
        if self._writer is None or not self._writer.is_alive():
            self._writer = threading.Thread(
                target=self._writer_loop,
                name="bk-security-sqlite-writer",
                daemon=True,
            )
            self._writer.start()

    def persist_ingest(self, event: Any = None, alerts=(), incidents=()) -> None:
        """Queue one normalized event with its alerts/incidents as one atomic write."""
        event_data = dict(_payload(event)) if event is not None else None
        alert_data = [dict(_payload(item)) for item in alerts]
        incident_data = [dict(_payload(item)) for item in incidents]
        if event_data is not None and not event_data.get("event_id"):
            raise ValueError("Security event requires event_id")
        if any(not item.get("alert_id") for item in alert_data):
            raise ValueError("Security alert requires alert_id")
        if any(not item.get("incident_id") for item in incident_data):
            raise ValueError("Security incident requires incident_id")
        if event_data is None and not alert_data and not incident_data:
            return
        # Serialize before enqueue so callers cannot mutate records while the
        # writer is batching them and serialization errors remain synchronous.
        for record in [event_data, *alert_data, *incident_data]:
            if record is not None:
                json.dumps(record, default=str)
        batch = _PendingIngest(event_data, alert_data, incident_data)
        with self._writer_lock:
            if self._closed:
                raise RuntimeError("SecurityStore is closed")
            self._start_writer_locked()
            # A full bounded queue applies backpressure instead of dropping
            # security telemetry.
            self._pending.put(batch)

    def _writer_loop(self) -> None:
        while True:
            try:
                first = self._pending.get(timeout=self.writer_idle_seconds)
            except queue.Empty:
                with self._writer_lock:
                    if self._pending.empty():
                        self._writer = None
                        return
                continue

            if first is _STOP_WRITER:
                self._pending.task_done()
                with self._writer_lock:
                    self._writer = None
                return
            if isinstance(first, _FlushBarrier):
                first.ready.set()
                self._pending.task_done()
                continue

            ingest_batch = [first]
            barriers: list[_FlushBarrier] = []
            stop_after_batch = False
            deadline = time.monotonic() + self.batch_window_seconds
            while len(ingest_batch) < self.write_batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    item = self._pending.get(timeout=remaining)
                except queue.Empty:
                    break
                if item is _STOP_WRITER:
                    stop_after_batch = True
                    break
                if isinstance(item, _FlushBarrier):
                    barriers.append(item)
                else:
                    ingest_batch.append(item)

            delay = 0.025
            while True:
                try:
                    self._write_ingest_batch(ingest_batch)
                    self._writer_error = None
                    break
                except (OSError, sqlite3.Error) as exc:
                    self._writer_error = str(exc)
                    logging.getLogger(__name__).error(
                        "BK Security SQLite writer is applying backpressure and retrying: %s", exc
                    )
                    time.sleep(delay)
                    delay = min(delay * 2, 1.0)

            for _ in ingest_batch:
                self._pending.task_done()
            for barrier in barriers:
                barrier.ready.set()
                self._pending.task_done()
            if stop_after_batch:
                self._pending.task_done()
                with self._writer_lock:
                    self._writer = None
                return

    def _write_ingest_batch(self, batch: list[_PendingIngest]) -> None:
        with self._lock, self._connect() as connection:
            event_records: list[tuple[str, str, str, str]] = []
            alert_records: list[tuple[str, str, str, str | None, str]] = []
            incident_records: list[tuple[str, str]] = []
            for item in batch:
                if item.event is not None:
                    data = item.event
                    event_records.append((
                        str(data["event_id"]), str(data.get("timestamp", "")),
                        str(data.get("host_id", "")), json.dumps(data, default=str),
                    ))
                for data in item.alerts:
                    alert_records.append((
                        str(data["alert_id"]), str(data.get("timestamp", "")),
                        str(data.get("host_id", "")), data.get("correlation_id"),
                        json.dumps(data, default=str),
                    ))
                for data in item.incidents:
                    incident_records.append((
                        str(data["incident_id"]), json.dumps(data, default=str),
                    ))
            if event_records:
                connection.executemany(
                    "INSERT OR REPLACE INTO events(event_id,timestamp,host_id,data) VALUES(?,?,?,?)",
                    event_records,
                )
            if alert_records:
                connection.executemany(
                    "INSERT OR REPLACE INTO alerts(alert_id,timestamp,host_id,correlation_id,data) VALUES(?,?,?,?,?)",
                    alert_records,
                )
            if incident_records:
                connection.executemany(
                    "INSERT OR REPLACE INTO incidents(id,data) VALUES(?,?)",
                    incident_records,
                )
            self._event_writes += len(event_records)
            self._alert_writes += len(alert_records)
            if self._event_writes >= self.prune_interval:
                self._trim(connection, "events", self.max_events)
                self._event_writes = 0
            if self._alert_writes >= self.prune_interval:
                self._trim(connection, "alerts", self.max_alerts)
                self._alert_writes = 0

        self._ingest_batches += 1
        self._ingests_written += len(batch)

    def flush(self, timeout: float = 10.0) -> None:
        """Wait for every previously queued ingest to reach SQLite."""
        barrier = _FlushBarrier()
        with self._writer_lock:
            if self._closed:
                return
            if self._writer is None and self._pending.empty():
                return
            self._start_writer_locked()
            self._pending.put(barrier)
        if not barrier.ready.wait(max(0.0, timeout)):
            detail = f"; last SQLite error: {self._writer_error}" if self._writer_error else ""
            raise TimeoutError(f"Timed out waiting for BK Security database writes{detail}")

    def close(self, timeout: float = 10.0) -> None:
        """Flush queued data and stop the background writer."""
        self.flush(timeout)
        with self._writer_lock:
            if self._closed:
                return
            self._closed = True
            writer = self._writer
            if writer is not None:
                self._pending.put(_STOP_WRITER)
        if writer is not None:
            writer.join(timeout=max(0.0, timeout))
            if writer.is_alive():
                raise TimeoutError("BK Security database writer did not stop cleanly")

    @property
    def writer_status(self) -> dict[str, Any]:
        return {
            "healthy": self._writer_error is None,
            "pending": self._pending.qsize(),
            "capacity": self._pending.maxsize,
            "running": self._writer is not None and self._writer.is_alive(),
            "batches_written": self._ingest_batches,
            "ingests_written": self._ingests_written,
        }

    def _flush_before_read(self) -> None:
        self.flush()

    @staticmethod
    def _trim(connection: sqlite3.Connection, table: str, keep: int) -> None:
        # Table names are internal constants, never caller input.
        connection.execute(
            f"DELETE FROM {table} WHERE rowid NOT IN "
            f"(SELECT rowid FROM {table} ORDER BY rowid DESC LIMIT ?)",
            (keep,),
        )

    @staticmethod
    def _list_records(connection: sqlite3.Connection, table: str, limit: int) -> list[dict[str, Any]]:
        rows = connection.execute(
            f"SELECT data FROM {table} ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]

    def save_event(self, event: Any) -> None:
        self.persist_ingest(event)

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        self._flush_before_read()
        limit = max(1, min(int(limit), self.max_events))
        with self._connect() as connection:
            return self._list_records(connection, "events", limit)

    def trim_retention(self) -> None:
        """Apply event retention after the core has restored evidence provenance."""
        self._flush_before_read()
        with self._lock, self._connect() as connection:
            self._trim(connection, "events", self.max_events)
            self._trim(connection, "alerts", self.max_alerts)

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        self._flush_before_read()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def save_alert(self, alert: Any) -> None:
        self.persist_ingest(alerts=[alert])

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        self._flush_before_read()
        limit = max(1, min(int(limit), self.max_alerts))
        with self._connect() as connection:
            return self._list_records(connection, "alerts", limit)

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        self._flush_before_read()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def save_incident(self, incident: Any) -> None:
        self.persist_ingest(incidents=[incident])

    def record_incident_transition(self, incident: Any, actor: str, previous: str, target: str) -> None:
        data = dict(_payload(incident))
        # This write must follow the incident's earlier queued ingest update;
        # otherwise an older queued snapshot could overwrite the new status.
        self.flush()
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO incidents(id,data) VALUES(?,?)",
                (str(data["incident_id"]), json.dumps(data, default=str)),
            )
            connection.execute(
                "INSERT INTO audit(ts,actor,action,target,data) VALUES(datetime('now'),?,?,?,?)",
                (actor, "incident_status_transition", str(data["incident_id"]),
                 json.dumps({"from": previous, "to": target}, default=str)),
            )

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        self._flush_before_read()
        limit = max(1, min(int(limit), 10_000))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT data FROM incidents ORDER BY rowid DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        self._flush_before_read()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM incidents WHERE id=?", (incident_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def save_host(self, host: Any) -> None:
        data = _payload(host)
        host_id = str(data["host_id"])
        last_seen = str(data.get("last_seen") or data.get("timestamp") or "")
        with self._lock, self._connect() as connection:
            previous = connection.execute("SELECT last_seen,data FROM hosts WHERE host_id=?", (host_id,)).fetchone()
            if previous:
                merged = json.loads(previous[1])
                merged.update({key: value for key, value in data.items() if value is not None})
                data = merged
                last_seen = max(last_seen, str(previous[0] or ""))
            connection.execute(
                "INSERT OR REPLACE INTO hosts(host_id,last_seen,data) VALUES(?,?,?)",
                (host_id, last_seen, json.dumps(data, default=str)),
            )

    def list_hosts(self, limit: int = 1000) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 10_000))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT data FROM hosts ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_response_action(self, action: Any) -> None:
        data = dict(_payload(action))
        action_id = str(data.get("action_id") or data.get("execution_id") or data.get("plan_id") or "")
        if not action_id:
            raise ValueError("Response action requires action_id or execution_id")
        timestamp = str(data.get("timestamp") or data.get("created_at") or data.get("planned_at") or "")
        data.setdefault("timestamp", timestamp)
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO response_actions(action_id,timestamp,status,data) VALUES(?,?,?,?)",
                (action_id, timestamp, str(data.get("status", "unknown")), json.dumps(data, default=str)),
            )

    def list_response_actions(self, limit: int = 500) -> list[dict[str, Any]]:
        self._flush_before_read()
        limit = max(1, min(int(limit), 10_000))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT data FROM response_actions ORDER BY rowid DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]

    def audit(self, actor: str, action: str, target: str | None = None, data: dict | None = None) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO audit(ts,actor,action,target,data) VALUES(datetime('now'),?,?,?,?)",
                (actor, action, target, json.dumps(data or {}, default=str)),
            )

    def save_autonomy_policy(self, data: dict[str, Any]) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO autonomy_policy(id,data,updated_at) VALUES(1,?,datetime('now')) "
                "ON CONFLICT(id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                (json.dumps(data, default=str),),
            )

    def load_autonomy_policy(self) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT data FROM autonomy_policy WHERE id=1").fetchone()
        return json.loads(row[0]) if row else None

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 10_000))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT ts,actor,action,target,data FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {"timestamp": row[0], "actor": row[1], "action": row[2], "target": row[3], "data": json.loads(row[4] or "{}")}
            for row in rows
        ]

    def register_auth_session(self, token_id: str, username: str, expires_at: int) -> None:
        if not isinstance(token_id, str) or not 16 <= len(token_id) <= 128:
            raise ValueError("Authentication session requires a valid token identifier.")
        if not isinstance(username, str) or not username or len(username) > 128:
            raise ValueError("Authentication session requires a valid username.")
        expiration = int(expires_at)
        now = int(time.time())
        if expiration <= now:
            raise ValueError("Authentication session must expire in the future.")
        with self._lock, self._connect() as connection:
            # Keep a short expired-session window for diagnostics without
            # letting the registry grow for the lifetime of the data plane.
            connection.execute(
                "DELETE FROM auth_sessions WHERE expires_at < ?", (now - 86_400,)
            )
            connection.execute(
                "INSERT INTO auth_sessions(token_id,username,expires_at,revoked_at) "
                "VALUES(?,?,?,NULL)",
                (token_id, username, expiration),
            )

    def auth_session_status(self, token_id: str) -> str:
        if not isinstance(token_id, str) or not token_id:
            return "unknown"
        with self._connect() as connection:
            row = connection.execute(
                "SELECT expires_at,revoked_at FROM auth_sessions WHERE token_id=?",
                (token_id,),
            ).fetchone()
        if row is None:
            return "unknown"
        if row[1] is not None:
            return "revoked"
        if int(row[0]) <= int(time.time()):
            return "expired"
        return "active"

    def revoke_auth_session(self, token_id: str) -> bool:
        if not isinstance(token_id, str) or not token_id:
            return False
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE auth_sessions SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE token_id=? AND revoked_at IS NULL AND expires_at>?",
                (token_id, int(time.time())),
            )
            return cursor.rowcount == 1

    def list_active_auth_sessions(self) -> list[dict[str, Any]]:
        now = int(time.time())
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT username,COUNT(*),MAX(expires_at) FROM auth_sessions "
                "WHERE revoked_at IS NULL AND expires_at>? GROUP BY username ORDER BY username",
                (now,),
            ).fetchall()
        return [
            {"username": row[0], "active_sessions": int(row[1]), "latest_expiration": int(row[2])}
            for row in rows
        ]

    def revoke_auth_sessions(self, username: str) -> int:
        if not isinstance(username, str) or not username.strip() or len(username) > 128:
            raise ValueError("Authentication session revocation requires a valid username.")
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE auth_sessions SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE username=? AND revoked_at IS NULL AND expires_at>?",
                (username, int(time.time())),
            )
            return cursor.rowcount
