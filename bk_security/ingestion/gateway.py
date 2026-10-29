"""Durable ingestion queue: acknowledge only after commit, dedupe, quota, quarantine, replay.

Single-host SQLite implementation of the Phase 16 contract. It proves the
semantics locally; it is not a distributed queue and makes no capacity claim.

Guarantees, each covered by tests:
- the queue file is bound to one customer deployment, like the customer database;
- an `accepted` ack is returned only after the envelope is committed;
- a queue row is marked done only after the core's store has flushed the event;
- delivery to the core is at-least-once with a deterministic event_id, so the
  customer database stays idempotent across replays;
- leases use wall-clock time and are fenced by an owner token;
- payloads are sanitized before storage; rejected input is kept only as a keyed hash;
- done rows (the dedupe window) and quarantine rows are pruned.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..deployment import DeploymentContext
from ..events.models import SecurityEvent
from ..events.sanitization import sanitize_security_event
from .envelope import EnvelopeError, parse_envelope

SCHEMA_VERSION = 2
_SCHEMA = """
CREATE TABLE IF NOT EXISTS binding(
  id INTEGER PRIMARY KEY CHECK(id=1), profile TEXT NOT NULL, customer_ref TEXT NOT NULL,
  deployment_id TEXT NOT NULL, region TEXT NOT NULL, hash_key BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS queue(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL, envelope_id TEXT NOT NULL,
  content_hash TEXT NOT NULL, payload TEXT, state TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0, lease_owner TEXT,
  received_at REAL NOT NULL, completed_at REAL, UNIQUE(agent_id, envelope_id));
CREATE INDEX IF NOT EXISTS idx_queue_open ON queue(lease_until, seq) WHERE state!='done';
CREATE INDEX IF NOT EXISTS idx_queue_done ON queue(completed_at) WHERE state='done';
CREATE TABLE IF NOT EXISTS quarantine(
  id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, reason_code TEXT NOT NULL, detail TEXT,
  raw_hash TEXT NOT NULL, raw_bytes INTEGER NOT NULL, ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS idx_quarantine_ts ON quarantine(ts);
"""

EventPolicy = Callable[[dict[str, Any]], "tuple[str, str] | None"]


@dataclass(frozen=True, slots=True)
class Ack:
    status: str  # accepted | duplicate | quarantined | throttled | backpressure
    envelope_id: str | None = None
    reason: str | None = None
    retry_after: float | None = None


@dataclass(frozen=True, slots=True)
class Lease:
    seq: int
    token: str
    attempt: int
    event: dict[str, Any]


class _Tx:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self.conn

    def __exit__(self, exc_type, *_) -> None:
        try:
            (self.conn.rollback if exc_type else self.conn.commit)()
        finally:
            self.conn.close()


def _raw_bytes(raw: Any) -> bytes:
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode("utf-8", "replace")
    try:
        return json.dumps(raw, sort_keys=True, default=str).encode()
    except (TypeError, ValueError, RecursionError):
        return repr(type(raw)).encode()


class IngestionQueue:
    def __init__(self, path: str, context: DeploymentContext, *, max_depth: int = 100_000,
                 agent_rate: float = 100.0, agent_burst: int = 200, max_attempts: int = 3,
                 lease_seconds: float = 30.0, retention_seconds: float = 7 * 86_400,
                 max_quarantine: int = 10_000, max_tracked_agents: int = 4096,
                 event_policy: EventPolicy | None = None, clock: Callable[[], float] = time.time) -> None:
        if path == ":memory:":
            raise ValueError("Durable ingestion requires a file-backed database.")
        if context.profile != "dedicated_customer":
            raise ValueError("Durable ingestion requires a dedicated customer deployment.")
        if max_depth < 1 or agent_burst < 1 or max_attempts < 1 or max_quarantine < 1 or max_tracked_agents < 1:
            raise ValueError("Ingestion limits must be positive integers.")
        if not (agent_rate > 0 and lease_seconds > 0 and retention_seconds > 0):
            raise ValueError("Ingestion rates and durations must be positive.")
        self.path, self.context = path, context
        self.max_depth, self.agent_rate, self.agent_burst = int(max_depth), float(agent_rate), int(agent_burst)
        self.max_attempts, self.lease_seconds = int(max_attempts), float(lease_seconds)
        self.retention_seconds, self.max_quarantine = float(retention_seconds), int(max_quarantine)
        self.max_tracked_agents, self.event_policy, self.clock = int(max_tracked_agents), event_policy, clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._bucket_lock = threading.Lock()
        self._hash_key = self._bind()

    # -- storage ------------------------------------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _db(self) -> _Tx:
        """One IMMEDIATE transaction, after re-checking that the file still belongs to this deployment."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._check_binding(conn)
        except BaseException:
            conn.close()
            raise
        return _Tx(conn)

    def _check_binding(self, conn: sqlite3.Connection) -> bytes:
        row = conn.execute("SELECT profile, customer_ref, deployment_id, region, hash_key FROM binding").fetchone()
        if row is None or tuple(row[:4]) != self.context.database_binding():
            raise ValueError("Ingestion queue is bound to a different customer deployment.")
        return bytes(row[4])

    def _bind(self) -> bytes:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            tables = {name for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if tables - {"sqlite_sequence"} and version != SCHEMA_VERSION:
                raise ValueError("Ingestion queue file has an incompatible schema; refusing to reuse it.")
            for statement in filter(None, (part.strip() for part in _SCHEMA.split(";"))):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            if conn.execute("SELECT 1 FROM binding").fetchone() is None:
                populated = conn.execute("SELECT (SELECT COUNT(*) FROM queue) + (SELECT COUNT(*) FROM quarantine)")
                if populated.fetchone()[0]:
                    raise ValueError("Unbound ingestion queue already holds data; refusing to bind it.")
                conn.execute("INSERT INTO binding VALUES(1,?,?,?,?,?)", (*self.context.database_binding(), os.urandom(32)))
            key = self._check_binding(conn)
            conn.execute("COMMIT")
            return key
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _keyed_hash(self, blob: bytes) -> str:
        return hmac.new(self._hash_key, blob, hashlib.sha256).hexdigest()

    def _quarantine(self, db: sqlite3.Connection, raw: Any, code: str, detail: str, agent: str | None) -> None:
        blob = _raw_bytes(raw)
        db.execute("INSERT INTO quarantine(agent_id,reason_code,detail,raw_hash,raw_bytes,ts) VALUES(?,?,?,?,?,?)",
                   (None if agent is None else str(agent)[:128], code, str(detail)[:256], self._keyed_hash(blob),
                    len(blob), self.clock()))
        db.execute("DELETE FROM quarantine WHERE id <= (SELECT MAX(id) FROM quarantine) - ?", (self.max_quarantine,))

    # -- admission ----------------------------------------------------------------------------------------------

    def _take_token(self, agent: str) -> float | None:
        now = time.monotonic()  # process-local rate state; never persisted
        with self._bucket_lock:
            tokens, last = self._buckets.pop(agent, (float(self.agent_burst), now))
            tokens = min(float(self.agent_burst), tokens + max(0.0, now - last) * self.agent_rate)
            allowed = tokens >= 1.0
            self._buckets[agent] = (tokens - 1.0 if allowed else tokens, now)
            while len(self._buckets) > self.max_tracked_agents:
                self._buckets.popitem(last=False)
        return None if allowed else (1.0 - tokens) / self.agent_rate

    def submit(self, raw: bytes | str | dict, *, authenticated_agent: str) -> Ack:
        """Return an Ack only once the outcome is durably recorded."""
        retry = self._take_token(authenticated_agent)
        if retry is not None:
            return Ack("throttled", reason="agent_quota", retry_after=retry)
        try:
            env = parse_envelope(raw, self.context, received_at=datetime.fromtimestamp(self.clock(), timezone.utc))
            if env.agent_id != authenticated_agent:
                raise EnvelopeError("agent_mismatch", "Envelope agent_id differs from the authenticated agent.")
            rejection = self.event_policy(env.event) if self.event_policy else None
            if rejection:
                raise EnvelopeError(*rejection)
            event = sanitize_security_event(SecurityEvent(**env.event))
            payload = json.dumps(event.to_dict(), separators=(",", ":"), default=str)
        except EnvelopeError as exc:
            return self._reject(raw, exc.code, str(exc), authenticated_agent)
        except Exception as exc:  # noqa: BLE001 - hostile input must never escape as a 500 without a record
            return self._reject(raw, "invalid_envelope", type(exc).__name__, authenticated_agent)
        content_hash = self._keyed_hash(env.content.encode())
        with self._db() as db:
            existing = db.execute("SELECT content_hash FROM queue WHERE agent_id=? AND envelope_id=?",
                                  (env.agent_id, env.envelope_id)).fetchone()
            if existing:
                if hmac.compare_digest(existing[0], content_hash):
                    return Ack("duplicate", env.envelope_id)
                self._quarantine(db, raw, "envelope_id_conflict", "envelope_id reused with different content",
                                 authenticated_agent)
                return Ack("quarantined", env.envelope_id, "envelope_id_conflict")
            depth = db.execute("SELECT COUNT(*) FROM queue WHERE state!='done'").fetchone()[0]
            if depth >= self.max_depth:
                return Ack("backpressure", env.envelope_id, "queue_full", retry_after=1.0)
            db.execute("INSERT INTO queue(agent_id,envelope_id,content_hash,payload,received_at) VALUES(?,?,?,?,?)",
                       (env.agent_id, env.envelope_id, content_hash, payload, self.clock()))
        return Ack("accepted", env.envelope_id)

    def _reject(self, raw: Any, code: str, detail: str, agent: str) -> Ack:
        with self._db() as db:
            self._quarantine(db, raw, code, detail, agent)
        return Ack("quarantined", reason=code)

    # -- consumption --------------------------------------------------------------------------------------------

    def claim(self, limit: int = 100) -> list[Lease]:
        """Lease pending or expired-lease items; abandoned items past max_attempts are quarantined."""
        now, token, leases = self.clock(), uuid.uuid4().hex, []
        with self._db() as db:
            rows = db.execute("SELECT seq,agent_id,payload,attempts FROM queue WHERE state!='done' AND lease_until<=? "
                              "ORDER BY seq LIMIT ?", (now, int(limit))).fetchall()
            for seq, agent, payload, attempts in rows:
                if attempts >= self.max_attempts:
                    self._quarantine(db, payload or "", "processing_abandoned",
                                     f"lease expired after {attempts} attempts", agent)
                    db.execute("UPDATE queue SET state='done', payload=NULL, completed_at=?, lease_owner=NULL "
                               "WHERE seq=?", (now, seq))
                    continue
                db.execute("UPDATE queue SET state='leased', lease_until=?, lease_owner=?, attempts=attempts+1 "
                           "WHERE seq=?", (now + self.lease_seconds, token, seq))
                leases.append(Lease(seq, token, attempts + 1, json.loads(payload)))
        return leases

    def complete(self, leases: list[Lease]) -> int:
        """Mark leased items done; a lease that expired and was re-claimed by someone else is ignored."""
        done = 0
        with self._db() as db:
            for lease in leases:
                done += db.execute("UPDATE queue SET state='done', payload=NULL, completed_at=?, lease_owner=NULL "
                                   "WHERE seq=? AND lease_owner=? AND state='leased'",
                                   (self.clock(), lease.seq, lease.token)).rowcount
        return done

    def fail(self, lease: Lease, reason: str) -> None:
        """Release for retry, or quarantine once attempts are exhausted. Fenced by the lease owner."""
        with self._db() as db:
            row = db.execute("SELECT agent_id,payload,attempts FROM queue WHERE seq=? AND lease_owner=? "
                             "AND state='leased'", (lease.seq, lease.token)).fetchone()
            if row is None:
                return
            if row[2] >= self.max_attempts:
                self._quarantine(db, row[1] or "", "processing_failed", reason, row[0])
                db.execute("UPDATE queue SET state='done', payload=NULL, completed_at=?, lease_owner=NULL WHERE seq=?",
                           (self.clock(), lease.seq))
            else:
                db.execute("UPDATE queue SET state='pending', lease_until=0, lease_owner=NULL WHERE seq=?",
                           (lease.seq,))

    def drain(self, core, limit: int = 100, *, flush_timeout: float = 10.0) -> dict[str, int]:
        """Feed leased events to the core; ack each only after the core's store has flushed it."""
        ingested, failed = [], 0
        store = getattr(core, "store", None)
        for lease in self.claim(limit):
            try:
                already = lease.attempt > 1 and store is not None and store.get_event(lease.event["event_id"])
                if not already:
                    core.ingest(SecurityEvent(**lease.event))
            except Exception as exc:  # noqa: BLE001 - any processing failure is retried, then quarantined
                self.fail(lease, type(exc).__name__)
                failed += 1
            else:
                ingested.append(lease)
        flush = getattr(store, "flush", None)
        if ingested and callable(flush):
            try:
                flush(flush_timeout)
            except Exception as exc:  # noqa: BLE001 - not durable yet, so not acknowledged
                for lease in ingested:
                    self.fail(lease, f"store_flush_failed:{type(exc).__name__}")
                return {"processed": 0, "failed": failed + len(ingested)}
        processed = self.complete(ingested)
        self.prune()
        return {"processed": processed, "failed": failed}

    def prune(self) -> dict[str, int]:
        """Drop done rows past the dedupe window and quarantine rows past retention."""
        cutoff = self.clock() - self.retention_seconds
        with self._db() as db:
            done = db.execute("DELETE FROM queue WHERE state='done' AND completed_at < ?", (cutoff,)).rowcount
            quarantined = db.execute("DELETE FROM quarantine WHERE ts < ?", (cutoff,)).rowcount
        return {"done_rows": done, "quarantine_rows": quarantined}

    def stats(self) -> dict[str, int]:
        with self._db() as db:
            counts = dict(db.execute("SELECT state,COUNT(*) FROM queue GROUP BY state").fetchall())
            return {"pending": counts.get("pending", 0), "leased": counts.get("leased", 0),
                    "done": counts.get("done", 0),
                    "quarantined": db.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]}
