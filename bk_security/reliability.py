"""Integrity monitoring and bounded, auditable recovery for BK Security.

This module deliberately contains no code-writing or policy-changing repair.
Runtime integrations may register only the enumerated reversible actions.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Callable


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RepairAction(str, Enum):
    RESTART_WORKER = "restart_worker"
    INTERNAL_RECONNECT = "internal_reconnect"
    REBUILD_CACHE_INDEX = "rebuild_cache_index"
    RELOAD_VALIDATED_CONFIG = "reload_validated_config"
    RELAUNCH_PIPELINE = "relaunch_pipeline"
    DISABLE_OPTIONAL_COMPONENT = "disable_optional_component"
    ROLLBACK_RELEASE = "rollback_release"


@dataclass(slots=True)
class ComponentHealth:
    name: str
    status: str
    score: int
    critical: bool
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "score": self.score,
            "critical": self.critical,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(slots=True)
class IntegrityReport:
    status: str
    score: int
    checked_at: str
    components: dict[str, ComponentHealth]
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "integrity_score": self.score,
            "checked_at": self.checked_at,
            "components": {key: value.to_dict() for key, value in self.components.items()},
            "diagnostics": list(self.diagnostics),
        }


class ReliabilityLedger:
    """Persist LKG state and a hash-chained, append-only diagnostic audit."""

    def __init__(self, store: Any) -> None:
        raw_path = getattr(store, "path", None)
        self.path = str(raw_path) if raw_path and str(raw_path) != ":memory:" else None
        self._lock = threading.RLock()
        self._memory_state: dict[str, Any] = {}
        self._memory_audit: list[dict[str, Any]] = []
        if self.path:
            self._ensure_schema()

    def _connect(self):
        assert self.path is not None
        return sqlite3.connect(self.path, timeout=5.0)

    def _ensure_schema(self) -> None:
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS bk_reliability_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS bk_reliability_audit ("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, "
                "action TEXT NOT NULL, target TEXT, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, "
                "event_hash TEXT NOT NULL UNIQUE)"
            )
            db.execute(
                "CREATE TRIGGER IF NOT EXISTS bk_reliability_audit_no_update "
                "BEFORE UPDATE ON bk_reliability_audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END"
            )
            db.execute(
                "CREATE TRIGGER IF NOT EXISTS bk_reliability_audit_no_delete "
                "BEFORE DELETE ON bk_reliability_audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END"
            )

    def get_state(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if not self.path:
                return self._memory_state.get(key, default)
            with self._connect() as db:
                row = db.execute("SELECT value FROM bk_reliability_state WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set_state(self, key: str, value: Any) -> None:
        packed = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        with self._lock:
            if not self.path:
                self._memory_state[key] = json.loads(packed)
                return
            with self._connect() as db:
                db.execute(
                    "INSERT INTO bk_reliability_state(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, packed),
                )

    def append(self, actor: str, action: str, target: str | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        event = {
            "ts": _now(), "actor": str(actor), "action": str(action),
            "target": target, "payload": payload or {},
        }
        packed = json.dumps(event["payload"], sort_keys=True, separators=(",", ":"), default=str)
        with self._lock:
            if not self.path:
                previous = self._memory_audit[-1]["event_hash"] if self._memory_audit else "0" * 64
                event_hash = hashlib.sha256((previous + "\n" + event["ts"] + "\n" + event["actor"] + "\n" + event["action"] + "\n" + str(target) + "\n" + packed).encode()).hexdigest()
                row = {**event, "payload": json.loads(packed), "prev_hash": previous, "event_hash": event_hash}
                self._memory_audit.append(row)
                return row
            with self._connect() as db:
                row = db.execute("SELECT event_hash FROM bk_reliability_audit ORDER BY seq DESC LIMIT 1").fetchone()
                previous = row[0] if row else "0" * 64
                event_hash = hashlib.sha256((previous + "\n" + event["ts"] + "\n" + event["actor"] + "\n" + event["action"] + "\n" + str(target) + "\n" + packed).encode()).hexdigest()
                cursor = db.execute(
                    "INSERT INTO bk_reliability_audit(ts,actor,action,target,payload,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
                    (event["ts"], event["actor"], event["action"], target, packed, previous, event_hash),
                )
                seq = cursor.lastrowid
            return {**event, "seq": seq, "payload": json.loads(packed), "prev_hash": previous, "event_hash": event_hash}

    def verify_audit(self) -> tuple[bool, str | None]:
        def verify_rows(rows) -> tuple[bool, str | None]:
            previous = "0" * 64
            for seq, ts, actor, action, target, payload, prev_hash, event_hash in rows:
                if prev_hash != previous:
                    return False, f"Audit chain link is invalid at sequence {seq}."
                calculated = hashlib.sha256((previous + "\n" + ts + "\n" + actor + "\n" + action + "\n" + str(target) + "\n" + payload).encode()).hexdigest()
                if calculated != event_hash:
                    return False, f"Audit event hash is invalid at sequence {seq}."
                previous = event_hash
            return True, None

        with self._lock:
            if self.path:
                with self._connect() as db:
                    rows = db.execute(
                        "SELECT seq,ts,actor,action,target,payload,prev_hash,event_hash "
                        "FROM bk_reliability_audit ORDER BY seq"
                    )
                    # Iterate the SQLite cursor so audit verification does not
                    # materialize the full append-only ledger in memory.
                    return verify_rows(rows)
            rows = [
                (i + 1, row["ts"], row["actor"], row["action"], row["target"],
                 json.dumps(row["payload"], sort_keys=True, separators=(",", ":")), row["prev_hash"], row["event_hash"])
                for i, row in enumerate(self._memory_audit)
            ]
            return verify_rows(rows)

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            if not self.path:
                return [dict(row) for row in reversed(self._memory_audit[-limit:])]
            with self._connect() as db:
                rows = db.execute(
                    "SELECT seq,ts,actor,action,target,payload,prev_hash,event_hash "
                    "FROM bk_reliability_audit ORDER BY seq DESC LIMIT ?", (limit,)
                ).fetchall()
        return [
            {"seq": r[0], "ts": r[1], "actor": r[2], "action": r[3], "target": r[4],
             "payload": json.loads(r[5]), "prev_hash": r[6], "event_hash": r[7]}
            for r in rows
        ]


class IntegrityMonitor:
    """Read-only checks of critical BK-owned components and persisted schema."""

    WEIGHTS = {
        "core": 15, "detection": 15, "correlation": 10, "threat_family": 8,
        "ai_soc": 10, "db": 15, "api_rbac": 10, "response": 7, "runtime": 5,
        "configuration": 5,
    }
    CRITICAL = {"core", "detection", "correlation", "db", "api_rbac", "configuration"}

    def __init__(self, core: Any, app: Any = None, runtime: Any = None) -> None:
        self.core = core
        self.app = app
        self.runtime = runtime
        self.ledger = ReliabilityLedger(core.store)

    @staticmethod
    def _component(name: str, ok: bool | None, details: str = "") -> ComponentHealth:
        if ok is None:
            return ComponentHealth(name, "not_checked", 0, name in IntegrityMonitor.CRITICAL, [details] if details else [])
        return ComponentHealth(name, "ok" if ok else "failed", 100 if ok else 0, name in IntegrityMonitor.CRITICAL, [] if ok else [details or "Invariant check failed."])

    def _db_check(self, *, deep: bool = True) -> tuple[bool | None, str]:
        store = self.core.store
        try:
            flush = getattr(store, "flush", None)
            if callable(flush):
                flush()
            path = getattr(store, "path", None)
            if not path or str(path) == ":memory:":
                return True, "Repository exposes no file-backed schema to inspect."
            with sqlite3.connect(str(path), timeout=5) as db:
                quick = db.execute("PRAGMA quick_check").fetchone() if deep else db.execute("SELECT 1").fetchone()
                tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {"events", "alerts", "incidents", "audit", "hosts", "response_actions"}
            if deep and (not quick or quick[0] != "ok"):
                return False, f"SQLite quick_check failed: {quick[0] if quick else 'no result'}."
            missing = sorted(required - tables)
            if missing:
                return False, "Required database tables are missing: " + ", ".join(missing)
            return True, "SQLite integrity and required tables are healthy."
        except Exception as exc:
            return False, f"Database check failed: {type(exc).__name__}: {exc}"

    @staticmethod
    def _configuration_check() -> tuple[bool, str]:
        problems = []
        environment = os.getenv("BK_SECURITY_ENV", "development").lower()
        if environment not in {"development", "test", "staging", "production"}:
            problems.append("BK_SECURITY_ENV is unsupported.")
        if environment == "production":
            secret = os.getenv("BK_SECURITY_AUTH_SECRET", "")
            if len(secret.encode("utf-8")) < 32 or secret == "CHANGE-ME-BK-SECURITY":
                problems.append("Production authentication secret is missing or too short.")
        if os.getenv("BK_SECURITY_CAPTURE_MODE", "stopped").lower() not in {"live", "simulation", "stopped"}:
            problems.append("BK_SECURITY_CAPTURE_MODE must be live, simulation or stopped.")
        try:
            rate = int(os.getenv("BK_SECURITY_MAX_EVENTS_PER_SECOND", "500"))
            if not 1 <= rate <= 50_000:
                problems.append("BK_SECURITY_MAX_EVENTS_PER_SECOND is outside the supported range.")
        except ValueError:
            problems.append("BK_SECURITY_MAX_EVENTS_PER_SECOND must be an integer.")
        try:
            request_limit = int(os.getenv("BK_SECURITY_MAX_REQUEST_BYTES", "1048576"))
            if not 1024 <= request_limit <= 10_485_760:
                problems.append("BK_SECURITY_MAX_REQUEST_BYTES is outside the supported range.")
        except ValueError:
            problems.append("BK_SECURITY_MAX_REQUEST_BYTES must be an integer.")
        origins = [item.strip() for item in os.getenv("BK_SECURITY_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if item.strip()]
        if "*" in origins:
            problems.append("Wildcard CORS origins are not allowed.")
        if problems:
            return False, " ".join(problems)
        return True, "Security runtime configuration passes validation."

    def inspect(self, *, include_forced_status: bool = True, deep: bool = True) -> IntegrityReport:
        core = self.core
        components: dict[str, ComponentHealth] = {}
        components["core"] = self._component("core", callable(getattr(core, "ingest", None)), "Core ingest entry point is unavailable.")
        components["detection"] = self._component("detection", callable(getattr(getattr(core, "detector", None), "evaluate", None)), "Detection engine is unavailable.")
        correlation_ok, correlation_message = self._correlation_check()
        components["correlation"] = self._component("correlation", correlation_ok, correlation_message)
        components["threat_family"] = self._component("threat_family", callable(getattr(core, "_attach_threat_family", None)), "Threat Family attachment contract is unavailable.")
        workers = getattr(getattr(core, "ai", None), "workers", None)
        workers_ok = bool(workers) and all(callable(getattr(w, "can_handle", None)) and callable(getattr(w, "investigate", None)) for w in workers)
        components["ai_soc"] = self._component("ai_soc", workers_ok, "AI SOC has no workers or a worker contract is incomplete.")
        db_ok, db_message = self._db_check(deep=deep)
        components["db"] = self._component("db", db_ok, db_message)
        if self.app is None:
            components["api_rbac"] = self._component("api_rbac", None, "API is not attached to this monitor.")
        else:
            route_map = {}

            def collect_routes(routes, prefix: str = "") -> None:
                for route in routes:
                    original_router = getattr(route, "original_router", None)
                    if original_router is not None:
                        context = getattr(route, "include_context", None)
                        # FastAPI's router stores child paths with its own
                        # prefix already applied; only the include context is
                        # additional here.
                        nested_prefix = prefix + str(getattr(context, "prefix", ""))
                        collect_routes(getattr(original_router, "routes", []), nested_prefix)
                    else:
                        path = getattr(route, "path", None)
                        if path:
                            route_map[prefix + path] = route

            collect_routes(getattr(self.app, "routes", []))
            def allowed(path: str) -> set[str]:
                route = route_map.get(path)
                dependencies = getattr(getattr(route, "dependant", None), "dependencies", [])
                return set().union(*(set(getattr(getattr(dep, "call", None), "allowed_roles", ())) for dep in dependencies)) if dependencies else set()
            investigation_roles = allowed("/api/v1/alerts/{alert_id}/investigate")
            repair_roles = allowed("/api/v1/reliability/repair")
            response_plan_roles = allowed("/api/v1/response/plan")
            response_approval_roles = allowed("/api/v1/response/approve/{plan_id}")
            response_roles = allowed("/api/v1/response/execute")
            api_ok = (
                callable(getattr(self.app, "openapi", None))
                and {"admin", "analyst", "viewer"}.issubset(investigation_roles)
                and repair_roles == {"admin"}
                and {"admin", "analyst"}.issubset(response_plan_roles)
                and response_approval_roles == {"approver"}
                and response_roles == {"responder"}
            )
            components["api_rbac"] = self._component("api_rbac", api_ok, "Authenticated investigation route is missing.")
        components["response"] = self._component("response", callable(getattr(getattr(core, "response", None), "execute", None)), "Response engine is unavailable.")
        config_ok, config_message = self._configuration_check()
        components["configuration"] = self._component("configuration", config_ok, config_message)
        runtime = self.runtime
        if runtime is None:
            from .capture.pipeline import PacketPipeline
            pipeline_ok = callable(getattr(PacketPipeline, "observe", None))
            components["runtime"] = self._component("runtime", None if pipeline_ok else False, "Capture pipeline contract is unavailable; runtime sensors are not attached to this monitor.")
        else:
            manager = getattr(runtime, "sensor_manager", runtime)
            status = getattr(manager, "status", None)
            try:
                from .capture.pipeline import PacketPipeline
                runtime_ok = callable(status) and isinstance(status(), dict) and callable(getattr(PacketPipeline, "observe", None))
            except Exception:
                runtime_ok = False
            components["runtime"] = self._component("runtime", runtime_ok, "Runtime status check failed.")

        diagnostics = []
        audit_ok, audit_error = self.ledger.verify_audit()
        if not audit_ok and audit_error:
            diagnostics.append(audit_error)
        for item in components.values():
            diagnostics.extend(f"{item.name}: {message}" for message in item.diagnostics)
        total = sum(self.WEIGHTS[name] for name, item in components.items() if item.status != "not_checked")
        score = round(sum(self.WEIGHTS[name] * item.score for name, item in components.items() if item.status != "not_checked") / total) if total else 0
        forced_status = self.ledger.get_state("system_status") if include_forced_status else None
        if not audit_ok:
            score = min(score, 49)
        elif forced_status == "BLOCKED":
            score = min(score, 49)
        elif forced_status == "DEGRADED":
            score = min(score, 79)
        if forced_status in {"BLOCKED", "DEGRADED"}:
            diagnostics.append(f"reliability recovery state: {forced_status}")
        if forced_status == "BLOCKED" or not audit_ok or any(item.status == "failed" and item.critical for item in components.values()):
            state = "BLOCKED"
        elif forced_status == "DEGRADED" or any(item.status == "failed" for item in components.values()):
            state = "DEGRADED"
        else:
            state = "SAFE"
        return IntegrityReport(state, score, _now(), components, diagnostics)

    def _correlation_check(self) -> tuple[bool, str]:
        correlation = getattr(self.core, "correlation", None)
        if not callable(getattr(correlation, "restore", None)):
            return False, "Correlation engine restore contract is unavailable."
        cache = getattr(correlation, "_by_host", None)
        if not isinstance(cache, dict):
            return False, "Correlation cache has an invalid container."
        known_alerts = {alert.alert_id: alert for alert in getattr(self.core, "alerts", [])}
        for host_id, clusters in cache.items():
            if not host_id or not hasattr(clusters, "__iter__"):
                return False, "Correlation cache contains an invalid host entry."
            for cluster in clusters:
                last_seen = getattr(cluster, "last_seen", None)
                alert_ids = getattr(cluster, "alert_ids", None)
                if not isinstance(last_seen, (int, float)) or not math.isfinite(float(last_seen)) or not hasattr(alert_ids, "__iter__"):
                    return False, "Correlation cache contains an invalid cluster."
                if any(alert_id not in known_alerts for alert_id in alert_ids):
                    return False, "Correlation cache references an alert that is no longer available."
                if any(known_alerts[alert_id].host_id != host_id for alert_id in alert_ids):
                    return False, "Correlation cache host partition does not match its alert evidence."
        return True, "Correlation index is coherent with retained alert evidence."


class SafeAutoRepair:
    """Execute registered reversible repairs with a mandatory post-check and loop guard."""

    def __init__(self, ledger: ReliabilityLedger, handlers: dict[RepairAction, Callable[[str], Any]] | None = None, *, max_attempts: int = 2, window_seconds: int = 300) -> None:
        self.ledger = ledger
        self.handlers = dict(handlers or {})
        self.max_attempts = max(1, int(max_attempts))
        self.window_seconds = max(1, int(window_seconds))
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._results: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.RLock()

    def register(self, action: RepairAction, handler: Callable[[str], Any]) -> None:
        if not isinstance(action, RepairAction) or not callable(handler):
            raise ValueError("Only an enumerated safe repair and callable handler may be registered.")
        self.handlers[action] = handler

    def apply(self, action: RepairAction | str, target: str, *, validate: Callable[[], bool], actor: str = "bk-regression-guardian", idempotency_key: str | None = None) -> dict[str, Any]:
        try:
            selected = action if isinstance(action, RepairAction) else RepairAction(str(action))
        except ValueError:
            self.ledger.append(actor, "repair_rejected", target, {"action": str(action), "reason": "not_allowlisted"})
            return {"status": "BLOCKED", "reason": "Repair action is not allowlisted."}
        if not callable(validate):
            raise ValueError("A post-repair validator is required.")
        key = idempotency_key or f"{selected.value}:{target}"
        with self._lock:
            now = time.monotonic()
            cached = self._results.get(key)
            if cached and now - cached[0] <= self.window_seconds:
                return dict(cached[1])
            self._results.pop(key, None)
            handler = self.handlers.get(selected)
            if handler is None:
                self.ledger.append(actor, "repair_rejected", target, {"action": selected.value, "reason": "no_safe_handler_registered"})
                return {"status": "BLOCKED", "reason": "No safe runtime handler is registered for this action."}
            attempts = self._attempts[f"{selected.value}:{target}"]
            while attempts and now - attempts[0] > self.window_seconds:
                attempts.popleft()
            if len(attempts) >= self.max_attempts:
                result = {"status": "BLOCKED", "reason": "Repair loop guard reached its attempt limit."}
                self.ledger.append(actor, "repair_loop_blocked", target, {"action": selected.value, "attempts": len(attempts)})
                return result
            attempts.append(now)

        self.ledger.append(actor, "repair_started", target, {"action": selected.value, "idempotency_key": key})
        try:
            handler(target)
            valid = bool(validate())
        except Exception as exc:
            valid = False
            error = f"{type(exc).__name__}: {exc}"
        else:
            error = "post_repair_validation_failed" if not valid else ""
        result = {"status": "SUCCEEDED" if valid else "DEGRADED", "action": selected.value, "target": target, "validated": valid}
        if error:
            result["diagnostic"] = error
        self.ledger.append(actor, "repair_succeeded" if valid else "repair_failed", target, result)
        if valid:
            with self._lock:
                self._results[key] = (time.monotonic(), dict(result))
        return result


class ReliabilityService:
    """Product facade tying integrity reports, audit, LKG and safe repairs together."""

    REQUIRED_RELEASE_CHECKS = {"critical_tests", "full_tests", "compile"}

    def __init__(self, core: Any, app: Any = None, runtime: Any = None, repair_handlers: dict[RepairAction, Callable[[str], Any]] | None = None) -> None:
        self.core = core
        self.monitor = IntegrityMonitor(core, app, runtime)
        handlers = dict(repair_handlers or {})
        correlation = getattr(core, "correlation", None)
        if callable(getattr(correlation, "restore", None)):
            handlers.setdefault(RepairAction.REBUILD_CACHE_INDEX, self._rebuild_correlation_index)
        self.repairs = SafeAutoRepair(self.monitor.ledger, handlers)

    def _rebuild_correlation_index(self, _target: str) -> None:
        active = {
            item.incident_id for item in getattr(self.core, "incidents", [])
            if str(getattr(item, "status", "")).upper() not in {"RESOLVED", "CLOSED"}
        }
        self.core.correlation._by_host.clear()
        self.core.correlation.restore(self.core.alerts, active)

    def integrity(self) -> IntegrityReport:
        report = self.monitor.inspect()
        self.monitor.ledger.append("integrity-monitor", "diagnostic", None, {"status": report.status, "integrity_score": report.score, "diagnostics": report.diagnostics})
        return report

    def record_last_known_good(
        self,
        version: str,
        config_fingerprint: str,
        artifact_digest: str,
        *,
        checks: dict[str, bool] | None = None,
        canary_healthy: bool = False,
        configuration: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not version or not config_fingerprint or not artifact_digest:
            raise ValueError("Last Known Good requires version, configuration fingerprint, and artifact digest.")
        missing_checks = sorted(self.REQUIRED_RELEASE_CHECKS - set(checks or {}))
        if missing_checks or not checks or not all(checks.values()) or not canary_healthy:
            self.monitor.ledger.append("release-gate", "lkg_rejected", version, {
                "reason": "validated_checks_and_canary_required", "missing_checks": missing_checks,
                "checks": checks or {}, "canary_healthy": canary_healthy,
            })
            raise RuntimeError("Last Known Good requires passing critical/full/compile checks and a healthy canary.")
        report = self.integrity()
        if report.status != "SAFE":
            self.monitor.ledger.append("release-gate", "lkg_rejected", version, {"status": report.status, "integrity_score": report.score})
            raise RuntimeError("Last Known Good can only be recorded from a SAFE, validated release.")
        if not isinstance(configuration, dict) or not configuration:
            raise ValueError("Last Known Good requires a sanitized configuration snapshot.")
        safe_configuration = {}
        for key, value in configuration.items():
            if any(marker in str(key).lower() for marker in ("secret", "password", "token", "key")):
                raise ValueError("Last Known Good configuration cannot contain secrets or credentials.")
            safe_configuration[str(key)] = value
        actual_config_fingerprint = hashlib.sha256(json.dumps(safe_configuration, sort_keys=True).encode("utf-8")).hexdigest()
        if actual_config_fingerprint != config_fingerprint:
            raise ValueError("Last Known Good configuration fingerprint does not match its snapshot.")
        record = {"version": str(version), "config_fingerprint": str(config_fingerprint), "artifact_digest": str(artifact_digest), "configuration": safe_configuration, "validated_at": _now()}
        self.monitor.ledger.set_state("last_known_good", record)
        self.monitor.ledger.append("release-gate", "lkg_recorded", version, {"config_fingerprint": config_fingerprint, "artifact_digest": artifact_digest})
        return record

    def guard_candidate(
        self,
        version: str,
        checks: dict[str, bool],
        *,
        canary_healthy: bool,
        config_fingerprint: str,
        artifact_digest: str,
        configuration: dict[str, Any] | None = None,
        candidate_activated: bool = False,
        activate_lkg: Callable[[dict[str, Any]], Any] | None = None,
        validate_rollback: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        """Block an unhealthy candidate; roll back an activated one through a runtime adapter."""
        failures = sorted(name for name, passed in checks.items() if not passed)
        if not checks:
            failures.append("checks:not-supplied")
        failures.extend(f"check_missing:{name}" for name in sorted(self.REQUIRED_RELEASE_CHECKS - set(checks)))
        report = self.monitor.inspect(include_forced_status=False)
        if report.status != "SAFE":
            failures.append(f"integrity:{report.status}")
        if not canary_healthy:
            failures.append("canary:unhealthy")
        if failures:
            reason = ", ".join(failures)
            self.monitor.ledger.set_state("system_status", "BLOCKED")
            self.monitor.ledger.set_state("release_status", "BLOCKED")
            self.monitor.ledger.append("bk-regression-guardian", "candidate_blocked", version, {
                "failed_checks": failures,
                "integrity_score": report.score,
                "candidate_activated": candidate_activated,
            })
            if candidate_activated:
                rollback = self.rollback_to_last_known_good(
                    reason,
                    activate=activate_lkg,
                    validate=validate_rollback,
                )
                return {"status": "BLOCKED", "candidate": version, "rollback": rollback, "failed_checks": failures}
            return {"status": "BLOCKED", "candidate": version, "active_version": (self.monitor.ledger.get_state("active_release") or {}).get("version"), "last_known_good": (self.monitor.ledger.get_state("last_known_good") or {}).get("version"), "failed_checks": failures}

        # A candidate becomes LKG only after the critical checks, complete
        # integrity inspection and canary have all passed.
        self.monitor.ledger.set_state("system_status", "SAFE")
        self.monitor.ledger.set_state("release_status", "SAFE")
        try:
            known = self.record_last_known_good(
                version,
                config_fingerprint,
                artifact_digest,
                checks=checks,
                canary_healthy=canary_healthy,
                configuration=configuration,
            )
        except Exception:
            self.monitor.ledger.set_state("system_status", "BLOCKED")
            self.monitor.ledger.set_state("release_status", "BLOCKED")
            raise
        if candidate_activated:
            self.monitor.ledger.set_state("active_release", known)
        self.monitor.ledger.append("bk-regression-guardian", "candidate_accepted", version, {
            "checks": checks, "canary_healthy": canary_healthy, "integrity_score": report.score,
        })
        return {"status": "SAFE", "candidate": version, "last_known_good": known}

    def rollback_to_last_known_good(self, reason: str, activate: Callable[[dict[str, Any]], Any] | None = None, *, validate: Callable[[], bool] | None = None) -> dict[str, Any]:
        known = self.monitor.ledger.get_state("last_known_good")
        if not known:
            self.monitor.ledger.append("bk-regression-guardian", "rollback_blocked", None, {"reason": "no_last_known_good", "diagnostic": reason})
            return {"status": "BLOCKED", "reason": "No validated Last Known Good release is recorded."}
        if not callable(activate) or not callable(validate):
            self.monitor.ledger.append("bk-regression-guardian", "rollback_blocked", known.get("version"), {"reason": "release_activation_handler_unavailable", "diagnostic": reason})
            return {"status": "BLOCKED", "reason": "Release activation and post-rollback validation handlers are required."}
        try:
            activate(known)
            healthy = bool(validate())
        except Exception as exc:
            healthy = False
            detail = f"{type(exc).__name__}: {exc}"
        else:
            detail = "post_rollback_validation_failed" if not healthy else ""
        status = "ROLLED_BACK" if healthy else "BLOCKED"
        result = {"status": status, "restored_version": known.get("version"), "reason": reason, "validated": healthy}
        if detail:
            result["diagnostic"] = detail
        if healthy:
            self.monitor.ledger.set_state("active_release", known)
            self.monitor.ledger.set_state("system_status", "SAFE")
            self.monitor.ledger.set_state("release_status", "SAFE")
        else:
            self.monitor.ledger.set_state("system_status", "BLOCKED")
            self.monitor.ledger.set_state("release_status", "BLOCKED")
        self.monitor.ledger.append("bk-regression-guardian", "automatic_rollback" if healthy else "rollback_failed", known.get("version"), result)
        return result

    def run_safe_repair(self, action: RepairAction | str, target: str, *, actor: str = "admin") -> dict[str, Any]:
        def post_check() -> bool:
            report = self.monitor.inspect(include_forced_status=False)
            component = report.components.get(target)
            return report.status != "BLOCKED" and (component is None or component.status == "ok")
        result = self.repairs.apply(action, target, validate=post_check, actor=actor)
        if result.get("status") == "SUCCEEDED":
            self.clear_degraded_state_after_validation()
        else:
            status = "BLOCKED" if "loop guard" in str(result.get("reason", "")) else "DEGRADED"
            self.monitor.ledger.set_state("system_status", status)
            self.monitor.ledger.append(actor, "system_status_changed", target, {"status": status, "repair": result})
        return result

    def clear_degraded_state_after_validation(self) -> bool:
        """Clear a recovery lock only after a fresh complete SAFE check."""
        previous = self.monitor.ledger.get_state("system_status")
        self.monitor.ledger.set_state("system_status", "SAFE")
        report = self.monitor.inspect()
        if report.status != "SAFE":
            self.monitor.ledger.set_state("system_status", previous or "DEGRADED")
            return False
        self.monitor.ledger.append("integrity-monitor", "recovery_state_cleared", None, {"integrity_score": report.score})
        return True


class BKRegressionGuardian:
    """AI SOC worker/service: diagnose BK health and recommend safe actions only."""

    name = "bk_regression_guardian"

    def __init__(self, service: ReliabilityService) -> None:
        self.service = service

    def can_handle(self, request: Any) -> bool:
        context = getattr(request, "threat_context", {}) or {}
        return bool(context.get("bk_self_diagnostic") or getattr(getattr(request, "alert", None), "alert_type", "") == "BK_INTEGRITY_DIAGNOSTIC")

    def diagnose(self) -> dict[str, Any]:
        before = self.service.integrity()
        repairs = []
        if before.components["correlation"].status == "failed":
            repair = self.service.run_safe_repair(
                RepairAction.REBUILD_CACHE_INDEX, "correlation", actor=self.name,
            )
            repairs.append(repair)
        report = self.service.integrity() if repairs else before
        failed = [component.to_dict() for component in report.components.values() if component.status in {"failed", "not_checked"}]
        recommendations = []
        for component in failed:
            if component["name"] == "correlation":
                recommendations.append({"action": RepairAction.REBUILD_CACHE_INDEX.value, "target": "correlation", "automatic": True})
            else:
                recommendations.append({"action": "operator_review", "target": component["name"], "automatic": False})
        if report.status != "SAFE":
            recommendations.append({"action": "block_candidate_and_preserve_lkg", "target": "release", "automatic": True})
        return {"integrity": report.to_dict(), "recommendations": recommendations,
                "safe_repairs": repairs, "code_modification_allowed": False}

    def investigate(self, request: Any):
        from .ai.contracts import InvestigationResult

        diagnosis = self.diagnose()
        report = diagnosis["integrity"]
        failed = [component for component in report["components"].values() if component["status"] in {"failed", "not_checked"}]
        recommendations = []
        for component in failed:
            if component["name"] == "correlation":
                recommendations.append("Rebuild the correlation cache/index, then rerun integrity validation.")
            else:
                recommendations.append(f"Keep {component['name']} in degraded/blocked state and require operator review.")
        if report["status"] != "SAFE":
            recommendations.append("Block the candidate release and preserve the Last Known Good release until validation passes.")
        evidence = [{"type": "integrity_component", **item} for item in failed]
        evidence.extend({"type": "repair_validation", **item} for item in diagnosis["safe_repairs"])
        if not evidence:
            evidence = [{"type": "integrity_report", "status": report["status"], "integrity_score": report["integrity_score"]}]
        result = InvestigationResult(
            "needs_review" if report["status"] != "SAFE" else "benign",
            0.95 if report["status"] == "BLOCKED" else 0.8,
            f"BK Security integrity is {report['status']} ({report['integrity_score']}/100).",
            findings=list(report["diagnostics"]),
            recommended_actions=recommendations,
            evidence=evidence,
        )
        # Newer InvestigationResult contracts carry explicit provenance. Keep
        # this worker compatible with older serialized deployments as well.
        if hasattr(result, "limitations"):
            result.limitations = ["Guardian diagnoses and recommends; it cannot edit or approve security code."]
        return result
