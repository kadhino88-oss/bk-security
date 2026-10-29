"""Applies the customer's autonomy policy to new alerts, through the existing response engine.

Automatic execution reuses plan -> approve -> execute with two distinct system identities, so separation of duties,
verification, rollback and audit stay exactly as for human-driven responses. A failure here never affects ingestion.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from .policy.autonomy import AutonomyPolicy, Consent, decide
from .policy.engine import Action

log = logging.getLogger(__name__)
POLICY_ACTOR = "bk-autonomy-policy"
EXECUTOR_ACTOR = "bk-autonomy-executor"
PLANNER_ACTOR = "bk-autonomy"


def _public_ip(value: Any) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return ip.compressed if ip.is_global else None


class AutonomyController:
    def __init__(self, core) -> None:
        self.core = core
        self._lock = threading.RLock()
        self._recent: deque[datetime] = deque()  # process-local: a restart resets the hourly cap
        self._targets: dict[str, datetime] = {}  # one automatic response per target per hour
        self.policy = self._load()

    def _load(self) -> AutonomyPolicy:
        try:
            stored = self.core.store.load_autonomy_policy()
            return AutonomyPolicy.from_dict(stored) if stored else AutonomyPolicy()
        except Exception as exc:  # noqa: BLE001 - an unreadable policy must fail closed to OBSERVE
            log.error("Stored autonomy policy is invalid; falling back to observe: %s", type(exc).__name__)
            self.core.store.audit("system", "autonomy_policy_invalid", None, {"error": type(exc).__name__})
            return AutonomyPolicy(emergency_stop=True)

    # -- operator actions ---------------------------------------------------------------------------------------

    def set_policy(self, actor: str, *, level: int, auto_actions, min_risk_score: int, max_actions_per_hour: int,
                   protected_networks, consent: dict | None) -> AutonomyPolicy:
        with self._lock:
            now = datetime.now(timezone.utc)
            built = Consent(approved_by=consent["approved_by"], customer_reference=consent["customer_reference"],
                            approved_at=now.isoformat(), expires_at=consent["expires_at"]) if consent else None
            policy = AutonomyPolicy(
                level=level, auto_actions=frozenset(auto_actions), min_risk_score=min_risk_score,
                max_actions_per_hour=max_actions_per_hour, protected_networks=tuple(protected_networks),
                consent=built, emergency_stop=self.policy.emergency_stop, version=self.policy.version + 1)
            self.core.store.save_autonomy_policy(policy.to_dict())
            self.core.store.audit(actor, "autonomy_policy_set", None, {"previous": self.policy.to_dict(),
                                                                      "new": policy.to_dict()})
            self.policy = policy
            return policy

    def _set_stop(self, actor: str, stopped: bool) -> AutonomyPolicy:
        with self._lock:
            data = {**self.policy.to_dict(), "emergency_stop": stopped, "version": self.policy.version + 1}
            data.pop("level_name", None)
            policy = AutonomyPolicy.from_dict(data)
            self.core.store.save_autonomy_policy(policy.to_dict())
            self.core.store.audit(actor, "autonomy_emergency_stop" if stopped else "autonomy_resume", None,
                                  {"version": policy.version})
            self.policy = policy
            return policy

    def emergency_stop(self, actor: str) -> AutonomyPolicy:
        return self._set_stop(actor, True)

    def resume(self, actor: str) -> AutonomyPolicy:
        return self._set_stop(actor, False)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {**self.policy.to_dict(), "actions_last_hour": self._recent_count(datetime.now(timezone.utc))}

    # -- automatic path -----------------------------------------------------------------------------------------

    def _recent_count(self, now: datetime) -> int:
        while self._recent and now - self._recent[0] > timedelta(hours=1):
            self._recent.popleft()
        return len(self._recent)

    @staticmethod
    def _block_target(alert, events) -> str | None:
        """The remote public IP implicated by the alert's own source events, or None."""
        wanted = set(alert.source_event_ids)
        for event in events:
            if event.event_id not in wanted:
                continue
            data, network = event.data or {}, event.network or {}
            direction = str(data.get("direction") or network.get("direction") or "")
            keys = ("src_ip",) if direction == "remote->local" else ("dst_ip",)
            for key in keys:
                found = _public_ip(data.get(key) or network.get(key))
                if found:
                    return found
        return None

    def on_alerts(self, alerts, events) -> None:
        """Hook called after alerts are persisted; swallows every error so ingestion is never affected."""
        if self.policy.emergency_stop or int(self.policy.level) < 2 or not alerts:
            return
        for alert in alerts:
            try:
                self._handle(alert, events)
            except Exception as exc:  # noqa: BLE001
                log.error("Autonomy handling failed: %s", type(exc).__name__)
                self.core.store.audit(PLANNER_ACTOR, "autonomy_error", alert.alert_id, {"error": type(exc).__name__})

    def _handle(self, alert, events) -> None:
        target = self._block_target(alert, events)
        if target is None:
            return
        with self._lock:
            now = datetime.now(timezone.utc)
            decision = decide(self.policy, Action.BLOCK, target, alert.risk_score, len(alert.source_event_ids),
                              self._recent_count(now), now=now)
            if decision.mode == "observe":
                return
            plan_id = "auto-" + hashlib.sha256(f"{alert.alert_id}|block|{target}".encode()).hexdigest()[:32]
            if plan_id in self.core.response.plans:
                return  # already handled for this alert and target
            self._targets = {key: seen for key, seen in self._targets.items() if now - seen <= timedelta(hours=1)}
            if target in self._targets:
                return
            self._targets[target] = now
            self._recent.append(now)
            execute = decision.mode == "execute"
            reason = f"Automatic {decision.mode} by autonomy policy v{self.policy.version}: {alert.title}"[:1000]
            plan = self.core.plan_response(
                Action.BLOCK, target, reason, actor=PLANNER_ACTOR, actor_role="analyst", dry_run=not execute,
                alert_id=alert.alert_id, evidence_ids=[alert.alert_id], plan_id=plan_id)
            self.core.store.audit(PLANNER_ACTOR, "autonomy_decision", target, {
                "plan_id": plan_id, "alert_id": alert.alert_id, "decision": decision.to_dict(),
                "policy_version": self.policy.version, "level": int(self.policy.level),
                "consent": None if self.policy.consent is None else self.policy.consent.customer_reference})
            if execute and plan["policy_decision"].get("allowed", True):
                self.core.approve_response(plan_id, actor=POLICY_ACTOR, role="approver")
                self.core.execute_response(plan_id, plan_id, actor=EXECUTOR_ACTOR, actor_role="responder",
                                           dry_run=False)
