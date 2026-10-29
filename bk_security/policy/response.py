from __future__ import annotations

import ipaddress
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .engine import Action, PROTECTED_ACTIONS


class ResponseAdapter(Protocol):
    def execute(self, target: str, action: Action, reason: str) -> dict: ...
    def rollback(self, execution: dict) -> dict: ...


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime | None:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        return None


def _safety_conditions(action: Action) -> list[str]:
    return {
        Action.ALERT: ["No operating-system adapter is called."],
        Action.REQUIRE_APPROVAL: ["A separate protected action must be proposed before execution."],
        Action.BLOCK: ["Target must be one valid unicast IP address.", "Only BK Security firewall rules may be rolled back."],
        Action.ISOLATE: ["Target must identify the local host.", "Isolation is enforced by an outbound firewall rule."],
        Action.TERMINATE_PROCESS: [
            "Target must be a bounded PID above reserved system PIDs.",
            "Protected Windows processes and the BK Security process are refused.",
            "Process termination is non-reversible.",
        ],
    }[action]


def validate_target(action: Action, target: str) -> str:
    value = str(target).strip()
    if not value or len(value) > 512 or any(ord(char) < 32 for char in value):
        raise ValueError("Response target must be non-empty, bounded, and contain no control characters.")
    if action == Action.BLOCK:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("BLOCK target must be a valid IP address.") from exc
        if (
            address.is_unspecified or address.is_multicast or address.is_loopback
            or address == ipaddress.ip_address("255.255.255.255")
        ):
            raise ValueError("BLOCK target must identify a unicast remote IP address.")
        return address.compressed
    if action == Action.TERMINATE_PROCESS:
        try:
            pid = int(value, 10)
        except ValueError as exc:
            raise ValueError("TERMINATE_PROCESS target must be a PID.") from exc
        if pid < 5 or pid > 2_147_483_647:
            raise ValueError("TERMINATE_PROCESS target PID is outside the permitted range.")
        return str(pid)
    return value


@dataclass(slots=True)
class ResponseEngine:
    """Explicitly approved, auditable response execution with safe defaults."""

    adapters: dict[Action, ResponseAdapter] = field(default_factory=dict)
    executions: dict[str, dict] = field(default_factory=dict)
    plans: dict[str, dict] = field(default_factory=dict)
    approval_ttl_seconds: int = 300

    def plan(
        self,
        plan_id: str,
        action: Action,
        target: str,
        reason: str,
        *,
        dry_run: bool = True,
        risk_level: str = "info",
        risk_score: int = 0,
        alert_id: str | None = None,
        incident_id: str | None = None,
        evidence_ids: list[str] | None = None,
        policy_decision: dict | None = None,
        ai_recommendation: str | None = None,
    ) -> dict:
        if not plan_id or len(plan_id) > 128:
            raise ValueError("Response plan identifier is invalid.")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise ValueError("Response reason must be non-empty and bounded.")
        if risk_level not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError("Response risk level is invalid.")
        if not isinstance(risk_score, int) or not 0 <= risk_score <= 100:
            raise ValueError("Response risk score must be between 0 and 100.")
        target = validate_target(Action(action), target)
        evidence = list(dict.fromkeys(str(item) for item in (evidence_ids or []) if str(item)))
        if len(evidence) > 64 or any(len(item) > 256 for item in evidence):
            raise ValueError("Response evidence references exceed the permitted bounds.")
        plan = {
            "plan_id": plan_id,
            "action": Action(action).value,
            "target": target,
            "reason": reason.strip(),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "alert_id": alert_id,
            "incident_id": incident_id,
            "evidence_ids": evidence,
            "ai_recommendation": ai_recommendation,
            "policy_decision": deepcopy(policy_decision or {}),
            "requires_approval": (
                Action(action) in PROTECTED_ACTIONS
                or Action(action) == Action.REQUIRE_APPROVAL
                or bool((policy_decision or {}).get("requires_approval"))
            ),
            "approval_requirements": {
                "role": "approver",
                "expires_in_seconds": self.approval_ttl_seconds,
                "approver_and_executor_must_differ": True,
            } if (
                Action(action) in PROTECTED_ACTIONS
                or Action(action) == Action.REQUIRE_APPROVAL
                or bool((policy_decision or {}).get("requires_approval"))
            ) else None,
            "safety_conditions": _safety_conditions(Action(action)),
            "execution_timeout_seconds": 20,
            "reversible": Action(action) != Action.TERMINATE_PROCESS,
            "dry_run": bool(dry_run),
            "status": "planned",
            "planned_at": _iso(_now()),
        }
        existing = self.plans.get(plan_id)
        if existing:
            immutable = ("action", "target", "reason", "alert_id", "incident_id", "evidence_ids", "policy_decision")
            if any(existing.get(key) != plan.get(key) for key in immutable):
                raise ValueError("A response plan identifier cannot be reused with different contents.")
            return deepcopy(existing)
        self.plans[plan_id] = plan
        return deepcopy(plan)

    def restore(self, records: list[dict]) -> None:
        for record in records:
            plan_id = str(record.get("plan_id") or record.get("execution_id") or "")
            if not plan_id or "action" not in record:
                continue
            self.plans[plan_id] = deepcopy(record)
            if record.get("execution_id") and record.get("status") == "executing":
                recovered = {
                    **deepcopy(record),
                    "status": "degraded",
                    "executed": False,
                    "execution_attempted": True,
                    "recovered_incomplete_execution": True,
                    "verification": {
                        "verified": False,
                        "reason": "process_interrupted_before_result_persistence",
                    },
                    "error": {
                        "type": "InterruptedExecution",
                        "message": "Execution ended before a final result was persisted.",
                    },
                }
                self.plans[plan_id] = recovered
                self.executions[str(record["execution_id"])] = recovered
            elif record.get("execution_id") and record.get("status") in {
                "executed", "degraded", "failed", "rolled_back", "rollback_failed", "dry_run",
            }:
                self.executions[str(record["execution_id"])] = deepcopy(record)

    def approve(self, plan_id: str, actor: str, role: str, *, rollback: bool = False,
                now: datetime | None = None) -> dict:
        if role != "approver":
            raise PermissionError("Only the approver role can approve a response.")
        current = self.plans.get(plan_id)
        if not current:
            raise LookupError("Response plan not found.")
        if rollback:
            current = self.executions.get(plan_id)
            if not current or not current.get("executed"):
                raise ValueError("Only an executed response can be approved for rollback.")
            if Action(current["action"]) == Action.TERMINATE_PROCESS:
                raise ValueError("TERMINATE_PROCESS cannot be rolled back.")
        issued = now or _now()
        approval_key = "rollback_approval" if rollback else "approval"
        existing_approval = current.get(approval_key)
        existing_expiry = (
            _parse_time(existing_approval.get("expires_at"))
            if isinstance(existing_approval, dict) else None
        )
        if existing_expiry is not None and issued < existing_expiry:
            return deepcopy(current)
        approval = {
            "actor": actor,
            "role": role,
            "approved_at": _iso(issued),
            "expires_at": _iso(issued + timedelta(seconds=self.approval_ttl_seconds)),
            "plan_id": plan_id,
        }
        current[approval_key] = approval
        if not rollback:
            current["status"] = "approved"
        return deepcopy(current)

    def _valid_approval(self, plan: dict, actor: str, *, rollback: bool = False,
                        now: datetime | None = None) -> tuple[bool, str]:
        approval = plan.get("rollback_approval" if rollback else "approval")
        if not isinstance(approval, dict) or approval.get("role") != "approver":
            return False, "approval_required"
        if not approval.get("actor") or approval.get("actor") == actor:
            return False, "approver_and_executor_must_be_distinct"
        expires = _parse_time(approval.get("expires_at"))
        if expires is None or (now or _now()) >= expires:
            return False, "approval_expired_or_invalid"
        if approval.get("plan_id") != plan.get("plan_id") and approval.get("plan_id") != plan.get("execution_id"):
            return False, "approval_plan_mismatch"
        return True, ""

    def execute(self, execution_id: str, plan_id: str, actor: str, actor_role: str,
                *, dry_run: bool | None = None, now: datetime | None = None) -> dict:
        if actor_role != "responder":
            raise PermissionError("Only the responder role can execute a response.")
        previous = self.executions.get(execution_id)
        if previous and previous.get("status") not in {
            "dry_run", "approval_required", "approver_and_executor_must_be_distinct",
            "approval_expired_or_invalid", "approval_plan_mismatch", "policy_denied", "plan_is_dry_run",
        }:
            return {**deepcopy(previous), "idempotent_replay": True}
        plan = self.plans.get(plan_id)
        if not plan:
            return {"plan_id": plan_id, "execution_id": execution_id, "status": "plan_not_found", "executed": False}
        if execution_id != plan_id:
            return {**deepcopy(plan), "execution_id": execution_id, "status": "idempotency_key_mismatch", "executed": False}
        policy = plan.get("policy_decision") or {}
        if policy.get("allowed") is False:
            result = {**deepcopy(plan), "execution_id": execution_id, "status": "policy_denied", "executed": False}
            self.executions[execution_id] = result
            return result
        actual_dry_run = plan.get("dry_run", True) if dry_run is None else bool(dry_run)
        if actual_dry_run:
            result = {**deepcopy(plan), "execution_id": execution_id, "dry_run": True,
                      "status": "dry_run", "executed": False, "result": {"simulated": True}}
            self.executions[execution_id] = result
            return result
        if plan.get("dry_run", True):
            return {**deepcopy(plan), "execution_id": execution_id, "status": "plan_is_dry_run", "executed": False}

        action = Action(plan["action"])
        if action in PROTECTED_ACTIONS or (plan.get("requires_approval") and action != Action.ALERT):
            valid, error = self._valid_approval(plan, actor, now=now)
            if not valid:
                result = {**deepcopy(plan), "execution_id": execution_id, "executed": False, "status": error}
                self.executions[execution_id] = result
                return result
        if action in {Action.ALERT, Action.REQUIRE_APPROVAL}:
            result = {**deepcopy(plan), "execution_id": execution_id, "executed": False,
                      "status": "decision_only", "result": {"action": action.value}}
            self.executions[execution_id] = result
            return result

        adapter = self.adapters.get(action)
        if adapter is None:
            result = {**deepcopy(plan), "execution_id": execution_id, "executed": False,
                      "status": "adapter_not_configured"}
            self.executions[execution_id] = result
            return result
        result = {**deepcopy(plan), "execution_id": execution_id, "execution_actor": actor,
                  "executed": False, "status": "failed"}
        try:
            result["execution_attempted"] = True
            adapter_result = adapter.execute(plan["target"], action, plan["reason"])
            result["result"] = adapter_result
            result["executed"] = True
            verifier = getattr(adapter, "verify", None)
            if verifier is None:
                verification = {"verified": False, "reason": "adapter_verification_unavailable"}
            else:
                verification = verifier(plan["target"], action, adapter_result)
                if isinstance(verification, bool):
                    verification = {"verified": verification}
                elif not isinstance(verification, dict):
                    verification = {"verified": False, "reason": "invalid_verification_result"}
            result["verification"] = verification
            result["status"] = "executed" if verification.get("verified") is True else "degraded"
            result["verified"] = verification.get("verified") is True
            result["reversible"] = action != Action.TERMINATE_PROCESS and adapter_result.get("reversible", True)
        except Exception as exc:
            result["status"] = "degraded" if result.get("execution_attempted") else "failed"
            result["error"] = {"type": type(exc).__name__, "message": str(exc)[:1000]}
            verifier = getattr(adapter, "verify", None)
            if verifier is not None and result.get("execution_attempted"):
                try:
                    result["verification"] = verifier(plan["target"], action, result.get("result") or {})
                except Exception as verify_exc:
                    result["verification"] = {
                        "verified": False, "reason": "verification_after_adapter_error_failed",
                        "error": type(verify_exc).__name__,
                    }
            else:
                result["verification"] = {"verified": False, "reason": "adapter_error_or_partial_execution"}
            result["verified"] = False
            result["reversible"] = action != Action.TERMINATE_PROCESS
        self.executions[execution_id] = result
        self.plans[plan_id] = result
        return deepcopy(result)

    def rollback(self, execution_id: str, actor: str, actor_role: str,
                 *, now: datetime | None = None) -> dict:
        if actor_role != "responder":
            raise PermissionError("Only the responder role can roll back a response.")
        execution = self.executions.get(execution_id)
        if not execution or not execution.get("executed"):
            return {"execution_id": execution_id, "status": "not_reversible", "verified": False}
        action = Action(execution["action"])
        if action == Action.TERMINATE_PROCESS or execution.get("reversible") is False:
            return {"execution_id": execution_id, "status": "non_reversible", "verified": False}
        valid, error = self._valid_approval(execution, actor, rollback=True, now=now)
        if not valid:
            return {"execution_id": execution_id, "status": error, "verified": False}
        adapter = self.adapters.get(action)
        if not adapter:
            return {"execution_id": execution_id, "status": "adapter_not_configured", "verified": False}
        try:
            rollback_result = adapter.rollback(deepcopy(execution))
            verifier = getattr(adapter, "verify_rollback", None)
            verification = verifier(execution, rollback_result) if verifier else {
                "verified": False, "reason": "rollback_verification_unavailable",
            }
            if isinstance(verification, bool):
                verification = {"verified": verification}
            if not isinstance(verification, dict):
                verification = {"verified": False, "reason": "invalid_verification_result"}
            status = "rolled_back" if verification.get("verified") is True else "rollback_failed"
            execution["rollback"] = rollback_result
            execution["rollback_verification"] = verification
            execution["rollback_status"] = status
            return {"execution_id": execution_id, "status": status, "verified": verification.get("verified") is True,
                    "result": rollback_result, "verification": verification}
        except Exception as exc:
            execution["rollback_error"] = {"type": type(exc).__name__, "message": str(exc)[:1000]}
            execution["rollback_status"] = "rollback_failed"
            return {"execution_id": execution_id, "status": "rollback_failed", "verified": False,
                    "error": execution["rollback_error"]}
