from datetime import datetime, timedelta, timezone

import pytest

from bk_security.core import SecurityCore
from bk_security.events.models import SecurityEvent
from bk_security.policy.engine import Action, ResponsePolicy


class RecordingAdapter:
    def __init__(self, verification=True):
        self.calls = []
        self.verification = verification

    def execute(self, target, action, reason):
        self.calls.append(("execute", target, action, reason))
        return {"accepted": True, "target": target, "reversible": True}

    def verify(self, target, action, result):
        return {"verified": self.verification, "target": target}

    def rollback(self, execution):
        self.calls.append(("rollback", execution["target"]))
        return {"restored": True, "reversible": True}

    def verify_rollback(self, execution, result):
        return {"verified": True, "target": execution["target"]}


class NonReversibleAdapter(RecordingAdapter):
    def rollback(self, execution):
        return {"reversible": False}


class TimeoutAdapter(RecordingAdapter):
    def execute(self, target, action, reason):
        raise TimeoutError("mock execution timeout")

    def verify(self, target, action, result):
        return {"verified": False, "reason": "state_uncertain"}


def make_plan(core, adapter=None, *, action=Action.BLOCK, dry_run=False, risk_level="critical"):
    if adapter:
        core.response.adapters[action] = adapter
    return core.plan_response(
        action, "203.0.113.8" if action == Action.BLOCK else "1234", "test response",
        actor="analyst", actor_role="analyst", dry_run=dry_run, risk_level=risk_level,
    )


def test_protected_action_requires_actor_bound_approval():
    core = SecurityCore()
    plan = make_plan(core)
    with pytest.raises(PermissionError):
        core.execute_response(
            plan["plan_id"], plan["plan_id"], actor="analyst", actor_role="analyst", dry_run=False,
        )
    result = core.execute_response(plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False)
    assert result["status"] == "approval_required"
    assert result["executed"] is False


def test_approval_rejects_bad_role_expiry_and_approver_self_execution():
    core = SecurityCore()
    adapter = RecordingAdapter()
    plan = make_plan(core, adapter)
    plan_id = plan["plan_id"]
    with pytest.raises(PermissionError):
        core.response.approve(plan_id, "analyst", "analyst")

    expired = datetime.now(timezone.utc) - timedelta(seconds=600)
    core.response.approve(plan_id, "old-approver", "approver", now=expired)
    result = core.execute_response(plan_id, plan_id, actor="responder", actor_role="responder", dry_run=False)
    assert result["status"] == "approval_expired_or_invalid"
    assert adapter.calls == []

    core.response.approve(plan_id, "approver", "approver")
    same_actor = core.execute_response(plan_id, plan_id, actor="approver", actor_role="responder", dry_run=False)
    assert same_actor["status"] == "approver_and_executor_must_be_distinct"
    assert adapter.calls == []


def test_approved_action_executes_once_and_verification_is_recorded():
    core = SecurityCore()
    adapter = RecordingAdapter()
    plan = make_plan(core, adapter)
    core.approve_response(plan["plan_id"], actor="approver", role="approver")
    result = core.execute_response(plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False)
    assert result["status"] == "executed"
    assert result["verification"]["verified"] is True
    replay = core.execute_response(plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False)
    assert replay["idempotent_replay"] is True
    assert len([call for call in adapter.calls if call[0] == "execute"]) == 1


def test_dry_run_never_calls_adapter_even_for_approved_protected_action():
    core = SecurityCore()
    adapter = RecordingAdapter()
    plan = make_plan(core, adapter, dry_run=True)
    result = core.execute_response(plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=True)
    assert result["status"] == "dry_run"
    assert result["executed"] is False
    assert adapter.calls == []


def test_verification_failure_is_degraded_and_never_reported_as_success():
    core = SecurityCore()
    adapter = RecordingAdapter(verification=False)
    plan = make_plan(core, adapter)
    core.approve_response(plan["plan_id"], actor="approver", role="approver")
    result = core.execute_response(plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False)
    assert result["status"] == "degraded"
    assert result["executed"] is True
    assert result["verified"] is False


def test_adapter_timeout_is_audited_as_degraded_not_success():
    core = SecurityCore()
    plan = make_plan(core, TimeoutAdapter())
    core.approve_response(plan["plan_id"], actor="approver", role="approver")
    result = core.execute_response(
        plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False,
    )
    assert result["status"] == "degraded"
    assert result["execution_attempted"] is True
    assert result["executed"] is False


def test_reversible_rollback_requires_approval_and_is_verified():
    core = SecurityCore()
    adapter = RecordingAdapter()
    plan = make_plan(core, adapter)
    core.approve_response(plan["plan_id"], actor="approver", role="approver")
    core.execute_response(plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False)
    denied = core.rollback_response(plan["plan_id"], actor="responder", actor_role="responder")
    assert denied["status"] == "approval_required"

    core.approve_response(plan["plan_id"], actor="approver", role="approver", rollback=True)
    rolled_back = core.rollback_response(plan["plan_id"], actor="responder", actor_role="responder")
    assert rolled_back["status"] == "rolled_back"
    assert rolled_back["verified"] is True


def test_terminate_process_is_explicitly_non_reversible():
    core = SecurityCore()
    adapter = NonReversibleAdapter()
    plan = make_plan(core, adapter, action=Action.TERMINATE_PROCESS)
    core.approve_response(plan["plan_id"], actor="approver", role="approver")
    result = core.execute_response(plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False)
    assert result["status"] == "executed"
    assert result["reversible"] is False
    rollback = core.rollback_response(plan["plan_id"], actor="responder", actor_role="responder")
    assert rollback["status"] == "non_reversible"


def test_target_validation_and_plan_idempotency_are_strict():
    core = SecurityCore()
    with pytest.raises(ValueError):
        core.plan_response(Action.BLOCK, "not-an-ip", "test", actor="analyst", actor_role="analyst", risk_level="critical")
    with pytest.raises(ValueError):
        core.plan_response(Action.TERMINATE_PROCESS, "4", "test", actor="analyst", actor_role="analyst", risk_level="critical")
    plan = core.plan_response(
        Action.BLOCK, "203.0.113.10", "test", actor="analyst", actor_role="analyst", risk_level="critical", plan_id="fixed-plan"
    )
    same = core.plan_response(
        Action.BLOCK, "203.0.113.10", "test", actor="analyst", actor_role="analyst",
        risk_level="critical", plan_id="fixed-plan",
    )
    assert same["plan_id"] == plan["plan_id"]
    with pytest.raises(ValueError):
        core.response.plan("fixed-plan", Action.BLOCK, "203.0.113.11", "test")


def test_ai_recommendation_cannot_override_policy_authority():
    policy = ResponsePolicy()
    medium = policy.evaluate("medium", ai_recommendation=Action.ISOLATE)
    assert medium["action"] == Action.ALERT.value
    assert medium["allowed"] is False
    assert medium["ai_recommendation"] == Action.ISOLATE.value

    high = policy.evaluate("high", ai_recommendation=Action.ISOLATE)
    assert high["action"] == Action.ISOLATE.value
    assert high["allowed"] is True
    assert high["requires_approval"] is True


def test_core_plans_ai_recommendation_through_policy_and_records_safety_conditions():
    core = SecurityCore()
    medium = core.plan_response(
        None, "local", "worker proposal", actor="analyst", actor_role="analyst",
        risk_level="medium", ai_recommendation=Action.ISOLATE, dry_run=False,
    )
    assert medium["action"] == Action.ALERT.value
    assert medium["policy_decision"]["allowed"] is False
    assert medium["requires_approval"] is False

    high = core.plan_response(
        None, "local", "worker proposal", actor="analyst", actor_role="analyst",
        risk_level="high", ai_recommendation=Action.ISOLATE, dry_run=False,
    )
    assert high["action"] == Action.ISOLATE.value
    assert high["requires_approval"] is True
    assert high["approval_requirements"]["approver_and_executor_must_differ"] is True
    assert high["execution_timeout_seconds"] == 20
    assert "local host" in " ".join(high["safety_conditions"])


def test_configured_policy_can_select_each_protected_action_but_still_requires_approval():
    for action in (Action.BLOCK, Action.ISOLATE, Action.TERMINATE_PROCESS):
        decision = ResponsePolicy(critical_auto_action=action).evaluate("critical")
        assert decision["action"] == action.value
        assert decision["requires_approval"] is True


def test_response_lifecycle_audit_has_actor_reasons_evidence_and_all_stages():
    core = SecurityCore()
    adapter = RecordingAdapter()
    core.response.adapters[Action.BLOCK] = adapter
    evidence = SecurityEvent(event_type="network.dns", source="test", host_id="host-1")
    core.events.append(evidence)
    core.store.save_event(evidence)
    before = core.store.get_event(evidence.event_id)
    plan = core.plan_response(
        Action.BLOCK, "203.0.113.21", "linked evidence", actor="analyst", actor_role="analyst",
        dry_run=False, risk_level="critical", evidence_ids=[evidence.event_id],
    )
    core.approve_response(plan["plan_id"], actor="approver", role="approver")
    core.execute_response(plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False)
    core.approve_response(plan["plan_id"], actor="approver", role="approver", rollback=True)
    core.rollback_response(plan["plan_id"], actor="responder", actor_role="responder")
    after = core.store.get_event(evidence.event_id)
    assert after == before
    audit = core.store.list_audit(100)
    stages = {item["action"] for item in audit}
    assert {
        "response_policy_decision", "response_plan", "response_approval",
        "response_execute", "response_verification", "response_rollback_approval",
        "response_rollback",
    } <= stages
    entries = [item for item in audit if item["action"] == "response_execute"]
    assert entries and entries[0]["actor"] == "responder"
    assert entries[0]["data"]["reason"] == "linked evidence"
    assert entries[0]["data"]["evidence_ids"] == [evidence.event_id]
