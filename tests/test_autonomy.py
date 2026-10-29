from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import bk_security.api.app as api_module
from bk_security.auth.security import issue_token
from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.events.models import SecurityEvent
from bk_security.policy.autonomy import AutonomyLevel, AutonomyPolicy, Consent, decide
from bk_security.policy.engine import Action

C2 = "45.33.32.156"


class FakeAdapter:
    def __init__(self):
        self.calls = []

    def execute(self, target, action, reason):
        self.calls.append(("execute", target))
        return {"accepted": True, "target": target, "reversible": True}

    def verify(self, target, action, result):
        return {"verified": True}

    def rollback(self, execution):
        return {"restored": True}

    def verify_rollback(self, execution, result):
        return {"verified": True}


@pytest.fixture
def core(tmp_path):
    instance = SecurityCore(SecurityStore(str(tmp_path / "autonomy.db")))
    instance.response.adapters = {Action.BLOCK: FakeAdapter()}
    instance.threat_intel.add_ip(C2, confidence=0.99, tags=["c2"], source="test")
    yield instance
    instance.store.close()


def _attack(core, count=6, target=C2, host="h1"):
    for index in range(count):
        core.ingest(SecurityEvent(
            event_type="network.packet", source="sensor", host_id=host,
            data={"dst_ip": target, "dst_port": 4444, "direction": "local->remote", "protocol": "TCP",
                  "size": 900000, "process_name": "powershell.exe", "pid": 100 + index},
            network={"dst_ip": target}, process={"name": "powershell.exe", "pid": 100 + index}))


def _set(core, level, **over):
    consent = over.pop("consent", {"approved_by": "owner@customer.example", "customer_reference": "CONSENT-1",
                                   "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()})
    settings = dict(level=level, auto_actions=[Action.BLOCK], min_risk_score=80, max_actions_per_hour=10,
                    protected_networks=("10.0.0.0/8", "192.168.0.0/16"), consent=consent)
    settings.update(over)
    return core.autonomy.set_policy("admin", **settings)


def _actions(core, name):
    return [row for row in core.store.list_audit(500) if row["action"] == name]


# ---- pure decision --------------------------------------------------------------------------------------------

def _policy(level, **kw):
    now = datetime.now(timezone.utc)
    consent = kw.pop("consent", Consent("owner", "REF", now.isoformat(), (now + timedelta(days=1)).isoformat()))
    return AutonomyPolicy(level=level, consent=consent, **kw)


def test_default_policy_is_observe_and_automatic_execution_needs_consent():
    assert AutonomyPolicy().level == AutonomyLevel.OBSERVE
    with pytest.raises(ValueError, match="consent"):
        AutonomyPolicy(level=AutonomyLevel.CONTAIN_AUTO)
    assert AutonomyPolicy(level=AutonomyLevel.RECOMMEND).consent is None


def test_levels_bound_what_can_happen_automatically():
    args = (Action.BLOCK, "45.33.32.156", 95, 1, 0)
    assert decide(AutonomyPolicy(), *args).mode == "observe"
    assert decide(AutonomyPolicy(level=AutonomyLevel.RECOMMEND), *args).mode == "recommend"
    assert decide(_policy(AutonomyLevel.CONTAIN_AUTO), *args).mode == "execute"
    stopped = _policy(AutonomyLevel.EXTENDED, emergency_stop=True)
    assert decide(stopped, *args).reasons == ("emergency_stop",)


def test_isolation_and_termination_need_the_extended_level_and_explicit_listing():
    both = frozenset({Action.BLOCK, Action.ISOLATE, Action.TERMINATE_PROCESS})
    level3 = _policy(AutonomyLevel.CONTAIN_AUTO, auto_actions=both)
    assert level3.effective_actions() == {Action.BLOCK}
    assert decide(level3, Action.ISOLATE, "local", 99, 1, 0).mode == "recommend"
    assert _policy(AutonomyLevel.EXTENDED).effective_actions() == {Action.BLOCK}
    assert decide(_policy(AutonomyLevel.EXTENDED, auto_actions=both), Action.ISOLATE, "local", 99, 1, 0).mode == "execute"


@pytest.mark.parametrize("risk,evidence,recent,reason", [(79, 1, 0, "below_min_risk"), (95, 0, 0, "no_evidence"),
                                                         (95, 1, 10, "hourly_cap_reached")])
def test_thresholds_fail_closed_to_observe(risk, evidence, recent, reason):
    decision = decide(_policy(AutonomyLevel.CONTAIN_AUTO), Action.BLOCK, C2, risk, evidence, recent)
    assert decision.mode == "observe" and decision.reasons == (reason,)


def test_protected_targets_and_expired_consent_downgrade_to_recommend():
    policy = _policy(AutonomyLevel.CONTAIN_AUTO)
    assert decide(policy, Action.BLOCK, "192.168.1.5", 95, 1, 0).reasons == ("protected_target",)
    assert decide(policy, Action.BLOCK, "not-an-ip", 95, 1, 0).reasons == ("protected_target",)
    later = datetime.now(timezone.utc) + timedelta(days=2)
    expired = decide(policy, Action.BLOCK, C2, 95, 1, 0, now=later)
    assert expired.mode == "recommend" and expired.reasons == ("consent_missing_or_expired",)


@pytest.mark.parametrize("kw", [{"min_risk_score": 10}, {"max_actions_per_hour": 0}, {"protected_networks": ("nope",)},
                                {"auto_actions": frozenset({Action.ALERT})}])
def test_invalid_policy_values_are_rejected(kw):
    with pytest.raises(ValueError):
        AutonomyPolicy(**kw)


# ---- controller integrated into the ingest path ---------------------------------------------------------------

def test_default_level_takes_no_automatic_response(core):
    _attack(core)
    assert core.alerts and core.response.plans == {}
    assert _actions(core, "autonomy_decision") == []


def test_recommend_level_prepares_only_a_dry_run_plan(core):
    _set(core, 2, consent=None)
    _attack(core)
    plans = [p for p in core.response.plans.values() if p["action"] == "block"]
    assert len(plans) == 1 and plans[0]["dry_run"] is True and plans[0]["target"] == C2
    assert core.response.adapters[Action.BLOCK].calls == []
    assert not core.response.executions


def test_contain_auto_blocks_a_public_ioc_with_verification_and_audit(core):
    _set(core, 3)
    _attack(core)
    adapter = core.response.adapters[Action.BLOCK]
    assert adapter.calls == [("execute", C2)]  # once, despite many alerts for the same target
    execution = next(iter(core.response.executions.values()))
    assert execution["status"] == "executed" and execution["verified"] is True
    assert execution["execution_actor"] == "bk-autonomy-executor"
    assert execution["approval"]["actor"] == "bk-autonomy-policy"
    decision = _actions(core, "autonomy_decision")[0]
    assert decision["data"]["decision"]["mode"] == "execute"
    assert decision["data"]["consent"] == "CONSENT-1" and decision["data"]["policy_version"] == 2
    assert _actions(core, "autonomy_policy_set")


def test_protected_internal_target_is_never_blocked_automatically(core):
    core.threat_intel.add_ip("192.168.1.50", confidence=0.99, tags=["c2"], source="test")
    _set(core, 3)
    _attack(core, target="192.168.1.50")
    assert core.response.adapters[Action.BLOCK].calls == []


def test_emergency_stop_halts_automatic_response_and_survives_restart(core, tmp_path):
    _set(core, 3)
    core.autonomy.emergency_stop("responder")
    _attack(core)
    assert core.response.adapters[Action.BLOCK].calls == [] and core.response.plans == {}
    core.store.flush()
    reopened = SecurityCore(SecurityStore(str(tmp_path / "autonomy.db")))
    try:
        assert reopened.autonomy.policy.emergency_stop is True
        assert reopened.autonomy.policy.level == AutonomyLevel.CONTAIN_AUTO
        reopened.autonomy.resume("admin")
        assert reopened.autonomy.policy.emergency_stop is False
    finally:
        reopened.store.close()


def test_hourly_cap_limits_automatic_responses(core):
    _set(core, 3, max_actions_per_hour=1)
    for target in ("45.33.32.156", "45.33.32.157"):
        core.threat_intel.add_ip(target, confidence=0.99, tags=["c2"], source="test")
        _attack(core, target=target)
    assert len(core.response.adapters[Action.BLOCK].calls) == 1


def test_invalid_stored_policy_fails_closed_to_observe(tmp_path):
    store = SecurityStore(str(tmp_path / "bad.db"))
    store.save_autonomy_policy({"level": 3, "consent": None})  # level 3 without consent
    core = SecurityCore(store)
    try:
        assert core.autonomy.policy.emergency_stop is True
        assert [row for row in store.list_audit(50) if row["action"] == "autonomy_policy_invalid"]
    finally:
        store.close()


def test_a_failing_response_never_breaks_ingestion(core, monkeypatch):
    _set(core, 3)
    monkeypatch.setattr(core, "plan_response", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    _attack(core)
    assert core.alerts and _actions(core, "autonomy_error")


# ---- operator API ----------------------------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch, tmp_path):
    store = SecurityStore(path=str(tmp_path / "api.db"))
    monkeypatch.setattr(api_module.core, "store", store)
    monkeypatch.setattr(api_module.core.autonomy, "policy", AutonomyPolicy())
    yield TestClient(api_module.app)
    store.close()


def _h(role):
    return {"Authorization": f"Bearer {issue_token(f'u-{role}', role)}"}


def test_only_admin_can_set_policy_and_a_responder_can_stop(client):
    body = {"level": 2}
    assert client.put("/api/v1/autonomy", json=body).status_code == 401
    assert client.put("/api/v1/autonomy", headers=_h("analyst"), json=body).status_code == 403
    assert client.put("/api/v1/autonomy", headers=_h("admin"), json=body).json()["level_name"] == "recommend"
    assert client.get("/api/v1/autonomy", headers=_h("viewer")).json()["level"] == 2
    assert client.post("/api/v1/autonomy/emergency-stop", headers=_h("viewer")).status_code == 403
    assert client.post("/api/v1/autonomy/emergency-stop", headers=_h("responder")).json()["emergency_stop"] is True
    assert client.post("/api/v1/autonomy/resume", headers=_h("responder")).status_code == 403
    assert client.post("/api/v1/autonomy/resume", headers=_h("admin")).json()["emergency_stop"] is False


def test_automatic_levels_require_a_valid_consent_through_the_api(client):
    assert client.put("/api/v1/autonomy", headers=_h("admin"), json={"level": 3}).status_code == 422
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    bad = {"level": 3, "consent": {"approved_by": "o", "customer_reference": "R", "expires_at": past}}
    assert client.put("/api/v1/autonomy", headers=_h("admin"), json=bad).status_code == 422
    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    good = {"level": 3, "consent": {"approved_by": "o", "customer_reference": "R", "expires_at": future}}
    response = client.put("/api/v1/autonomy", headers=_h("admin"), json=good)
    assert response.status_code == 200 and response.json()["consent"]["customer_reference"] == "R"
    assert response.json()["version"] >= 2
