from __future__ import annotations

import hashlib
import sqlite3
import json

import pytest

from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.reliability import (
    IntegrityMonitor,
    ReliabilityService,
    ReliabilityLedger,
    RepairAction,
    SafeAutoRepair,
    BKRegressionGuardian,
)
from scripts.release_gate import _record_blocked_candidate, _record_passed_candidate


def _config_fingerprint(configuration):
    return hashlib.sha256(json.dumps(configuration, sort_keys=True).encode("utf-8")).hexdigest()


@pytest.fixture
def core(tmp_path):
    instance = SecurityCore(SecurityStore(str(tmp_path / "reliability.sqlite3")))
    yield instance
    instance.store.close()


def test_integrity_monitor_reports_required_components_and_blocks_critical_failure(core):
    monitor = IntegrityMonitor(core)
    report = monitor.inspect()
    assert report.status == "SAFE"
    assert 0 <= report.score <= 100
    assert set(report.components) == {
        "core", "detection", "correlation", "threat_family", "ai_soc",
        "db", "api_rbac", "response", "runtime", "configuration",
    }
    assert report.components["db"].status == "ok"

    core.detector = object()
    failed = monitor.inspect()
    assert failed.status == "BLOCKED"
    assert failed.components["detection"].status == "failed"
    assert any("detection" in item for item in failed.diagnostics)


def test_reliability_audit_is_append_only_and_tampering_is_detected(core):
    ledger = ReliabilityLedger(core.store)
    ledger.append("test", "diagnostic", "api", {"status": "DEGRADED"})
    assert ledger.verify_audit() == (True, None)

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with sqlite3.connect(core.store.path) as db:
            db.execute("DELETE FROM bk_reliability_audit")

    # Verify the hash chain still detects privileged/manual changes that bypass
    # the ordinary append-only SQL triggers.
    with sqlite3.connect(core.store.path) as db:
        db.execute("DROP TRIGGER bk_reliability_audit_no_update")
        db.execute("UPDATE bk_reliability_audit SET payload='{}' WHERE seq=1")
    valid, diagnostic = ledger.verify_audit()
    assert valid is False
    assert "hash" in diagnostic
    report = IntegrityMonitor(core).inspect()
    assert report.status == "BLOCKED"
    assert report.score <= 49


def test_safe_repair_requires_allowlist_handler_postcheck_and_is_idempotent(core):
    calls = []
    service = ReliabilityService(
        core,
        repair_handlers={RepairAction.REBUILD_CACHE_INDEX: lambda target: calls.append(target)},
    )
    first = service.run_safe_repair("rebuild_cache_index", "correlation")
    second = service.run_safe_repair("rebuild_cache_index", "correlation")
    assert first["status"] == second["status"] == "SUCCEEDED"
    assert first["validated"] is True
    assert calls == ["correlation"]
    assert service.monitor.ledger.verify_audit() == (True, None)

    rejected = service.run_safe_repair("modify_detection_rules", "detection")
    assert rejected["status"] == "BLOCKED"
    assert "allowlisted" in rejected["reason"]


def test_repair_loop_guard_degrades_then_blocks_repeated_failure(core):
    calls = []
    ledger = ReliabilityLedger(core.store)
    repair = SafeAutoRepair(
        ledger,
        {RepairAction.INTERNAL_RECONNECT: lambda target: calls.append(target)},
        max_attempts=1,
    )
    first = repair.apply(
        RepairAction.INTERNAL_RECONNECT, "sqlite", validate=lambda: False,
        idempotency_key="attempt-1",
    )
    second = repair.apply(
        RepairAction.INTERNAL_RECONNECT, "sqlite", validate=lambda: True,
        idempotency_key="attempt-2",
    )
    assert first["status"] == "DEGRADED"
    assert second["status"] == "BLOCKED"
    assert "loop guard" in second["reason"]
    assert calls == ["sqlite"]


def test_regression_guardian_rebuilds_only_derived_correlation_cache(core):
    service = ReliabilityService(core)
    core.correlation._by_host["corrupt-host"] = [object()]
    guardian = BKRegressionGuardian(service)

    diagnosis = guardian.diagnose()
    assert diagnosis["integrity"]["status"] == "SAFE"
    assert diagnosis["safe_repairs"][0]["status"] == "SUCCEEDED"
    assert diagnosis["code_modification_allowed"] is False
    assert "corrupt-host" not in core.correlation._by_host
    actions = [item["action"] for item in service.monitor.ledger.list_audit()]
    assert "repair_started" in actions
    assert "repair_succeeded" in actions


def test_last_known_good_and_validated_rollback_are_audited(core):
    service = ReliabilityService(core)
    configuration = {"BK_SECURITY_ENV": "production", "BK_SECURITY_CAPTURE_MODE": "live"}
    known = service.record_last_known_good(
        "1.0.0-alpha.13", _config_fingerprint(configuration), "artifact-sha256",
        checks={"critical_tests": True, "full_tests": True, "compile": True}, canary_healthy=True,
        configuration=configuration,
    )
    activated = []
    outcome = service.rollback_to_last_known_good(
        "canary health check failed",
        activate=lambda record: activated.append(record["version"]),
        validate=lambda: True,
    )
    assert known["version"] == "1.0.0-alpha.13"
    assert known["configuration"]["BK_SECURITY_ENV"] == "production"
    assert activated == [known["version"]]
    assert outcome["status"] == "ROLLED_BACK"
    actions = [item["action"] for item in service.monitor.ledger.list_audit()]
    assert "lkg_recorded" in actions
    assert "automatic_rollback" in actions


def test_candidate_gate_blocks_failure_and_rolls_back_activated_canary(core):
    service = ReliabilityService(core)
    configuration = {"BK_SECURITY_ENV": "test"}
    service.record_last_known_good(
        "release-good", _config_fingerprint(configuration), "artifact-good",
        checks={"critical_tests": True, "full_tests": True, "compile": True}, canary_healthy=True,
        configuration=configuration,
    )
    activated = []
    outcome = service.guard_candidate(
        "release-candidate",
        {"critical_tests": False},
        canary_healthy=False,
        config_fingerprint="cfg-candidate",
        artifact_digest="artifact-candidate",
        candidate_activated=True,
        activate_lkg=lambda record: activated.append(record["version"]),
        validate_rollback=lambda: True,
    )
    assert outcome["status"] == "BLOCKED"
    assert outcome["rollback"]["status"] == "ROLLED_BACK"
    assert activated == ["release-good"]
    assert service.monitor.ledger.get_state("active_release")["version"] == "release-good"
    assert service.monitor.ledger.verify_audit() == (True, None)


def test_last_known_good_rejects_unhealthy_release(core):
    service = ReliabilityService(core)
    core.detector = None
    configuration = {"BK_SECURITY_ENV": "test"}
    with pytest.raises(RuntimeError, match="SAFE"):
        service.record_last_known_good(
            "candidate-bad", _config_fingerprint(configuration), "artifact",
            checks={"critical_tests": True, "full_tests": True, "compile": True}, canary_healthy=True,
            configuration=configuration,
        )
    assert service.monitor.ledger.get_state("last_known_good") is None


def test_release_gate_keeps_previous_lkg_on_failure_and_advances_only_after_pass(tmp_path):
    out_dir = tmp_path / "dist"
    out_dir.mkdir()
    previous = {"version": "release-good", "artifact_sha256": "old-digest"}
    (out_dir / "last-known-good.json").write_text(json.dumps(previous), encoding="utf-8")
    old_manifest = {"version": "release-good", "status": "SAFE"}
    (out_dir / "release-gate.json").write_text(json.dumps(old_manifest), encoding="utf-8")

    _record_blocked_candidate(out_dir, "release-bad", "critical tests", "one test failed")
    assert json.loads((out_dir / "last-known-good.json").read_text(encoding="utf-8")) == previous
    assert json.loads((out_dir / "release-gate.json").read_text(encoding="utf-8")) == old_manifest
    blocked = json.loads((out_dir / "candidate-status.json").read_text(encoding="utf-8"))
    assert blocked["status"] == "BLOCKED"
    assert blocked["active_version"] is None
    assert blocked["last_known_good"]["version"] == "release-good"

    candidate = {
        "version": "release-next", "artifact_sha256": "new-digest",
        "config_fingerprint": "new-config", "validated_at": "2026-10-06T00:00:00+00:00",
        "validated_configuration": {"BK_SECURITY_ENV": "test"},
    }
    _record_passed_candidate(out_dir, candidate)
    updated = json.loads((out_dir / "last-known-good.json").read_text(encoding="utf-8"))
    status = json.loads((out_dir / "candidate-status.json").read_text(encoding="utf-8"))
    assert updated["version"] == "release-next"
    assert updated["configuration"] == candidate["validated_configuration"]
    assert status["status"] == "SAFE"
    assert status["release_eligible"] is True
    # Gate validation does not itself install a candidate.
    assert status["active_version"] is None
    assert status["activated"] is False
