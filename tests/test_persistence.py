import sqlite3

import pytest

from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.events.models import SecurityEvent
from bk_security.policy.engine import Action


def packet(host="host-persist", destination="203.0.113.25"):
    return SecurityEvent(
        event_type="network.packet",
        source="test",
        host_id=host,
        data={"dst_ip": destination, "dst_port": 4444, "process_name": "powershell.exe"},
    )


def test_events_alerts_incidents_and_active_correlation_survive_restart(tmp_path):
    database = str(tmp_path / "history.sqlite3")
    first = SecurityCore(SecurityStore(database))
    first.ingest(packet())
    first.ingest(packet(destination="203.0.113.26"))
    incident_id = first.incidents[0].incident_id
    event_ids = {event.event_id for event in first.events}
    assert len(first.alerts) == 2
    assert len(first.incidents) == 1

    first.store.close()
    restarted = SecurityCore(SecurityStore(database))
    assert event_ids <= {event.event_id for event in restarted.events}
    assert {alert.alert_id for alert in restarted.alerts}
    assert restarted.incidents[0].incident_id == incident_id
    assert len(restarted.incidents) == 1

    restarted.ingest(packet(destination="203.0.113.27"))
    assert len(restarted.incidents) == 1
    assert restarted.incidents[0].incident_id == incident_id
    assert len(restarted.incidents[0].alert_ids) == 3


def test_incident_history_restores_in_chronological_core_order(tmp_path):
    database = str(tmp_path / "incident-order.sqlite3")
    first = SecurityCore(SecurityStore(database))
    first.ingest(packet(host="host-old"))
    first.ingest(packet(host="host-new"))
    created_order = [incident.incident_id for incident in first.incidents]
    assert len(created_order) == 2

    first.store.close()
    restarted = SecurityCore(SecurityStore(database))
    assert [incident.incident_id for incident in restarted.incidents] == created_order


def test_response_execution_and_rollback_state_survive_restart(tmp_path):
    database = str(tmp_path / "response-history.sqlite3")
    first = SecurityCore(SecurityStore(database))

    class TestAdapter:
        def execute(self, target, action, reason):
            return {"accepted": True, "target": target}

        def verify(self, target, action, result):
            return {"verified": True}

        def rollback(self, execution):
            return {"restored": True}

        def verify_rollback(self, execution, result):
            return {"verified": True}

    first.response.adapters[Action.BLOCK] = TestAdapter()
    plan = first.plan_response(
        Action.BLOCK, "203.0.113.44", "test approval", actor="analyst", actor_role="analyst",
        risk_level="critical", dry_run=False, plan_id="execution-persisted",
    )
    first.approve_response(plan["plan_id"], actor="approver", role="approver")
    execution = first.execute_response(
        plan["plan_id"], plan["plan_id"], actor="responder", actor_role="responder", dry_run=False,
    )
    assert execution["status"] == "executed"
    first.approve_response(plan["plan_id"], actor="approver", role="approver", rollback=True)
    assert first.rollback_response(
        "execution-persisted", actor="responder", actor_role="responder",
    )["status"] == "rolled_back"

    restarted = SecurityCore(SecurityStore(database))

    assert restarted.response.executions["execution-persisted"]["rollback"] == {"restored": True}
    assert restarted.store.list_response_actions()[0]["timestamp"] == execution["planned_at"]


def test_interrupted_response_is_restored_as_degraded_without_reexecution(tmp_path):
    database = str(tmp_path / "interrupted-response.sqlite3")
    store = SecurityStore(database)
    store.save_response_action({
        "plan_id": "interrupted-1", "execution_id": "interrupted-1",
        "action": "block", "target": "203.0.113.9", "reason": "interruption test",
        "evidence_ids": ["event-1"], "status": "executing", "executed": False,
        "dry_run": False, "policy_decision": {"allowed": True},
    })

    restarted = SecurityCore(store)
    restored = restarted.response.executions["interrupted-1"]
    assert restored["status"] == "degraded"
    assert restored["executed"] is False
    assert restored["recovered_incomplete_execution"] is True
    assert any(
        row["action"] == "response_execution_recovered"
        for row in restarted.store.list_audit(20)
    )
    restarted.store.close()


def test_dns_enrichment_context_survives_restart(tmp_path):
    database = str(tmp_path / "dns-history.sqlite3")
    first = SecurityCore(SecurityStore(database))
    dns = SecurityEvent(
        event_type="network.dns",
        source="test",
        host_id="host-dns",
        data={"domain": "beacon.example", "answers": ["203.0.113.88"]},
    )
    first.ingest(dns)

    first.store.close()
    restarted = SecurityCore(SecurityStore(database))
    packet_event = SecurityEvent(
        event_type="network.packet",
        source="test",
        host_id="host-dns",
        data={"dst_ip": "203.0.113.88", "dst_port": 4444, "process_name": "powershell.exe"},
    )
    alerts = restarted.ingest(packet_event)

    assert packet_event.data["domain"] == "beacon.example"
    assert dns.event_id in packet_event.data["related_event_ids"]
    assert alerts and dns.event_id in alerts[0].source_event_ids


def test_repository_creates_required_tables_and_bounds_event_retention(tmp_path):
    database = str(tmp_path / "repository.sqlite3")
    store = SecurityStore(database, max_events=2)
    store.prune_interval = 1
    for index in range(3):
        store.save_event(SecurityEvent(
            event_type="endpoint.process", source="test", host_id="host-1",
            data={"index": index},
        ))
    store.save_host({"host_id": "host-1", "hostname": "bk-test", "last_seen": "2026-10-01T00:00:00+00:00"})
    store.save_host({"host_id": "host-1", "last_seen": "2026-10-01T00:01:00+00:00"})
    store.save_response_action({"action_id": "response-1", "status": "dry_run", "timestamp": "2026-10-01T00:01:00+00:00"})

    store.flush()
    with sqlite3.connect(database) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        event_count = connection.execute("SELECT count(*) FROM events").fetchone()[0]

    assert {"events", "alerts", "incidents", "audit", "hosts", "response_actions"} <= tables
    assert event_count == 2
    assert [record["data"]["index"] for record in store.list_events(10)] == [1, 2]
    assert store.list_hosts()[0]["hostname"] == "bk-test"
    assert store.list_response_actions()[0]["action_id"] == "response-1"


def test_security_audit_rejects_updates_and_deletions(tmp_path):
    database = str(tmp_path / "append-only-audit.sqlite3")
    store = SecurityStore(database)
    store.audit("responder", "response_execute", "203.0.113.1", {"status": "dry_run"})
    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only audit"):
            connection.execute("UPDATE audit SET action='tampered'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only audit"):
            connection.execute("DELETE FROM audit")
        assert connection.execute("SELECT action FROM audit").fetchone()[0] == "response_execute"
    store.close()


def test_bounded_write_queue_applies_backpressure_without_dropping_events(tmp_path):
    store = SecurityStore(str(tmp_path / "bounded-queue.sqlite3"), max_pending_writes=1)
    store.write_batch_size = 32
    for index in range(64):
        store.save_event(SecurityEvent(
            event_type="network.dns", source="queue-test", host_id="host-queue",
            data={"domain": f"{index}.example"},
        ))

    store.close()

    records = store.list_events(100)
    assert len(records) == 64
    assert store.writer_status["capacity"] == 1
    assert store.writer_status["healthy"] is True
    assert store.writer_status["running"] is False
