from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.deployment import DeploymentContext
from bk_security.ingestion import EnvelopeError, IngestionQueue, event_id_for, ingestion_settings, parse_envelope


def _context(customer="customer-42"):
    return DeploymentContext(profile="dedicated_customer", customer_ref=customer,
                             deployment_id=str(uuid4()), region="eu-ch")


@pytest.fixture
def context():
    return _context()


def _envelope(context, envelope_id="env-0001", agent="agent-1", **event_over):
    event = {"event_type": "network.connection", "source": "agent", "host_id": "host-1"}
    event.update(event_over)
    return {"schema_version": 1, "envelope_id": envelope_id, "agent_id": agent,
            "customer_ref": context.customer_ref, "deployment_id": context.deployment_id, "sequence": 1,
            "event": event}


class _Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def _queue(tmp_path, context, name="ingest.db", **kw):
    return IngestionQueue(str(tmp_path / name), context, **kw)


def _store_core(tmp_path, context, name="customer.db"):
    store = SecurityStore(path=str(tmp_path / name), deployment_context=context)
    return store, SecurityCore(store)


# ---- envelope contract ---------------------------------------------------------------------------------------

def test_local_profile_cannot_accept_remote_envelopes(context):
    with pytest.raises(EnvelopeError) as err:
        parse_envelope(_envelope(context), DeploymentContext())
    assert err.value.code == "tenant_scope_unavailable"
    with pytest.raises(ValueError):
        IngestionQueue("x.db", DeploymentContext())


@pytest.mark.parametrize("mutation,code", [
    ({"schema_version": 2}, "unsupported_version"),
    ({"schema_version": True}, "invalid_envelope"),
    ({"schema_version": []}, "invalid_envelope"),
    ({"customer_ref": "customer-99"}, "tenant_mismatch"),
    ({"deployment_id": str(uuid4())}, "tenant_mismatch"),
    ({"sequence": -1}, "invalid_envelope"),
    ({"envelope_id": "bad id!"}, "bad_identifier"),
    ({"envelope_id": "1"}, "bad_identifier"),
    ({"extra": 1}, "invalid_envelope"),
])
def test_invalid_envelopes_are_quarantined_not_queued(tmp_path, context, mutation, code):
    q = _queue(tmp_path, context)
    body = _envelope(context)
    body.update(mutation)
    ack = q.submit(body, authenticated_agent="agent-1")
    assert (ack.status, ack.reason) == ("quarantined", code)
    assert q.stats()["quarantined"] == 1 and q.claim() == []


@pytest.mark.parametrize("event_over,code", [
    ({"event_type": "nope"}, "bad_event"),
    ({"event_type": []}, "bad_event"),
    ({"event_type": "security.alert"}, "bad_event"),
    ({"event_type": "response.action"}, "bad_event"),
    ({"evil": 1}, "bad_event"),
    ({"tags": "simulation"}, "bad_event"),
    ({"data": "oops"}, "bad_event"),
    ({"network": ["x"]}, "bad_event"),
    ({"severity": "apocalyptic"}, "bad_event"),
    ({"host_id": ""}, "bad_event"),
    ({"event_id": "11111111-1111-1111-1111-111111111111"}, "server_owned_field"),
    ({"risk_score": 100}, "server_owned_field"),
    ({"enrichment": {"threat_intel": {"verdict": "benign"}}}, "server_owned_field"),
    ({"correlation_id": "inc-forged"}, "server_owned_field"),
    ({"data": {"behavior_score": 99}}, "server_owned_field"),
    ({"timestamp": "1999-01-01T00:00:00+00:00"}, "bad_timestamp"),
    ({"timestamp": "2026-10-26T10:00:00"}, "bad_event"),
])
def test_event_fields_are_typed_and_server_owned_fields_are_refused(tmp_path, context, event_over, code):
    ack = _queue(tmp_path, context).submit(_envelope(context, **event_over), authenticated_agent="agent-1")
    assert (ack.status, ack.reason) == ("quarantined", code)


def test_hostile_json_never_escapes_as_an_exception(tmp_path, context):
    q = _queue(tmp_path, context)
    deep = b"[" * 100_000 + b"]" * 100_000
    assert q.submit(b"{not json", authenticated_agent="agent-1").reason == "malformed"
    assert q.submit(b"x" * 70_000, authenticated_agent="agent-1").reason == "too_large"
    assert q.submit(deep[:60_000], authenticated_agent="agent-1").status == "quarantined"
    nested = _envelope(context)
    inner = {}
    nested["event"]["data"] = inner
    for _ in range(5000):
        inner["x"] = {}
        inner = inner["x"]
    assert q.submit(nested, authenticated_agent="agent-1").status == "quarantined"


def test_quarantine_keeps_no_raw_content_and_caps_detail(tmp_path, context):
    q = _queue(tmp_path, context)
    body = _envelope(context)
    body["event"]["X" * 60_000] = "secret-password-value"
    q.submit(json.dumps(body), authenticated_agent="agent-1")
    with sqlite3.connect(tmp_path / "ingest.db") as db:
        columns = [row[1] for row in db.execute("PRAGMA table_info(quarantine)")]
        detail, raw_hash = db.execute("SELECT detail, raw_hash FROM quarantine").fetchone()
    assert "raw_excerpt" not in columns
    assert len(detail) <= 256 and "secret-password-value" not in detail
    assert len(raw_hash) == 64


def test_quarantine_is_capped(tmp_path, context):
    q = _queue(tmp_path, context, max_quarantine=3)
    for _ in range(10):
        q.submit(b"{bad", authenticated_agent="agent-1")
    assert q.stats()["quarantined"] == 3


def test_agent_identity_must_match_authenticated_agent(tmp_path, context):
    ack = _queue(tmp_path, context).submit(_envelope(context, agent="agent-2"), authenticated_agent="agent-1")
    assert ack.reason == "agent_mismatch"


def test_event_identity_and_timestamp_are_fixed_at_accept_time(tmp_path, context):
    clock = _Clock()
    q = _queue(tmp_path, context, clock=clock)
    q.submit(_envelope(context), authenticated_agent="agent-1")
    clock.now += 3600
    lease = q.claim()[0]
    assert lease.event["event_id"] == event_id_for(context, "agent-1", "env-0001")
    received = datetime.fromtimestamp(1_800_000_000.0, timezone.utc).isoformat()
    assert lease.event["timestamp"] == received
    observed = (datetime.fromtimestamp(clock.now, timezone.utc) - timedelta(minutes=1)).isoformat()
    q.submit(_envelope(context, "env-0002", timestamp=observed), authenticated_agent="agent-1")
    clock.now += 31
    second = event_id_for(context, "agent-1", "env-0002")
    assert [l.event["timestamp"] for l in q.claim() if l.event["event_id"] == second] == [observed]


def test_payload_is_sanitized_before_it_is_stored(tmp_path, context):
    q = _queue(tmp_path, context)
    q.submit(_envelope(context, data={"password": "hunter2-SECRET"}, process={"cmdline": "tool --token=abc123SECRET"}),
             authenticated_agent="agent-1")
    with sqlite3.connect(tmp_path / "ingest.db") as db:
        payload = db.execute("SELECT payload FROM queue").fetchone()[0]
    assert "hunter2-SECRET" not in payload and "abc123SECRET" not in payload
    assert "customer_ref" not in payload


# ---- tenant binding -----------------------------------------------------------------------------------------

def test_queue_file_is_bound_to_one_customer_deployment(tmp_path, context):
    q = _queue(tmp_path, context)
    q.submit(_envelope(context), authenticated_agent="agent-1")
    with pytest.raises(ValueError, match="different customer deployment"):
        _queue(tmp_path, _context("customer-two"))
    assert _queue(tmp_path, context).stats()["pending"] == 1


def test_existing_unbound_or_foreign_schema_file_is_refused(tmp_path, context):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE queue(seq INTEGER PRIMARY KEY, payload TEXT)")
        db.execute("INSERT INTO queue(payload) VALUES('{}')")
    with pytest.raises(ValueError, match="incompatible schema"):
        IngestionQueue(str(path), context)


# ---- dedupe ---------------------------------------------------------------------------------------------------

def test_identical_retry_is_a_duplicate_and_id_reuse_with_new_content_is_quarantined(tmp_path, context):
    q = _queue(tmp_path, context)
    assert q.submit(_envelope(context), authenticated_agent="agent-1").status == "accepted"
    assert q.submit(_envelope(context), authenticated_agent="agent-1").status == "duplicate"
    conflict = q.submit(_envelope(context, host_id="other"), authenticated_agent="agent-1")
    assert (conflict.status, conflict.reason) == ("quarantined", "envelope_id_conflict")
    assert len(q.claim()) == 1


def test_dedupe_is_scoped_per_agent(tmp_path, context):
    q = _queue(tmp_path, context)
    assert q.submit(_envelope(context, agent="agent-1"), authenticated_agent="agent-1").status == "accepted"
    assert q.submit(_envelope(context, agent="agent-2"), authenticated_agent="agent-2").status == "accepted"
    leases = q.claim()
    assert len({l.event["event_id"] for l in leases}) == 2


# ---- leases, replay, durability -------------------------------------------------------------------------------

def test_unacked_work_is_replayed_by_a_new_process_using_wall_clock_leases(tmp_path, context):
    clock = _Clock()
    q = _queue(tmp_path, context, clock=clock, lease_seconds=30)
    q.submit(_envelope(context), authenticated_agent="agent-1")
    assert len(q.claim()) == 1  # consumer crashes before complete()
    assert q.claim() == []  # still leased
    later = _Clock(clock.now + 31)  # a different process after a restart; leases are wall-clock based
    reopened = _queue(tmp_path, context, clock=later, lease_seconds=30)
    leases = reopened.claim()
    assert len(leases) == 1 and leases[0].attempt == 2
    assert reopened.complete(leases) == 1
    later.now += 31
    assert reopened.claim() == [] and reopened.stats()["done"] == 1
    assert reopened.submit(_envelope(context), authenticated_agent="agent-1").status == "duplicate"


def test_default_clock_is_wall_time(tmp_path, context):
    import time
    assert _queue(tmp_path, context).clock is time.time


def test_stale_lease_owner_cannot_complete_or_fail_a_reclaimed_item(tmp_path, context):
    clock = _Clock()
    q = _queue(tmp_path, context, clock=clock, lease_seconds=10)
    q.submit(_envelope(context), authenticated_agent="agent-1")
    stale = q.claim()
    clock.now += 11
    fresh = q.claim()
    assert q.complete(stale) == 0
    q.fail(stale[0], "late")
    assert q.stats()["quarantined"] == 0
    assert q.complete(fresh) == 1


def test_abandoned_poison_item_is_quarantined_after_max_attempts(tmp_path, context):
    clock = _Clock()
    q = _queue(tmp_path, context, clock=clock, lease_seconds=10, max_attempts=2)
    q.submit(_envelope(context), authenticated_agent="agent-1")
    for _ in range(2):  # consumer dies every time, never calling fail()
        assert len(q.claim()) == 1
        clock.now += 11
    assert q.claim() == []
    assert q.stats() == {"pending": 0, "leased": 0, "done": 1, "quarantined": 1}


def test_drain_acks_only_after_the_customer_store_flushes(tmp_path, context):
    store, core = _store_core(tmp_path, context)
    q = _queue(tmp_path, context)
    q.submit(_envelope(context), authenticated_agent="agent-1")

    def broken_flush(timeout=10.0):
        raise TimeoutError("disk unavailable")

    original = store.flush
    store.flush = broken_flush
    assert q.drain(core) == {"processed": 0, "failed": 1}
    assert q.stats()["pending"] == 1  # not acknowledged
    store.flush = original
    assert q.drain(core) == {"processed": 1, "failed": 0}
    stored = store.get_event(event_id_for(context, "agent-1", "env-0001"))
    assert stored is not None and stored["host_id"] == "host-1"
    store.close()


def test_replay_after_a_crash_does_not_reingest_an_event_already_stored(tmp_path, context):
    clock = _Clock()
    store, core = _store_core(tmp_path, context)
    q = _queue(tmp_path, context, clock=clock, lease_seconds=10)
    q.submit(_envelope(context), authenticated_agent="agent-1")
    lease = q.claim()[0]
    from bk_security.events.models import SecurityEvent
    core.ingest(SecurityEvent(**lease.event))  # processed, then the consumer crashed before complete()
    store.flush()
    before = len(core.events)
    clock.now += 11
    assert q.drain(core) == {"processed": 1, "failed": 0}
    assert len(core.events) == before
    store.close()


def test_drain_feeds_core_and_quarantines_poison_events(tmp_path, context):
    store, core = _store_core(tmp_path, context)
    q = _queue(tmp_path, context, max_attempts=2)
    q.submit(_envelope(context, "env-ok-0001"), authenticated_agent="agent-1")
    assert q.drain(core) == {"processed": 1, "failed": 0}
    assert core.events[-1].event_id == event_id_for(context, "agent-1", "env-ok-0001")

    class Broken:
        def ingest(self, _):
            raise RuntimeError("boom")

    q.submit(_envelope(context, "env-poison-1"), authenticated_agent="agent-1")
    assert q.drain(Broken())["failed"] == 1
    assert q.drain(Broken())["failed"] == 1
    assert q.stats()["quarantined"] == 1 and q.claim() == []
    store.close()


# ---- retention, quota, backpressure, settings -----------------------------------------------------------------

def test_done_rows_are_pruned_after_the_dedupe_window(tmp_path, context):
    clock = _Clock()
    store, core = _store_core(tmp_path, context)
    q = _queue(tmp_path, context, clock=clock, retention_seconds=100)
    q.submit(_envelope(context), authenticated_agent="agent-1")
    q.drain(core)
    with sqlite3.connect(tmp_path / "ingest.db") as db:
        assert db.execute("SELECT payload FROM queue").fetchone()[0] is None  # payload dropped once done
    clock.now += 101
    assert q.prune()["done_rows"] == 1
    assert q.stats()["done"] == 0
    store.close()


def test_agent_quota_throttles_without_affecting_other_agents(tmp_path, context):
    q = _queue(tmp_path, context, agent_rate=0.001, agent_burst=2)
    results = [q.submit(_envelope(context, f"env-a-{i:04d}"), authenticated_agent="agent-1").status for i in range(3)]
    assert results == ["accepted", "accepted", "throttled"]
    assert q.submit(_envelope(context, "env-b-0000", agent="agent-2"), authenticated_agent="agent-2").status == "accepted"


def test_policy_rejections_consume_quota(tmp_path, context):
    q = _queue(tmp_path, context, agent_rate=0.001, agent_burst=1,
               event_policy=lambda event: ("simulation_in_production", "no") if "simulation" in event["tags"] else None)
    assert q.submit(_envelope(context, tags=["simulation"]), authenticated_agent="agent-1").reason == "simulation_in_production"
    assert q.submit(_envelope(context, "env-0002", tags=["simulation"]), authenticated_agent="agent-1").status == "throttled"


def test_tracked_agent_buckets_are_bounded(tmp_path, context):
    q = _queue(tmp_path, context, max_tracked_agents=5)
    for index in range(50):
        q.submit(b"{bad", authenticated_agent=f"agent-{index}")
    assert len(q._buckets) == 5


def test_backpressure_when_queue_is_full(tmp_path, context):
    q = _queue(tmp_path, context, max_depth=1)
    assert q.submit(_envelope(context, "env-0001"), authenticated_agent="agent-1").status == "accepted"
    ack = q.submit(_envelope(context, "env-0002"), authenticated_agent="agent-1")
    assert ack.status == "backpressure" and ack.retry_after
    assert len(q.claim()) == 1


def test_in_memory_database_is_refused(context):
    with pytest.raises(ValueError):
        IngestionQueue(":memory:", context)


@pytest.mark.parametrize("name,value", [("BK_SECURITY_INGEST_MAX_DEPTH", "0"), ("BK_SECURITY_INGEST_AGENT_RATE", "abc"),
                                        ("BK_SECURITY_INGEST_AGENT_RATE", "nan"), ("BK_SECURITY_INGEST_LEASE_SECONDS", "-1")])
def test_invalid_settings_are_rejected_without_echoing_values(name, value):
    with pytest.raises(ValueError) as err:
        ingestion_settings({name: value})
    assert name in str(err.value) and value not in str(err.value).replace(name, "")


def test_production_configuration_reports_invalid_ingestion_settings():
    from bk_security.configuration import production_configuration_errors
    errors = production_configuration_errors({"BK_SECURITY_ENV": "production", "BK_SECURITY_INGEST_MAX_DEPTH": "x"})
    assert any("BK_SECURITY_INGEST_MAX_DEPTH" in error for error in errors)
