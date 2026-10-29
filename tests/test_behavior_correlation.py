from bk_security.core import SecurityCore
from bk_security.events.models import SecurityEvent
from bk_security.detection.behavior import BehaviorEngine

def packet(**kw):
    data={"src_ip":"10.0.0.2","dst_ip":"8.8.8.8","src_port":50000,"dst_port":443,"protocol":"TCP","size":100,"direction":"outbound","pid":10,"process_name":"chrome.exe"}; data.update(kw)
    return SecurityEvent(event_type="network.packet", source="test", host_id="host-a", data=data)

def test_new_destination_behavior_is_observation_only():
    core=SecurityCore(); alerts=core.ingest(packet())
    assert alerts == []
    assert core.events[-1].data["behavior_score"] == 12
    assert core.incidents == []

def test_repeated_alerts_are_correlated():
    core=SecurityCore()
    first=core.ingest(packet(process_name="powershell.exe", dst_port=4444))[0]
    second=core.ingest(packet(process_name="powershell.exe", dst_port=4444))[0]
    assert second.risk_score >= first.risk_score
    assert len(core.incidents[0].alert_ids) >= 2


def test_behavior_baseline_memory_is_bounded():
    engine = BehaviorEngine(max_hosts=2, max_flows=3, max_destinations_per_host=1)
    def event(host, destination):
        return SecurityEvent(event_type="network.packet", source="test", host_id=host,
                             data={"dst_ip": destination, "dst_port": 443})

    assert "new_destination" in engine.evaluate(event("h1", "203.0.113.1")).reasons
    engine.evaluate(event("h1", "203.0.113.2"))
    assert "new_destination" in engine.evaluate(event("h1", "203.0.113.1")).reasons
    engine.evaluate(event("h2", "203.0.113.3"))
    engine.evaluate(event("h3", "203.0.113.4"))

    assert len(engine._known_destinations) <= 2
    assert len(engine._flows) <= 3
    assert all(len(destinations) <= 1 for destinations in engine._known_destinations.values())

    for _ in range(500):
        engine.evaluate(event("h3", "203.0.113.4"))
    assert max(map(len, engine._flows.values())) <= engine.beacon_threshold + 35


def test_new_destination_alone_is_observation_not_alert():
    core = SecurityCore()
    alerts = core.ingest(packet())
    assert alerts == []
    assert core.events[-1].data["behavior_score"] == 12
    assert core.events[-1].data["behavior_reasons"] == ["new_destination"]


def test_repetitive_connection_alerts_once_at_threshold():
    core = SecurityCore()
    for _ in range(core.behavior.beacon_threshold - 1):
        assert core.ingest(packet()) == []
    alerts = core.ingest(packet())
    assert len(alerts) == 1
    assert "repetitive_connection_pattern" in core.events[-1].data["behavior_reasons"]
    for _ in range(5):
        assert core.ingest(packet()) == []
