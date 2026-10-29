from bk_security.core import SecurityCore
from bk_security.events.models import SecurityEvent


def test_suspicious_network_event_generates_alert():
    core = SecurityCore()
    event = SecurityEvent(
        event_type="network.packet",
        source="bk_network_sensor",
        host_id="host-01",
        data={
            "process_name": "powershell.exe",
            "dst_port": 4444,
            "behavior_score": 65,
            "destination_score": 30,
        },
    )
    alerts = core.ingest(event)
    assert alerts
    assert alerts[0].risk_score >= 55
    assert alerts[0].severity in {"medium", "high", "critical"}

def test_detection_alerts_use_source_event_timestamps():
    from bk_security.detection.rules import DetectionEngine

    event_time = "2026-10-06T10:15:00+00:00"
    events = [
        SecurityEvent(
            event_type="network.packet",
            source="test",
            host_id="host-time",
            timestamp=event_time,
            data={"process_name": "powershell.exe", "dst_port": 4444},
        ),
        SecurityEvent(
            event_type="network.dns",
            source="test",
            host_id="host-time",
            timestamp=event_time,
            data={"domain": "a1b2c3d4e5f6g7h8i9j0.example.com"},
        ),
    ]

    detector = DetectionEngine()
    for event in events:
        alerts = detector.evaluate(event)
        assert alerts
        assert all(alert.timestamp == event.timestamp for alert in alerts)

