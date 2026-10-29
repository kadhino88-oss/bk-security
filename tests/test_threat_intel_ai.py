from bk_security.core import SecurityCore
from bk_security.events.models import SecurityEvent


def test_ioc_enrichment_and_ai_pipeline():
    core = SecurityCore()
    core.threat_intel.add_ip("203.0.113.50", tags=["malware-c2"])
    event = SecurityEvent(
        event_type="network.packet", source="test", host_id="host-1",
        data={"dst_ip":"203.0.113.50", "dst_port":4444, "process_name":"powershell.exe"},
        network={"dst_ip":"203.0.113.50"},
    )
    alerts = core.ingest(event)
    assert alerts
    assert event.enrichment["threat_intel"]["matched"] is True
    assert "T1059.001" in alerts[0].mitre_techniques
    result = core.ai.investigate(__import__('bk_security.ai.contracts', fromlist=['InvestigationRequest']).InvestigationRequest(alerts[0], threat_context={"threat_intel": event.enrichment["threat_intel"]}))
    assert result.disposition in {"malicious", "suspicious", "needs_review"}
