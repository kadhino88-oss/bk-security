from bk_security.core import SecurityCore
from bk_security.events.models import SecurityEvent

def test_two_related_alerts_create_incident():
    core=SecurityCore()
    for port in (4444,4445):
        core.ingest(SecurityEvent(event_type='network.packet',source='test',host_id='pc-1',data={'dst_port':port,'process_name':'powershell.exe'}))
    assert len(core.alerts)==2
    assert len(core.incidents)==1
    assert core.incidents[0].host_id == "pc-1"
    assert core.incidents[0].title == core.alerts[0].title
    assert core.incidents[0].risk_score >= max(a.risk_score for a in core.alerts)
    assert all(a.correlation_id==core.incidents[0].incident_id for a in core.alerts)
