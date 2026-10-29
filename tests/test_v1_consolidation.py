from datetime import datetime, timedelta, timezone

from bk_security.core import SecurityCore
from bk_security.events.models import SecurityEvent
from bk_security.sensors.host_identity import HostIdentitySensor
from bk_security.sensors.dns import DNSResolutionSensor
from bk_security.sensors.socket import SocketAttributionSensor

def test_host_identity_is_stable():
    a=HostIdentitySensor().identity; b=HostIdentitySensor().identity
    assert a.host_id == b.host_id and a.hostname

def test_dns_event_enters_core():
    core=SecurityCore(); sensor=DNSResolutionSensor(core.ingest,'h1')
    event=sensor.observe('example.com',resolve=False)
    assert event.event_type=='network.dns' and core.events[-1].event_id==event.event_id


def test_dns_answer_context_enriches_packet_alert_and_links_evidence():
    core=SecurityCore()
    dns=SecurityEvent(
        event_type='network.dns',source='test',host_id='h1',
        data={'domain':'beacon.example','answers':['203.0.113.10']},
    )
    core.ingest(dns)
    packet=SecurityEvent(
        event_type='network.packet',source='test',host_id='h1',
        data={'dst_ip':'203.0.113.10','dst_port':4444,'process_name':'powershell.exe'},
    )

    alerts=core.ingest(packet)

    assert packet.data['domain']=='beacon.example'
    assert alerts and dns.event_id in alerts[0].source_event_ids
    assert {'field':'destination_domain','value':'beacon.example'} in alerts[0].evidence


def test_dns_context_expires_after_one_hour():
    core=SecurityCore()
    now=datetime.now(timezone.utc)
    dns=SecurityEvent(
        event_type='network.dns',source='test',host_id='h1',
        timestamp=(now-timedelta(hours=1,seconds=1)).isoformat(),
        data={'domain':'old.example','answers':['203.0.113.11']},
    )
    packet=SecurityEvent(
        event_type='network.packet',source='test',host_id='h1',
        timestamp=now.isoformat(),
        data={'dst_ip':'203.0.113.11','dst_port':443,'process_name':'browser.exe'},
    )

    core.ingest(dns)
    core.ingest(packet)

    assert 'domain' not in packet.data
    assert 'related_event_ids' not in packet.data


def test_socket_sensor_is_non_destructive():
    core=SecurityCore(); events=SocketAttributionSensor('h1',core).snapshot()
    assert isinstance(events,list)

def test_incident_accumulates_mitre():
    core=SecurityCore()
    for port in (4444,4445):
        core.ingest(SecurityEvent(event_type='network.packet',source='test',host_id='h1',data={'dst_port':port,'process_name':'powershell.exe'}))
    assert core.incidents and core.incidents[0].mitre_techniques
