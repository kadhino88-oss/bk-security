from __future__ import annotations
import os
from fastapi import Depends, HTTPException, Query
from ..sensors.host_identity import HostIdentitySensor
from ..sensors.dns import DNSResolutionSensor
from ..sensors.socket import SocketAttributionSensor
from ..sensors.endpoint import EndpointProcessSensor
from ..capture.live import LivePacketCapture
from ..configuration import effective_capture_mode
from ..network import build_network_topology

_MITRE_TACTICS = {
    'T1059.001':'Execution','T1059.003':'Execution','T1059.005':'Execution',
    'T1218.005':'Defense Evasion','T1218.010':'Defense Evasion','T1218.011':'Defense Evasion',
    'T1140':'Defense Evasion','T1197':'Defense Evasion','T1053.005':'Persistence',
    'T1053.002':'Execution','T1071':'Command and Control','T1041':'Exfiltration',
    'T1003':'Credential Access','T1568.003':'Command and Control','T1021':'Lateral Movement',
}

host_sensor = HostIdentitySensor()

def install(app, core, require):
    @app.get('/api/v1/host/identity')
    async def host_identity(p=Depends(require('admin','analyst','viewer'))):
        return host_sensor.status()
    @app.get('/api/v1/sensors/status')
    async def sensor_status(p=Depends(require('admin','analyst','viewer'))):
        return getattr(app.state, 'sensor_manager', None).status() if getattr(app.state, 'sensor_manager', None) else {'sensors':{},'running':0}
    @app.post('/api/v1/dns/resolve')
    async def dns_resolve(body: dict, p=Depends(require('admin','analyst'))):
        sensor=DNSResolutionSensor(core.ingest, host_sensor.identity.host_id)
        event=sensor.observe(str(body.get('domain','')), str(body.get('qtype','A')), bool(body.get('resolve',False)))
        return {'event':event.to_dict()}
    @app.get('/api/v1/processes/sockets')
    async def socket_snapshot(p=Depends(require('admin','analyst'))):
        manager=getattr(app.state,'sensor_manager',None)
        sensor=manager.sensors.get('socket_attribution') if manager else None
        if sensor is None:
            sensor=SocketAttributionSensor(host_sensor.identity.host_id, core)
        events=[] if sensor.running else sensor.snapshot()
        return {'events':[e.to_dict() for e in events], 'connections':list(sensor.connections.values()),
                'count':len(sensor.connections),'events_emitted':len(events),'sensor':sensor.status()}
    @app.get('/api/v1/processes')
    async def process_snapshot(p=Depends(require('admin','analyst'))):
        manager=getattr(app.state,'sensor_manager',None)
        sensor=manager.sensors.get('endpoint_process') if manager else None
        records=list(sensor.records.values()) if sensor else []
        return {'processes':records,'count':len(records),'sensor':sensor.status() if sensor else {'running':False}}
    @app.get('/api/v1/dns/events')
    async def dns_events(p=Depends(require('admin','analyst'))):
        records=[event.to_dict() for event in core.events if event.event_type=='network.dns'][-200:]
        return {'events':records,'count':len(records)}
    @app.get('/api/v1/mitre')
    async def mitre_view(p=Depends(require('admin','analyst','viewer'))):
        incidents={item.incident_id:item.to_dict() for item in core.incidents[-1000:]}
        by_id={}
        for alert in core.alerts:
            for technique in alert.mitre_techniques:
                row=by_id.setdefault(technique,{'technique':technique,'count':0,'hosts':set(),'incidents':set(),'evidence':[]})
                row['count']+=1; row['hosts'].add(alert.host_id)
                if alert.correlation_id in incidents: row['incidents'].add(alert.correlation_id)
                if len(row['evidence'])<20:
                    row['evidence'].append({'alert_id':alert.alert_id,'title':alert.title,'timestamp':alert.timestamp})
        result=[]
        for technique,row in sorted(by_id.items()):
            row['hosts']=sorted(row['hosts']); row['incidents']=sorted(row['incidents'])
            row['tactic']=_MITRE_TACTICS.get(technique,'Unclassified'); result.append(row)
        return {'techniques':result,'count':len(result)}
    @app.get('/api/v1/threat-intelligence/matches')
    async def threat_intelligence_matches(p=Depends(require('admin','analyst','viewer'))):
        matches={}
        for event in core.events:
            match=event.enrichment.get('threat_intel')
            if not match or not match.get('matched'): continue
            key=(str(match.get('indicator_type','unknown')),str(match.get('indicator','')).lower())
            row=matches.setdefault(key,{'indicator':match.get('indicator'),'type':match.get('indicator_type'),
                'source':match.get('source'),'confidence':match.get('confidence'),'first_seen':event.timestamp,
                'last_seen':event.timestamp,'matches':0,'hosts':set()})
            row['first_seen']=min(row['first_seen'],event.timestamp); row['last_seen']=max(row['last_seen'],event.timestamp)
            row['matches']+=1; row['hosts'].add(event.host_id)
        result=list(matches.values())
        for row in result: row['hosts']=sorted(row['hosts'])
        result.sort(key=lambda item:(-item['matches'],item['indicator'] or ''))
        return {'matches':result,'count':len(result)}
    @app.get('/api/v1/settings')
    async def settings(p=Depends(require('admin','analyst'))):
        manager=getattr(app.state,'sensor_manager',None)
        return {
            'capture_mode':effective_capture_mode(os.environ),
            'capture_interface':os.getenv('BK_SECURITY_CAPTURE_INTERFACE') or None,
            'max_events_per_second':int(os.getenv('BK_SECURITY_MAX_EVENTS_PER_SECOND','500')),
            'live_capture_available':LivePacketCapture.available(),
            'sensors':manager.status() if manager else {'sensors':{},'running':0},
            'response_adapters':sorted(action.value for action in core.response.adapters),
        }
    @app.get('/api/v1/network/topology')
    async def network_topology(minutes: int = Query(default=60, ge=1, le=1440), p=Depends(require('admin','analyst','viewer'))):
        return build_network_topology(core.events, minutes=minutes)
    @app.post('/api/v1/sensors/{name}/start')
    async def start_sensor(name: str, p=Depends(require('admin','analyst'))):
        manager = getattr(app.state, 'sensor_manager', None)
        if not manager or name not in manager.sensors:
            raise HTTPException(404, 'Sensor not found')
        manager.start(name)
        return manager.status()['sensors'][name]
    @app.post('/api/v1/sensors/{name}/stop')
    async def stop_sensor(name: str, p=Depends(require('admin','analyst'))):
        manager = getattr(app.state, 'sensor_manager', None)
        if not manager or name not in manager.sensors:
            raise HTTPException(404, 'Sensor not found')
        manager.stop(name)
        return manager.status()['sensors'][name]
    @app.post('/api/v1/lan/discover')
    async def lan_discover(body: dict, p=Depends(require('admin','analyst'))):
        manager = getattr(app.state, 'sensor_manager', None)
        sensor = manager.sensors.get('lan') if manager else None
        if not sensor:
            raise HTTPException(503, 'LAN sensor is not configured')
        interface = str(body.get('interface') or '').strip()
        subnet = str(body.get('subnet') or '').strip()
        if not interface or not subnet:
            raise HTTPException(422, 'Both interface and local subnet are required')
        try:
            events = sensor.discover_once(interface, subnet)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        return {'count': len(events), 'devices': [event.to_dict() for event in events], 'sensor': sensor.status()}
