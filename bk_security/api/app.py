from __future__ import annotations
import asyncio, os, sys
import hmac
import ipaddress
import json
import math
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, Header, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from ..core import SecurityCore
from ..database import SecurityStore
from ..deployment import DeploymentContext
from ..events.models import EventType, SecurityEvent, Severity, utc_now
from ..incidents.lifecycle import IncidentStatus
from ..ai.contracts import InvestigationRequest
from ..auth import Principal, AuthError, issue_token, verify_token
from ..configuration import effective_capture_mode, production_configuration_errors
from ..provenance import is_simulation_record
from ..capture.live import LivePacketCapture
from ..capture.scenarios import SimulationScenario
from ..platforms import discover_interfaces, inspect_capture_runtime
from ..sensors.network import NetworkSensor
from ..sensors.manager import SensorManager
from ..sensors.lan import LANDiscoverySensor
from ..sensors.host_identity import HostIdentitySensor
from ..sensors.endpoint import EndpointProcessSensor
from ..sensors.socket import SocketAttributionSensor
from ..network import build_network_topology
from .soc_routes import install as install_soc_routes
from .response_routes import install as install_response_routes
from .reliability_routes import install as install_reliability_routes
from .monthly_audit_routes import install as install_monthly_audit_routes
from .ingestion_routes import install as install_ingestion_routes
from .autonomy_routes import install as install_autonomy_routes
from .hardening import RequestSizeLimitMiddleware, SecurityHeadersMiddleware, SlidingWindowRateLimiter
from ..reliability import BKRegressionGuardian, ReliabilityService

deployment_context = DeploymentContext.from_environment(os.environ)
core = SecurityCore(SecurityStore(deployment_context=deployment_context))
network_sensor = None

@asynccontextmanager
async def app_lifespan(_app):
    global network_sensor

    manager = getattr(_app.state, 'sensor_manager', None)

    # Start deterministic endpoint/LAN/socket sensors.
    if manager:
        manager.start_all()

    # Synthetic packets must never be presented as observed network traffic.
    # Desktop capture starts only after an authenticated operator selects an
    # interface and explicitly requests live capture.
    if network_sensor is None:
        configured_mode = os.getenv('BK_SECURITY_CAPTURE_MODE', 'stopped').lower()
        requested_mode = effective_capture_mode(os.environ)
        if configured_mode == 'simulation' and os.getenv('BK_SECURITY_ENV', '').strip().lower() == 'production':
            import logging
            logging.getLogger(__name__).warning('Production refused simulation capture; capture remains stopped.')
        interface = os.getenv('BK_SECURITY_CAPTURE_INTERFACE') or None
        scenario = os.getenv('BK_SECURITY_CAPTURE_SCENARIO') or None
        if requested_mode in {'live', 'simulation'}:
            network_sensor = NetworkSensor(
                core,
                host_id=_host_identity.identity.host_id,
                interface=interface,
                simulation=requested_mode == 'simulation',
                max_events_per_second=int(
                    os.getenv('BK_SECURITY_MAX_EVENTS_PER_SECOND', '500')
                ),
                scenario=scenario,
            )
            try:
                network_sensor.start()
            except Exception as exc:
                import logging
                logging.getLogger(__name__).exception(
                    'BK Security network capture failed to start: %s',
                    exc,
                )

    try:
        yield
    finally:
        if network_sensor:
            try:
                network_sensor.stop()
            except Exception:
                import logging
                logging.getLogger(__name__).exception(
                    'Failed to stop BK Security network sensor'
                )

        manager = getattr(_app.state, 'sensor_manager', None)
        if manager:
            manager.stop_all()

        try:
            await asyncio.to_thread(core.store.close)
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                'Failed to flush and close the BK Security database writer'
            )

app = FastAPI(title='BK Security API', version='1.0.0', lifespan=app_lifespan)
def _dashboard_static_path() -> Path:
    candidates = [
        Path(__file__).resolve().parents[2] / 'dashboard' / 'static',
        Path(getattr(sys, '_MEIPASS', '')) / 'dashboard' / 'static' if getattr(sys, '_MEIPASS', None) else Path(),
        Path(sys.executable).resolve().parent / 'dashboard' / 'static',
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]

dashboard_static = _dashboard_static_path()
if dashboard_static.is_dir():
    app.mount('/static', StaticFiles(directory=dashboard_static), name='bk-dashboard-static')

    dashboard_assets = dashboard_static / 'assets'
    if dashboard_assets.is_dir():
        app.mount('/assets', StaticFiles(directory=dashboard_assets), name='bk-dashboard-assets')

    @app.get('/', include_in_schema=False)
    async def dashboard_index():
        return FileResponse(dashboard_static / 'index.html')

origins=[x.strip() for x in os.getenv('BK_SECURITY_CORS_ORIGINS','http://localhost:5173,http://127.0.0.1:5173').split(',') if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=['GET','POST','PATCH','OPTIONS'], allow_headers=['Authorization','Content-Type'])
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=int(os.getenv('BK_SECURITY_MAX_REQUEST_BYTES', '1048576')))
app.add_middleware(SecurityHeadersMiddleware)

USERS = {
    'admin': (os.getenv('BK_SECURITY_ADMIN_PASSWORD', 'admin-dev-only'), 'admin'),
    'analyst': (os.getenv('BK_SECURITY_ANALYST_PASSWORD', 'analyst-dev-only'), 'analyst'),
    'viewer': (os.getenv('BK_SECURITY_VIEWER_PASSWORD', 'viewer-dev-only'), 'viewer'),
    'approver': (os.getenv('BK_SECURITY_APPROVER_PASSWORD', 'approver-dev-only'), 'approver'),
    'responder': (os.getenv('BK_SECURITY_RESPONDER_PASSWORD', 'responder-dev-only'), 'responder'),
}
if os.getenv('BK_SECURITY_ENV', '').strip().lower() == 'production':
    configuration_errors = production_configuration_errors(os.environ)
    if configuration_errors:
        raise RuntimeError('Invalid production configuration: ' + ' '.join(configuration_errors))

LOGIN_LIMITER = SlidingWindowRateLimiter(
    int(os.getenv('BK_SECURITY_LOGIN_LIMIT', '5')),
    float(os.getenv('BK_SECURITY_LOGIN_WINDOW_SECONDS', '60')),
)
EVENT_LIMITER = SlidingWindowRateLimiter(
    int(os.getenv('BK_SECURITY_API_EVENT_LIMIT', '1000')),
    float(os.getenv('BK_SECURITY_API_EVENT_WINDOW_SECONDS', '60')),
)

class Login(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)

class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus

class CaptureStart(BaseModel):
    mode: str | None = Field(default=None, pattern="^(live|simulation)$")
    interface: str | None = Field(default=None, max_length=256)
    scope: str = Field(default='endpoint', pattern='^(endpoint|mirror)$')
    scenario: SimulationScenario | None = None

class EventIn(BaseModel):
    event_type: EventType
    source: str = Field(min_length=1, max_length=64)
    host_id: str = Field(min_length=1, max_length=256)
    severity: Severity = 'info'
    data: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=64)
    process: dict = Field(default_factory=dict)
    network: dict = Field(default_factory=dict)

    @field_validator('data', 'process', 'network')
    @classmethod
    def limit_event_object_size(cls, value: dict) -> dict:
        if len(json.dumps(value, default=str).encode('utf-8')) > 65_536:
            raise ValueError('Event data sections cannot exceed 64 KiB')
        return value

def enforce_rate_limit(limiter: SlidingWindowRateLimiter, key: str) -> None:
    allowed, retry_after = limiter.allow(key)
    if not allowed:
        raise HTTPException(429, 'Rate limit exceeded', headers={'Retry-After': str(max(1, math.ceil(retry_after)))})

def principal(authorization: str|None=Header(default=None)) -> Principal:
    if not authorization or not authorization.lower().startswith('bearer '): raise HTTPException(401,'Authentication required')
    try:
        current = verify_token(authorization.split(' ',1)[1], deployment_context=deployment_context)
        if not _auth_session_allowed(current):
            raise AuthError('session revoked or not registered for this deployment')
        return current
    except AuthError as e: raise HTTPException(401,str(e))

def _auth_session_allowed(current: Principal) -> bool:
    if deployment_context.profile == 'dedicated_customer' and not current.token_id:
        return False
    if not current.token_id:
        return True
    status = core.store.auth_session_status(current.token_id)
    if deployment_context.profile == 'dedicated_customer':
        return status == 'active'
    # Older local tokens can be stateless, but sessions issued by this API are
    # checked so an explicit logout takes effect immediately.
    return status not in {'revoked', 'expired'}

def require(*roles):
    def dep(p: Principal=Depends(principal)):
        if roles and p.role not in roles: raise HTTPException(403,'Insufficient role')
        return p
    dep.allowed_roles = frozenset(roles)
    return dep

def overview():
    counts={s:0 for s in ('critical','high','medium','low','info')}
    for a in core.alerts:
        counts[a.severity]=counts.get(a.severity,0)+1
    open_inc=[i for i in core.incidents if str(i.status).upper() not in ('RESOLVED','CLOSED')]
    hosts=sorted({e.host_id for e in core.events})
    manager=getattr(app.state,'sensor_manager',None)
    sensor_status=manager.status() if manager else {'sensors':{},'running':0}
    return {
        'alerts':counts,'open_incidents':len(open_inc),'hosts':len(hosts),'events':len(core.events),
        'network_packets':sum(event.event_type=='network.packet' for event in core.events),
        'sensors_running':sensor_status.get('running',0),'sensors_total':len(sensor_status.get('sensors',{})),
        'risk_max':max((a.risk_score for a in core.alerts),default=0),
    }

install_response_routes(app, core, require)
install_soc_routes(app, core, require)
_host_identity = HostIdentitySensor()
core.store.save_host({**_host_identity.status(), 'last_seen': utc_now()})
app.state.sensor_manager = SensorManager({
    "lan": LANDiscoverySensor(core, host_id=_host_identity.identity.host_id),
    "endpoint_process": EndpointProcessSensor(core, host_id=_host_identity.identity.host_id),
    "socket_attribution": SocketAttributionSensor(host_id=_host_identity.identity.host_id, core=core),
})
app.state.reliability = ReliabilityService(core, app, app.state)
app.state.regression_guardian = BKRegressionGuardian(app.state.reliability)
core.ai.workers.append(app.state.regression_guardian)
install_reliability_routes(app, core, require, app.state.reliability, app.state.regression_guardian)
install_monthly_audit_routes(app, core, require, app.state.reliability)
install_ingestion_routes(app, core, require, lambda: deployment_context)
install_autonomy_routes(app, core, require)
@app.get('/health')
async def health():
    report = app.state.reliability.monitor.inspect(deep=False)
    payload = {
        'status': 'ok' if report.status == 'SAFE' else report.status.lower(),
        'product': 'BK Security',
        'version': os.getenv('BK_SECURITY_VERSION', '1.0.0'),
        'build_id': os.getenv('BK_SECURITY_BUILD_ID', 'development'),
        'capture_mode': effective_capture_mode(os.environ),
        'simulation_history_excluded': core.simulation_excluded_records,
        'integrity_score': report.score,
        'alerts': len(core.alerts), 'incidents': len(core.incidents),
    }
    if report.status != 'SAFE':
        return JSONResponse(status_code=503, content=payload)
    return payload

@app.post('/internal/shutdown', include_in_schema=False)
async def internal_shutdown(
    request: Request,
    x_bk_internal_shutdown: str = Header(default=''),
):
    expected = os.getenv('BK_SECURITY_INTERNAL_SHUTDOWN_TOKEN', '')
    client_ip = request.client.host if request.client else ''
    try:
        loopback = ipaddress.ip_address(client_ip).is_loopback
    except ValueError:
        loopback = False
    if not expected or not loopback or not hmac.compare_digest(x_bk_internal_shutdown, expected):
        raise HTTPException(status_code=403, detail='Shutdown request is not authorized.')
    request_shutdown = getattr(app.state, 'request_shutdown', None)
    if not callable(request_shutdown):
        raise HTTPException(status_code=503, detail='Backend shutdown is unavailable.')
    request_shutdown()
    return {'status': 'shutdown_requested'}
@app.post('/api/v1/auth/login')
async def login(body:Login, request:Request):
    client_ip = request.client.host if request.client else 'unknown'
    enforce_rate_limit(LOGIN_LIMITER, f'login:{client_ip}')
    expected=USERS.get(body.username)
    expected_password = expected[0] if expected else 'unknown-user-password-sentinel'
    matches = hmac.compare_digest(body.password.encode('utf-8'), expected_password.encode('utf-8'))
    if not expected or not matches: raise HTTPException(401,'Invalid credentials')
    LOGIN_LIMITER.reset(f'login:{client_ip}')
    token=issue_token(body.username, expected[1], deployment_context=deployment_context)
    session = verify_token(token, deployment_context=deployment_context)
    if session.token_id is None or session.expires_at is None:
        raise RuntimeError('Authentication token is missing its revocable session identity.')
    core.store.register_auth_session(session.token_id, body.username, session.expires_at)
    core.store.audit(body.username, 'login', session.token_id)
    return {'access_token':token,'token_type':'bearer','expires_in':3600,'role':expected[1]}

@app.post('/api/v1/auth/logout')
async def logout(p: Principal = Depends(principal)):
    revoked = bool(p.token_id and core.store.revoke_auth_session(p.token_id))
    if revoked:
        core.store.audit(p.username, 'logout', p.token_id)
    return {'status': 'logged_out', 'revoked': revoked}

@app.get('/api/v1/auth/sessions')
async def active_auth_sessions(p: Principal = Depends(require('admin'))):
    return {'sessions': core.store.list_active_auth_sessions()}

@app.post('/api/v1/auth/sessions/{username}/revoke')
async def revoke_user_auth_sessions(username: str, p: Principal = Depends(require('admin'))):
    if not username or len(username) > 128:
        raise HTTPException(422, 'Username must contain between 1 and 128 characters.')
    revoked = core.store.revoke_auth_sessions(username)
    core.store.audit(p.username, 'auth_sessions_revoked', username, {'sessions_revoked': revoked})
    return {'username': username, 'revoked_sessions': revoked}

@app.get('/api/v1/capture/capabilities')
async def capture_capabilities(p:Principal=Depends(principal)):
    capture_runtime = inspect_capture_runtime()
    return {
        'live_capture_available': LivePacketCapture.available(),
        'runtime': capture_runtime,
        'interfaces': [item.__dict__ if hasattr(item, '__dict__') else {
            'name': item.name, 'description': item.description, 'ipv4': item.ipv4, 'status': item.status,
        } for item in discover_interfaces()],
        'simulation_scenarios': [] if os.getenv('BK_SECURITY_ENV', '').strip().lower() == 'production'
        else [item.value for item in SimulationScenario],
        'status': network_sensor.status() if network_sensor else {
            'running': False,
            'mode': effective_capture_mode(os.environ),
            'interface': None,
            'capture_scope': 'endpoint',
            'accepted': 0,
            'rejected': 0,
            'dropped': 0,
        },
    }

@app.post('/api/v1/capture/start')
async def capture_start(p:Principal=Depends(require('admin','analyst')), body: CaptureStart | None = None):
    global network_sensor
    if network_sensor and network_sensor.running:
        return {'status':'already_running','sensor':network_sensor.status()}
    requested_mode = body.mode if body and body.mode else effective_capture_mode(os.environ)
    capture_scope = body.scope if body else 'endpoint'
    if capture_scope == 'mirror' and requested_mode != 'live':
        raise HTTPException(422, 'Mirrored-network scope requires live packet capture.')
    if requested_mode == 'simulation' and os.getenv('BK_SECURITY_ENV', '').strip().lower() == 'production':
        raise HTTPException(409, 'Simulation capture is disabled in production; select an authorized live interface.')
    interface = body.interface if body and body.interface else os.getenv('BK_SECURITY_CAPTURE_INTERFACE') or None
    scenario = body.scenario.value if body and body.scenario else None
    if requested_mode == 'stopped':
        raise HTTPException(409, 'Capture is stopped. Select an interface and explicitly start live capture.')
    if requested_mode == 'live' and not interface:
        raise HTTPException(422, 'Live capture requires an explicitly selected interface.')
    if scenario and requested_mode != 'simulation':
        raise HTTPException(422, 'Simulation scenarios require mode=simulation')
    network_sensor = NetworkSensor(core, host_id=_host_identity.identity.host_id,
                                  interface=interface,
                                  simulation=requested_mode=='simulation',
                                  max_events_per_second=int(os.getenv('BK_SECURITY_MAX_EVENTS_PER_SECOND','500')),
                                  scenario=scenario,
                                  capture_scope=capture_scope)
    try:
        network_sensor.start()
    except ValueError as exc:
        raise HTTPException(422, f'Invalid capture configuration: {exc}') from exc
    except Exception as exc:
        raise HTTPException(503, f'Capture unavailable: {exc}')
    return {'status':'started','sensor':network_sensor.status()}

@app.post('/api/v1/capture/stop')
async def capture_stop(p:Principal=Depends(require('admin','analyst'))):
    if network_sensor: network_sensor.stop()
    return {'status':'stopped','sensor':network_sensor.status() if network_sensor else {
        'running': False, 'mode': effective_capture_mode(os.environ),
        'interface': None, 'capture_scope': 'endpoint', 'accepted': 0, 'rejected': 0, 'dropped': 0,
    }}

@app.get('/api/v1/overview')
async def get_overview(p:Principal=Depends(principal)): return overview()
@app.get('/api/v1/alerts')
async def alerts(p:Principal=Depends(principal)): return {'alerts':[a.to_dict() for a in core.alerts[-200:]]}
@app.get('/api/v1/incidents')
async def incidents(p:Principal=Depends(principal)): return {'incidents':[item.to_dict() for item in reversed(core.incidents[-200:])]}
@app.patch('/api/v1/incidents/{incident_id}/status')
async def update_incident_status(incident_id: str, body: IncidentStatusUpdate,
                                 p:Principal=Depends(require('admin','analyst'))):
    try:
        return {'incident': core.transition_incident(incident_id, body.status, p.username)}
    except LookupError as exc:
        raise HTTPException(404, 'Incident not found') from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
@app.get('/api/v1/events')
async def events(p:Principal=Depends(principal), event_id: str | None = None):
    if event_id:
        event = core.store.get_event(event_id)
        if event is None:
            raise HTTPException(404, 'Event not found')
        return {'events': [event]}
    return {'events': [e.to_dict() for e in core.events[-200:]]}
@app.get('/api/v1/hosts')
async def hosts(p:Principal=Depends(principal)):
    out={str(item['host_id']):{**item,'events':0,'risk':0} for item in core.store.list_hosts(1000)}
    for e in core.events:
        item=out.setdefault(e.host_id,{'host_id':e.host_id,'events':0,'last_seen':e.timestamp,'risk':0})
        item['events']+=1; item['last_seen']=max(item['last_seen'],e.timestamp); item['risk']=max(item['risk'],e.risk_score)
    return {'hosts':list(out.values())}
@app.get('/api/v1/audit')
async def audit(p:Principal=Depends(require('admin','analyst','viewer','approver','responder'))):
    return {'audit':core.store.list_audit(200)}
@app.post('/api/v1/events')
async def ingest(body:EventIn,p:Principal=Depends(require('admin','analyst'))):
    enforce_rate_limit(EVENT_LIMITER, f'events:{p.username}')
    if os.getenv('BK_SECURITY_ENV', '').strip().lower() == 'production' and is_simulation_record({
        'source': body.source, 'tags': body.tags, 'data': body.data,
    }):
        raise HTTPException(422, 'Simulation-marked telemetry is not accepted in production.')
    event=SecurityEvent(event_type=body.event_type,source=body.source,host_id=body.host_id,severity=body.severity,data=body.data,tags=body.tags,process=body.process,network=body.network)
    alerts=core.ingest(event); core.store.audit(p.username,'ingest_event',event.event_id,{'event_type':event.event_type})
    return {'event':event.to_dict(),'alerts':[a.to_dict() for a in alerts],'overview':overview()}
@app.post('/api/v1/alerts/{alert_id}/investigate')
async def investigate(alert_id:str,p:Principal=Depends(require('admin','analyst','viewer'))):
    alert=next((a for a in core.alerts if a.alert_id==alert_id),None)
    if alert is None: raise HTTPException(404,'Alert not found')
    core.store.audit(p.username,'investigate',alert_id)
    related=[e for e in core.events if e.event_id in alert.source_event_ids or e.host_id == alert.host_id][-200:]
    intel=next((e.enrichment.get('threat_intel') for e in related if e.enrichment.get('threat_intel')), {})
    incident=next((i for i in core.incidents if alert_id in i.alert_ids),None)
    result=core.ai.investigate(InvestigationRequest(alert=alert,related_events=related,threat_context={'threat_intel':intel,'incident':incident.to_dict() if incident else None}))
    return result.to_dict()

@app.websocket('/ws/soc')
async def soc_ws(ws:WebSocket):
    token=ws.query_params.get('token')
    try:
        p=verify_token(token or '', deployment_context=deployment_context)
        if not _auth_session_allowed(p):
            raise AuthError('session revoked or not registered for this deployment')
    except AuthError: await ws.close(code=1008); return
    await ws.accept(); last=''
    try:
        while True:
            if not _auth_session_allowed(p):
                await ws.close(code=1008)
                return
            snapshot={
                'type':'soc.snapshot',
                'overview':overview(),
                'alerts':[a.to_dict() for a in core.alerts[-50:]],
                'incidents':[item.to_dict() for item in reversed(core.incidents[-50:])],
                'brain':build_network_topology(core.events, minutes=15),
            }
            import json
            sig=json.dumps(snapshot,sort_keys=True,default=str)
            if sig!=last: await ws.send_json(snapshot); last=sig
            await asyncio.sleep(1)
    except (WebSocketDisconnect,asyncio.CancelledError): pass

@app.websocket('/ws')
async def websocket(ws:WebSocket):
    await soc_ws(ws)


