from __future__ import annotations
from ..capture.live import LivePacketCapture
from ..capture.models import PacketObservation
from ..capture.pipeline import PacketPipeline
from ..capture.scenarios import SimulationScenario, generate_scenario
from ..platforms import discover_interfaces

class NetworkSensor:
    def __init__(self, core, host_id='local-host', interface=None, simulation=False, max_events_per_second=500, scenario=None, capture_scope='endpoint'):
        self.core=core; self.host_id=host_id; self.interface=interface; self.simulation=simulation
        if capture_scope not in {'endpoint', 'mirror'}:
            raise ValueError('Capture scope must be endpoint or mirror.')
        if simulation and capture_scope != 'endpoint':
            raise ValueError('Mirrored-network scope requires live packet capture.')
        self.capture_scope=capture_scope
        self.scenario = str(scenario).upper() if scenario else None
        self.pipeline=PacketPipeline(host_id, callback=core.ingest, max_events_per_second=max_events_per_second,
                                     capture_scope=capture_scope)
        self.capture=None; self.running=False
    def start(self):
        if self.running: return
        temporary_ioc = None
        if self.simulation:
            from ..capture.simulation import SimulationCapture
            if self.scenario:
                try:
                    scenario = SimulationScenario(self.scenario)
                except ValueError as exc:
                    raise ValueError(f'Unsupported simulation scenario: {self.scenario}') from exc
                observations = generate_scenario(scenario.value, self.host_id, self.interface)
                if scenario == SimulationScenario.IOC_MATCH:
                    temporary_ioc = '198.51.100.133'
                    self.core.threat_intel.add_ip(temporary_ioc, confidence=.99, tags=['simulation'], source='BK simulation')
                def dispatch(item):
                    if isinstance(item, PacketObservation):
                        self.pipeline.observe(item)
                    else:
                        self.core.ingest(item)
                self.capture=SimulationCapture(dispatch, observations)
            else:
                packets = [PacketObservation(
                    src_ip='192.0.2.10', dst_ip='203.0.113.66', protocol='TCP', size=74,
                    src_port=51514, dst_port=4444, direction='local->remote',
                    interface=self.interface, process_name='powershell.exe', flags='S',
                    metadata={'simulation': True},
                )]
                self.capture=SimulationCapture(lambda p:self.pipeline.observe(p), packets)
        else:
            local_ips={i.ipv4 for i in discover_interfaces() if i.ipv4}
            self.capture=LivePacketCapture(lambda p:self.pipeline.observe(p), self.interface, local_ips)
        try:
            self.capture.start()
        finally:
            if temporary_ioc:
                self.core.threat_intel.ip_iocs.pop(temporary_ioc, None)
                self.core.threat_intel._networks = [
                    (network, match) for network, match in self.core.threat_intel._networks
                    if match.indicator != temporary_ioc
                ]
        self.running=True
    def stop(self):
        if self.capture: self.capture.stop()
        self.running=False
    def status(self):
        return {'running':self.running,'mode':'simulation' if self.simulation else 'live','interface':self.interface,
                'scenario': self.scenario, 'capture_scope': self.capture_scope,
                'accepted':self.pipeline.accepted,'rejected':self.pipeline.rejected,'dropped':self.pipeline.aggregator.dropped,
                'writer':self.core.store.writer_status}
