from __future__ import annotations
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import threading, time
from typing import Callable
from .models import PacketObservation
from ..events.models import SecurityEvent

@dataclass(slots=True)
class FlowAggregate:
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

class TrafficAggregator:
    """Bounds high-volume repetitive traffic before it reaches the SOC event bus."""
    def __init__(self, window_seconds: float = 1.0, max_events_per_window: int = 500, max_flows: int = 20_000):
        self.window_seconds = max(0.1, float(window_seconds))
        self.max_events_per_window = max(1, int(max_events_per_window))
        self.max_flows = max(1, int(max_flows))
        self._seen = deque()
        self._flows: OrderedDict[tuple, FlowAggregate] = OrderedDict()
        self._lock = threading.Lock()
        self.dropped = 0

    def accept(self, observation: PacketObservation) -> bool:
        now = observation.timestamp or time.time()
        with self._lock:
            while self._seen and now - self._seen[0] > self.window_seconds:
                self._seen.popleft()
            if len(self._seen) >= self.max_events_per_window:
                self.dropped += 1
                return False
            self._seen.append(now)
            key=(observation.src_ip, observation.dst_ip, observation.src_port, observation.dst_port, observation.protocol)
            flow = self._flows.pop(key, None)
            if flow is None:
                flow = FlowAggregate()
            if not flow.first_seen: flow.first_seen=now
            flow.last_seen=now; flow.packets += 1; flow.bytes += max(0, observation.size)
            self._flows[key] = flow
            while len(self._flows) > self.max_flows:
                self._flows.popitem(last=False)
            return True

    def snapshot(self):
        with self._lock:
            return {str(k): {'packets':v.packets,'bytes':v.bytes,'first_seen':v.first_seen,'last_seen':v.last_seen} for k,v in self._flows.items()}

class PacketPipeline:
    def __init__(self, host_id='local-host', callback: Callable[[SecurityEvent], object] | None=None,
                 max_events_per_second=500, max_tracked_flows=20_000, capture_scope='endpoint'):
        if capture_scope not in {'endpoint', 'mirror'}:
            raise ValueError('Capture scope must be endpoint or mirror.')
        self.host_id=host_id; self.callback=callback
        self.capture_scope=capture_scope
        self.aggregator=TrafficAggregator(1.0, max_events_per_second, max_tracked_flows)
        self.accepted=0; self.rejected=0

    def observe(self, packet: PacketObservation):
        if not self.aggregator.accept(packet):
            self.rejected += 1
            return None
        self.accepted += 1
        event_host_id = self.host_id
        scope_data = {}
        scope_network = {}
        event_tags = []
        if self.capture_scope == 'mirror':
            source_ip = str(packet.src_ip or '').strip()
            if source_ip:
                event_host_id = f'network-ip:{source_ip}'
                scope_data = {
                    'capture_scope': 'mirror',
                    'sensor_host_id': self.host_id,
                    'observed_source_ip': source_ip,
                }
                scope_network = {'capture_scope': 'mirror', 'sensor_host_id': self.host_id}
                event_tags = ['network', 'mirrored']
        event=SecurityEvent(
            event_type='network.packet', source='bk_network_capture', host_id=event_host_id,
            timestamp=datetime.fromtimestamp(packet.timestamp, timezone.utc).isoformat(),
            data={
                'src_ip':packet.src_ip,'dst_ip':packet.dst_ip,'src_port':packet.src_port,
                'dst_port':packet.dst_port,'protocol':packet.protocol,'size':packet.size,
                'direction':packet.direction,'interface':packet.interface,'pid':packet.pid,
                'process_name':packet.process_name,'flags':packet.flags,**(packet.metadata or {}),**scope_data
            },
            network={'src_ip':packet.src_ip,'dst_ip':packet.dst_ip,'src_port':packet.src_port,
                     'dst_port':packet.dst_port,'protocol':packet.protocol,'direction':packet.direction,
                     'bytes':packet.size,'interface':packet.interface,**scope_network},
            process={'pid':packet.pid,'name':packet.process_name} if packet.pid or packet.process_name else {},
            tags=event_tags,
        )
        if self.callback:
            self.callback(event)
            dns = (packet.metadata or {}).get("dns")
            if isinstance(dns, dict) and dns.get("domain"):
                dns_event = SecurityEvent(
                    event_type="network.dns",
                    source="bk_dns_packet_sensor",
                    host_id=self.host_id,
                    timestamp=datetime.fromtimestamp(packet.timestamp, timezone.utc).isoformat(),
                    data={
                        "domain": str(dns["domain"]).lower().rstrip("."),
                        "qtype": str(dns.get("qtype") or "A").upper(),
                        "answers": [str(answer) for answer in dns.get("answers", []) if answer],
                        "response": bool(dns.get("response", False)),
                        "transaction_id": dns.get("transaction_id"),
                        "direction": packet.direction,
                    },
                    network={
                        "src_ip": packet.src_ip,
                        "dst_ip": packet.dst_ip,
                        "src_port": packet.src_port,
                        "dst_port": packet.dst_port,
                        "protocol": packet.protocol,
                    },
                    process={"pid": packet.pid, "name": packet.process_name} if packet.pid or packet.process_name else {},
                    tags=["dns", "passive"],
                )
                self.callback(dns_event)
        return event
