from __future__ import annotations
import socket
from dataclasses import dataclass, field
from typing import Callable
from ..events.models import SecurityEvent

@dataclass(slots=True)
class DNSObservation:
    domain: str
    qtype: str = "A"
    answers: list[str] = field(default_factory=list)

class DNSResolutionSensor:
    """Safe DNS telemetry sensor. It records explicitly supplied queries and optional local resolution."""
    def __init__(self, callback: Callable[[SecurityEvent], object] | None = None, host_id: str = "local-host"):
        self.callback, self.host_id, self.running = callback, host_id, False
    def observe(self, domain: str, qtype: str = "A", resolve: bool = False):
        answers=[]
        if resolve:
            try: answers=list({x[4][0] for x in socket.getaddrinfo(domain, None) if x[4]})
            except OSError: pass
        event=SecurityEvent(event_type="network.dns", source="bk_dns_sensor", host_id=self.host_id,
            data={"domain":domain.lower().rstrip('.'),"qtype":qtype,"answers":answers}, network={})
        if self.callback: self.callback(event)
        return event
    def start(self): self.running=True
    def stop(self): self.running=False
    def status(self): return {"running":self.running,"mode":"local-resolution"}
