from __future__ import annotations
import platform, socket, uuid
from dataclasses import dataclass, asdict

@dataclass(slots=True)
class HostIdentity:
    host_id: str
    hostname: str
    platform: str
    os_version: str
    machine: str
    boot_id: str

class HostIdentitySensor:
    def __init__(self, host_id: str | None = None):
        self.identity = self._collect(host_id)
        self.running = False
    def _collect(self, host_id: str | None):
        return HostIdentity(
            host_id=host_id or f"host-{uuid.getnode():012x}",
            hostname=socket.gethostname(),
            platform=platform.system(),
            os_version=platform.version(),
            machine=platform.machine(),
            boot_id=f"{uuid.getnode():012x}",
        )
    def start(self): self.running = True; return asdict(self.identity)
    def stop(self): self.running = False
    def status(self): return {"running": self.running, **asdict(self.identity)}
