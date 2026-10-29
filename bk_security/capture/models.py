from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any
import time

@dataclass(slots=True)
class PacketObservation:
    src_ip: str
    dst_ip: str
    protocol: str
    size: int
    src_port: int | None = None
    dst_port: int | None = None
    direction: str = 'unknown'
    interface: str | None = None
    timestamp: float = 0.0
    pid: int | None = None
    process_name: str | None = None
    flags: str | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self):
        return asdict(self)
