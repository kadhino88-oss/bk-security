from __future__ import annotations
from .models import PacketObservation

class SimulationCapture:
    """Deterministic packet source for tests, demos and UI development."""
    def __init__(self, callback, packets=None): self.callback=callback; self.packets=packets or []; self.running=False
    def start(self):
        self.running=True
        for packet in self.packets:
            if not self.running: break
            self.callback(packet)
    def stop(self): self.running=False
