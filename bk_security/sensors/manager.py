from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass
class SensorState:
    name: str
    status: str = "stopped"
    error: str | None = None

class SensorManager:
    def __init__(self, sensors=None):
        self.sensors = sensors or {}
        self.states = {n: SensorState(n) for n in self.sensors}
    def start(self, name: str):
        sensor=self.sensors[name]
        self.states[name].status="starting"; self.states[name].error=None
        try:
            sensor.start(); self.states[name].status="running"
        except Exception as exc:
            self.states[name].status="error"; self.states[name].error=str(exc)
    def stop(self, name: str):
        sensor=self.sensors[name]
        try:
            sensor.stop(); self.states[name].status="stopped"
        except Exception as exc:
            self.states[name].status="error"; self.states[name].error=str(exc)
    def start_all(self):
        for name in self.sensors: self.start(name)
    def stop_all(self):
        for name in list(self.sensors): self.stop(name)
    def status(self) -> dict[str, Any]:
        sensors = {}
        for name, state in self.states.items():
            detail = {}
            status_method = getattr(self.sensors.get(name), "status", None)
            if callable(status_method):
                try:
                    detail = status_method()
                except Exception as exc:
                    detail = {"status_error": str(exc)[:256]}
            sensors[name] = {**vars(state), **detail}
        return {"sensors": sensors, "running": sum(s.status == "running" for s in self.states.values())}
