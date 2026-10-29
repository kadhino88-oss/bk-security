from __future__ import annotations

from inspect import Parameter, signature
from typing import Any, Callable

from bk_security.events.adapters import device_to_event, media_to_event, packet_to_event


class SecuritySensorBridge:
    """Connect independent sensor callbacks to the BK Security event pipeline."""

    def __init__(self, core: Any, host_id: str = "local-host") -> None:
        self.core = core
        self.host_id = host_id
        self.running = False
        self._components: list[tuple[Any, Callable[[Any], Any]]] = []
        self._started_components: list[Any] = []

    def attach(self, *, packet_sensor=None, device_sensor=None, media_sensor=None):
        if self.running:
            raise RuntimeError("Stop the sensor bridge before changing attached sensors.")
        self._components = [
            (sensor, callback)
            for sensor, callback in (
                (packet_sensor, self.ingest_packet),
                (device_sensor, self.ingest_device),
                (media_sensor, self.ingest_media),
            )
            if sensor is not None
        ]
        return self

    def ingest_packet(self, observation: Any):
        return self.core.ingest(packet_to_event(observation, self.host_id))

    def ingest_device(self, observation: Any):
        return self.core.ingest(device_to_event(observation, self.host_id))

    def ingest_media(self, observation: Any):
        return self.core.ingest(media_to_event(observation, self.host_id))

    @staticmethod
    def _accepts_callback(start: Callable[..., Any]) -> bool:
        try:
            params = signature(start).parameters.values()
        except (TypeError, ValueError):
            return True
        return any(
            p.name == "callback" or p.kind is Parameter.VAR_KEYWORD
            for p in params
        )

    def start(self) -> None:
        if self.running:
            return
        started: list[Any] = []
        try:
            for component, callback in self._components:
                start = getattr(component, "start", None)
                if not callable(start):
                    continue
                # Include the component before start: a failing start may have
                # partially acquired resources that still need to be released.
                started.append(component)
                if self._accepts_callback(start):
                    start(callback=callback)
                else:
                    start()
        except Exception:
            for component in reversed(started):
                stop = getattr(component, "stop", None)
                if callable(stop):
                    try:
                        stop()
                    except Exception:
                        pass
            raise
        self._started_components = started
        self.running = True

    def stop(self) -> None:
        failures: list[Exception] = []
        for component in reversed(self._started_components):
            stop = getattr(component, "stop", None)
            if callable(stop):
                try:
                    stop()
                except Exception as exc:
                    failures.append(exc)
        self.running = False
        self._started_components = []
        if failures:
            raise RuntimeError(f"{len(failures)} sensor component(s) failed to stop") from failures[0]
