from __future__ import annotations

import logging
import threading
from typing import Any


class PeriodicSensor:
    """Run a sensor snapshot immediately and refresh it on a bounded cadence."""

    def __init__(self, interval_seconds: float = 30.0) -> None:
        self.interval_seconds = max(1.0, min(3600.0, float(interval_seconds)))
        self.running = False
        self.last_error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lifecycle_lock = threading.Lock()
        self._first_snapshot_done = threading.Event()

    def start(self) -> Any:
        with self._lifecycle_lock:
            if self.running:
                return []
            self._stop.clear()
            self._first_snapshot_done.clear()
            self.last_error = None
            self.running = True
            self._thread = threading.Thread(
                target=self._run_periodically,
                name=f"bk-security-{type(self).__name__.lower()}",
                daemon=True,
            )
            self._thread.start()
            return []

    def _run_periodically(self) -> None:
        try:
            self.snapshot()
            self.last_error = None
        except Exception as exc:
            self.last_error = str(exc)[:512]
            logging.getLogger(__name__).warning(
                "Initial sensor snapshot failed (%s): %s", type(self).__name__, self.last_error,
            )
        finally:
            self._first_snapshot_done.set()
        while not self._stop.wait(self.interval_seconds):
            try:
                self.snapshot()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)[:512]
                logging.getLogger(__name__).warning(
                    "Periodic sensor snapshot failed (%s): %s", type(self).__name__, self.last_error,
                )

    def stop(self) -> None:
        with self._lifecycle_lock:
            self._stop.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)
        with self._lifecycle_lock:
            self.running = thread is not None and thread.is_alive()
            if not self.running:
                self._thread = None

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "initializing": self.running and not self._first_snapshot_done.is_set(),
            "interval_seconds": self.interval_seconds,
            "last_error": self.last_error,
        }

    def snapshot(self) -> list[Any]:
        raise NotImplementedError
