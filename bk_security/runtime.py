"""Runtime lifecycle helpers for BK Security desktop/backend deployments."""
from __future__ import annotations
import signal
import threading
from dataclasses import dataclass, field

@dataclass
class RuntimeLifecycle:
    """Coordinates a single clean shutdown path for desktop/backend deployments."""
    _stop_event: threading.Event = field(default_factory=threading.Event)
    _installed: bool = False

    def install_signal_handlers(self) -> None:
        if self._installed:
            return
        def _handler(signum, _frame):
            self._stop_event.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
            except (ValueError, RuntimeError):
                pass
        self._installed = True

    def request_stop(self) -> None:
        self._stop_event.set()

    @property
    def stopping(self) -> bool:
        return self._stop_event.is_set()
