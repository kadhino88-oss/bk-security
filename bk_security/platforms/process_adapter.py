"""Cross-platform process termination adapter (psutil). Irreversible, so never part of automatic containment."""
from __future__ import annotations

import os
from typing import Any

from ..policy.engine import Action
from ..policy.response import validate_target
from .adapter_support import ResponseAdapterError

PROTECTED_NAMES = frozenset({
    "init", "systemd", "kthreadd", "launchd", "kernel_task", "loginwindow", "windowserver",
    "sshd", "dbus-daemon", "networkmanager", "configd",
})


class ProcessTerminateAdapter:
    def __init__(self, psutil_module: Any = None, grace_seconds: float = 3.0) -> None:
        self._psutil = psutil_module
        self.grace_seconds = grace_seconds

    def _ps(self):
        if self._psutil is None:
            import psutil
            self._psutil = psutil
        return self._psutil

    @staticmethod
    def _pid(target: str) -> int:
        try:
            return int(validate_target(Action.TERMINATE_PROCESS, target), 10)
        except ValueError as exc:
            raise ResponseAdapterError(str(exc)) from exc

    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.TERMINATE_PROCESS:
            raise ResponseAdapterError("Process adapter only supports TERMINATE_PROCESS.")
        pid = self._pid(target)
        if pid in {1, os.getpid(), os.getppid()}:
            raise ResponseAdapterError("Refusing to terminate init, the BK Security process or its parent.")
        ps = self._ps()
        try:
            process = ps.Process(pid)
            name = process.name()
            if name.casefold().removesuffix(".exe") in PROTECTED_NAMES:
                raise ResponseAdapterError("Refusing to terminate a protected system process.")
            process.terminate()
            try:
                process.wait(self.grace_seconds)
            except ps.TimeoutExpired:
                process.kill()
                process.wait(self.grace_seconds)
        except ps.NoSuchProcess as exc:
            raise ResponseAdapterError("Process no longer exists.") from exc
        except ps.AccessDenied as exc:
            raise ResponseAdapterError("Access denied while terminating the process.") from exc
        except ps.TimeoutExpired as exc:
            raise ResponseAdapterError("Process did not exit after SIGKILL.") from exc
        return {"adapter": "posix_process", "pid": pid, "process": name, "reason": reason, "reversible": False}

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        ps = self._ps()
        pid = self._pid(target)
        try:
            alive = ps.Process(pid).status() != ps.STATUS_ZOMBIE
        except ps.NoSuchProcess:
            alive = False
        observed = "present" if alive else "absent"
        return {"verified": observed == "absent", "observed": observed, "expected": "absent"}

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        return {"adapter": "posix_process", "reversible": False,
                "reason": "A terminated process cannot be restored by BK Security."}

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        return {"verified": False, "reason": "TERMINATE_PROCESS is not reversible."}
