"""macOS response adapters built on pf anchors/tables. UNVALIDATED on a real host: lab validation is still required.

pf only enforces anchor rules when pf is enabled and the main ruleset references the anchor. BK Security does not edit
/etc/pf.conf; verification reports `anchor_not_active` instead of claiming a block that is not enforced.
"""
from __future__ import annotations

import socket
from typing import Any

from ..policy.engine import Action
from .adapter_support import ResponseAdapterError, Runner, require_success, run_command, validated_ip, verdict

ANCHOR = "bk-security"
ISOLATION_ANCHOR = "bk-security-isolation"
TABLE = "bk_blocked"


class PfBlockAdapter:
    def __init__(self, runner: Runner = run_command) -> None:
        self.run = runner

    def _members(self) -> set[str]:
        result = self.run(["pfctl", "-a", ANCHOR, "-t", TABLE, "-T", "show"], None)
        if result.returncode != 0:
            return set()
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}

    def _enforced(self, anchor: str) -> bool:
        enabled = self.run(["pfctl", "-s", "info"], None)
        rules = self.run(["pfctl", "-s", "rules"], None)
        return (enabled.returncode == 0 and "Status: Enabled" in enabled.stdout
                and rules.returncode == 0 and f'anchor "{anchor}"' in rules.stdout)

    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.BLOCK:
            raise ResponseAdapterError("pf adapter only supports BLOCK.")
        ip = validated_ip(target)
        loaded = self.run(["pfctl", "-a", ANCHOR, "-s", "rules"], None)
        if loaded.returncode != 0 or f"<{TABLE}>" not in loaded.stdout:
            rules = f"table <{TABLE}> persist\nblock drop out quick to <{TABLE}>\n"
            require_success(self.run(["pfctl", "-a", ANCHOR, "-f", "-"], rules), "pf anchor load failed.")
        require_success(self.run(["pfctl", "-a", ANCHOR, "-t", TABLE, "-T", "add", ip], None), "pf table add failed.")
        return {"adapter": "macos_pf", "anchor": ANCHOR, "table": TABLE, "target": ip, "reason": reason,
                "reversible": True}

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        ip = validated_ip(target)
        if ip not in self._members():
            return verdict("absent", "present")
        if not self._enforced(ANCHOR):
            return verdict("anchor_not_active", "present")
        return verdict("present", "present")

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        result = execution.get("result", {})
        if result.get("anchor") != ANCHOR or result.get("table") != TABLE:
            raise ResponseAdapterError("Refusing to modify an unknown pf table.")
        ip = validated_ip(str(result.get("target") or ""))
        require_success(self.run(["pfctl", "-a", ANCHOR, "-t", TABLE, "-T", "delete", ip], None),
                        "pf table removal failed.")
        return {"adapter": "macos_pf", "anchor": ANCHOR, "table": TABLE, "target": ip, "removed": True,
                "reversible": True}

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        ip = validated_ip(str(result.get("target") or ""))
        return verdict("absent" if ip not in self._members() else "present", "absent")


class PfIsolationAdapter:
    def __init__(self, runner: Runner = run_command) -> None:
        self.run = runner

    def _loaded(self) -> bool:
        result = self.run(["pfctl", "-a", ISOLATION_ANCHOR, "-s", "rules"], None)
        return result.returncode == 0 and "block" in result.stdout and "lo0" in result.stdout

    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.ISOLATE:
            raise ResponseAdapterError("Isolation adapter only supports ISOLATE.")
        if str(target).casefold() not in {"local", socket.gethostname().casefold()}:
            raise ResponseAdapterError("ISOLATE can only target this local host.")
        require_success(self.run(["pfctl", "-a", ISOLATION_ANCHOR, "-f", "-"],
                                 "block drop out quick on ! lo0 all\n"), "Isolation rule load failed.")
        return {"adapter": "macos_isolation", "anchor": ISOLATION_ANCHOR, "target": target, "reason": reason,
                "reversible": True}

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        if not self._loaded():
            return verdict("absent", "present")
        enabled = self.run(["pfctl", "-s", "info"], None)
        rules = self.run(["pfctl", "-s", "rules"], None)
        active = ("Status: Enabled" in enabled.stdout and f'anchor "{ISOLATION_ANCHOR}"' in rules.stdout)
        return verdict("present" if active else "anchor_not_active", "present")

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        if execution.get("result", {}).get("anchor") != ISOLATION_ANCHOR:
            raise ResponseAdapterError("Refusing to flush an unknown pf anchor.")
        require_success(self.run(["pfctl", "-a", ISOLATION_ANCHOR, "-F", "rules"], None), "Isolation rollback failed.")
        return {"adapter": "macos_isolation", "anchor": ISOLATION_ANCHOR, "removed": True, "reversible": True}

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        return verdict("absent" if not self._loaded() else "present", "absent")
