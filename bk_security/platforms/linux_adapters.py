"""Linux response adapters built on nftables sets. UNVALIDATED on a real host: lab validation is still required.

Blocks live in a dedicated BK Security table, so rollback never touches foreign rules. Commands are argv lists;
generated rule text only ever embeds a validated IP address and fixed names.
"""
from __future__ import annotations

import json
import socket
from typing import Any

from ..policy.engine import Action
from .adapter_support import ResponseAdapterError, Runner, require_success, run_command, validated_ip, verdict

TABLE = "bk_security"
ISOLATION_TABLE = "bk_security_isolation"
_SETS = {4: ("blocked4", "ipv4_addr", "ip"), 6: ("blocked6", "ipv6_addr", "ip6")}
_HOOK = "type filter hook output priority 0; policy accept;"


def _set_for(ip: str) -> tuple[str, str, str]:
    return _SETS[6 if ":" in ip else 4]


def _flatten(elements: Any) -> set[str]:
    found: set[str] = set()
    for item in elements or []:
        if isinstance(item, str):
            found.add(item)
        elif isinstance(item, dict):
            found |= _flatten([item.get("elem", {}).get("val")] if "elem" in item else [])
    return found


class NftBlockAdapter:
    def __init__(self, runner: Runner = run_command) -> None:
        self.run = runner

    def _members(self, set_name: str) -> set[str] | None:
        result = self.run(["nft", "-j", "list", "set", "inet", TABLE, set_name], None)
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result.stdout or "{}")
        except ValueError as exc:
            raise ResponseAdapterError("nft returned unreadable JSON.") from exc
        members: set[str] = set()
        for entry in payload.get("nftables", []):
            if "set" in entry:
                members |= _flatten(entry["set"].get("elem"))
        return members

    def _rules_present(self) -> bool:
        result = self.run(["nft", "list", "chain", "inet", TABLE, "output"], None)
        return result.returncode == 0 and "@blocked4" in result.stdout and "@blocked6" in result.stdout

    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.BLOCK:
            raise ResponseAdapterError("nftables adapter only supports BLOCK.")
        ip = validated_ip(target)
        set_name, set_type, family = _set_for(ip)
        ensure = (
            f"add table inet {TABLE}\n"
            f"add chain inet {TABLE} output {{ {_HOOK} }}\n"
            f"add set inet {TABLE} blocked4 {{ type ipv4_addr; }}\n"
            f"add set inet {TABLE} blocked6 {{ type ipv6_addr; }}\n"
        )
        require_success(self.run(["nft", "-f", "-"], ensure), "nftables table setup failed.")
        if not self._rules_present():
            rules = (f"add rule inet {TABLE} output ip daddr @blocked4 drop\n"
                     f"add rule inet {TABLE} output ip6 daddr @blocked6 drop\n")
            require_success(self.run(["nft", "-f", "-"], rules), "nftables rule setup failed.")
        require_success(self.run(["nft", "-f", "-"], f"add element inet {TABLE} {set_name} {{ {ip} }}\n"),
                        "nftables element insertion failed.")
        return {"adapter": "linux_nftables", "set": set_name, "target": ip, "reason": reason, "reversible": True}

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        ip = validated_ip(target)
        members = self._members(_set_for(ip)[0])
        enforced = self._rules_present()
        observed = "present" if members is not None and ip in members and enforced else "absent"
        return verdict(observed, "present", rule_active=enforced)

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        result = execution.get("result", {})
        ip = validated_ip(str(result.get("target") or ""))
        set_name = _set_for(ip)[0]
        if result.get("set") != set_name:
            raise ResponseAdapterError("Refusing to remove an element from an unknown set.")
        members = self._members(set_name)
        if members is not None and ip in members:
            require_success(self.run(["nft", "-f", "-"], f"delete element inet {TABLE} {set_name} {{ {ip} }}\n"),
                            "nftables element removal failed.")
        return {"adapter": "linux_nftables", "set": set_name, "target": ip, "removed": True, "reversible": True}

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        ip = validated_ip(str(result.get("target") or ""))
        members = self._members(_set_for(ip)[0])
        return verdict("absent" if members is None or ip not in members else "present", "absent")


class NftIsolationAdapter:
    """Blocks all outbound traffic except loopback by owning a whole table, removed as one unit on rollback."""

    def __init__(self, runner: Runner = run_command) -> None:
        self.run = runner

    def _active(self) -> bool:
        result = self.run(["nft", "list", "chain", "inet", ISOLATION_TABLE, "output"], None)
        return result.returncode == 0 and "drop" in result.stdout

    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.ISOLATE:
            raise ResponseAdapterError("Isolation adapter only supports ISOLATE.")
        if str(target).casefold() not in {"local", socket.gethostname().casefold()}:
            raise ResponseAdapterError("ISOLATE can only target this local host.")
        script = (f"add table inet {ISOLATION_TABLE}\n"
                  f"add chain inet {ISOLATION_TABLE} output {{ {_HOOK} }}\n")
        require_success(self.run(["nft", "-f", "-"], script), "Isolation table setup failed.")
        if not self._active():
            require_success(self.run(["nft", "-f", "-"],
                                     f'add rule inet {ISOLATION_TABLE} output oifname != "lo" drop\n'),
                            "Isolation rule creation failed.")
        return {"adapter": "linux_isolation", "table": ISOLATION_TABLE, "target": target,
                "reason": reason, "reversible": True}

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        return verdict("present" if self._active() else "absent", "present")

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        if execution.get("result", {}).get("table") != ISOLATION_TABLE:
            raise ResponseAdapterError("Refusing to remove an unknown isolation table.")
        if self.run(["nft", "list", "table", "inet", ISOLATION_TABLE], None).returncode == 0:
            require_success(self.run(["nft", "delete", "table", "inet", ISOLATION_TABLE], None),
                            "Isolation rollback failed.")
        return {"adapter": "linux_isolation", "table": ISOLATION_TABLE, "removed": True, "reversible": True}

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        gone = self.run(["nft", "list", "table", "inet", ISOLATION_TABLE], None).returncode != 0
        return verdict("absent" if gone else "present", "absent")
