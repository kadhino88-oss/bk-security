from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Any

from .engine import Action
from .response import validate_target


class WindowsResponseError(RuntimeError):
    pass


_PREFIX = "BK-Security-"
_NAME_RE = re.compile(r"[^A-Za-z0-9_.:-]+")


def _safe_rule_name(target: str) -> str:
    normalized = validate_target(Action.BLOCK, target)
    value = _NAME_RE.sub("-", normalized).strip("-")[:72] or "target"
    suffix = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    return f"{_PREFIX}{value}-{suffix}"


def _validate_ip(target: str) -> str:
    try:
        return str(ipaddress.ip_address(validate_target(Action.BLOCK, target)))
    except ValueError as exc:
        raise WindowsResponseError(str(exc)) from exc


def _validate_pid(target: str) -> int:
    try:
        return int(validate_target(Action.TERMINATE_PROCESS, target), 10)
    except ValueError as exc:
        raise WindowsResponseError(str(exc)) from exc


def _run_ps(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    if os.name != "nt":
        raise WindowsResponseError("Windows response adapters require Windows.")
    command = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-Command", script, "--", *[str(value) for value in args],
    ]
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WindowsResponseError(str(exc)) from exc


def _require_success(result: subprocess.CompletedProcess[str], message: str) -> None:
    if result.returncode != 0:
        raise WindowsResponseError(result.stderr.strip()[:1000] or message)


def _state(result: subprocess.CompletedProcess[str], expected: str) -> dict[str, Any]:
    _require_success(result, "Windows response verification failed.")
    observed = result.stdout.strip().lower()
    return {"verified": observed == expected, "observed": observed, "expected": expected}


@dataclass(slots=True)
class WindowsFirewallBlockAdapter:
    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.BLOCK:
            raise WindowsResponseError("Firewall adapter only supports BLOCK.")
        ip = _validate_ip(target)
        rule = _safe_rule_name(ip)
        script = (
            "$ErrorActionPreference='Stop';$n=$args[0];$r=$args[1];"
            "$rules=@(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue);"
            "if($rules.Count -gt 1){throw 'Duplicate BK Security firewall rules found'};"
            "if($rules.Count -eq 1){"
            "if($rules[0].Enabled -ne 'True' -or $rules[0].Action -ne 'Block' -or $rules[0].Direction -ne 'Outbound'){throw 'Existing rule has unexpected policy'};"
            "$f=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rules[0];"
            "if($f.RemoteAddress -notcontains $r){throw 'Existing rule has a different target'}"
            "}else{New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block "
            "-RemoteAddress $r -Profile Any|Out-Null};'present'"
        )
        result = _run_ps(script, rule, ip)
        _require_success(result, "Firewall rule creation failed.")
        return {"adapter": "windows_firewall", "rule": rule, "target": ip, "reason": reason, "reversible": True}

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        rule = result.get("rule") or _safe_rule_name(target)
        if not isinstance(rule, str) or not rule.startswith(_PREFIX):
            raise WindowsResponseError("Cannot verify an unknown BK Security firewall rule.")
        script = (
            "$ErrorActionPreference='Stop';$n=$args[0];$r=$args[1];"
            "$rules=@(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue);"
            "if($rules.Count -ne 1){'absent'}elseif($rules[0].Enabled -ne 'True' -or $rules[0].Action -ne 'Block' -or $rules[0].Direction -ne 'Outbound'){'mismatch'}else{"
            "$f=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rules[0];"
            "if($f.RemoteAddress -contains $r){'present'}else{'mismatch'}}"
        )
        return _state(_run_ps(script, rule, _validate_ip(target)), "present")

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        rule = str(execution.get("result", {}).get("rule") or "")
        if not rule.startswith(_PREFIX):
            raise WindowsResponseError("Refusing to remove a non-BK Security rule.")
        result = _run_ps(
            "$ErrorActionPreference='Stop';$n=$args[0];"
            "Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue|"
            "Remove-NetFirewallRule -ErrorAction Stop;'removed'", rule,
        )
        _require_success(result, "Firewall rollback failed.")
        return {"adapter": "windows_firewall", "rule": rule, "removed": True, "reversible": True}

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        rule = str(result.get("rule") or "")
        if not rule.startswith(_PREFIX):
            raise WindowsResponseError("Refusing to verify an unknown BK Security rule.")
        return _state(_run_ps(
            "$ErrorActionPreference='Stop';$n=$args[0];"
            "if(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue){'present'}else{'absent'}",
            rule,
        ), "absent")


@dataclass(slots=True)
class WindowsProcessTerminateAdapter:
    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.TERMINATE_PROCESS:
            raise WindowsResponseError("Process adapter only supports TERMINATE_PROCESS.")
        pid = _validate_pid(target)
        if pid == os.getpid():
            raise WindowsResponseError("Refusing to terminate the BK Security response process.")
        script = (
            "$ErrorActionPreference='Stop';$p=Get-Process -Id ([int]$args[0]) -ErrorAction Stop;"
            "if(@('Idle','System','Registry','smss','csrss','wininit','services','lsass') -contains $p.ProcessName){"
            "throw 'Refusing to terminate a protected Windows process'};"
            "$n=$p.ProcessName;Stop-Process -Id $p.Id -Force -ErrorAction Stop;"
            "[pscustomobject]@{pid=$p.Id;process=$n}|ConvertTo-Json -Compress"
        )
        result = _run_ps(script, str(pid))
        _require_success(result, "Process termination failed.")
        return {"adapter": "windows_process", "pid": pid, "reason": reason, "output": result.stdout.strip(),
                "reversible": False}

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        pid = _validate_pid(target)
        script = (
            "$ErrorActionPreference='Stop';$p=Get-Process -Id ([int]$args[0]) -ErrorAction SilentlyContinue;"
            "if($p){'present'}else{'absent'}"
        )
        return _state(_run_ps(script, str(pid)), "absent")

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        return {"adapter": "windows_process", "reversible": False,
                "reason": "A terminated process cannot be restored by BK Security."}

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        return {"verified": False, "reason": "TERMINATE_PROCESS is not reversible."}


@dataclass(slots=True)
class WindowsIsolationAdapter:
    rule_name: str = "BK-Security-Isolation"

    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.ISOLATE:
            raise WindowsResponseError("Isolation adapter only supports ISOLATE.")
        if not str(target).strip() or len(str(target)) > 256:
            raise WindowsResponseError("ISOLATE target must identify one bounded local host.")
        if str(target).casefold() not in {"local", socket.gethostname().casefold()}:
            raise WindowsResponseError("ISOLATE can only target this local Windows host.")
        script = (
            "$ErrorActionPreference='Stop';$n=$args[0];"
            "$rules=@(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue);"
            "if($rules.Count -gt 1){throw 'Duplicate isolation rules found'};"
            "if($rules.Count -eq 1){"
            "if($rules[0].Enabled -ne 'True' -or $rules[0].Action -ne 'Block' -or $rules[0].Direction -ne 'Outbound'){throw 'Existing isolation rule has unexpected policy'};"
            "$f=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rules[0];"
            "if(($f.RemoteAddress -notcontains '0.0.0.0/0') -or ($f.RemoteAddress -notcontains '::/0')){"
            "throw 'Existing isolation rule has unexpected scope'}"
            "}else{New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block "
            "-RemoteAddress '0.0.0.0/0','::/0' -Profile Any|Out-Null};'present'"
        )
        result = _run_ps(script, self.rule_name)
        _require_success(result, "Isolation rule creation failed.")
        return {"adapter": "windows_isolation", "rule": self.rule_name, "target": target,
                "reason": reason, "reversible": True}

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        if result.get("rule", self.rule_name) != self.rule_name:
            raise WindowsResponseError("Cannot verify an unknown isolation rule.")
        script = (
            "$ErrorActionPreference='Stop';$n=$args[0];"
            "$rules=@(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue);"
            "if($rules.Count -ne 1){'absent'}elseif($rules[0].Enabled -ne 'True' -or $rules[0].Action -ne 'Block' -or $rules[0].Direction -ne 'Outbound'){'mismatch'}else{"
            "$f=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rules[0];"
            "if(($f.RemoteAddress -contains '0.0.0.0/0') -and ($f.RemoteAddress -contains '::/0')){'present'}else{'mismatch'}}"
        )
        return _state(_run_ps(script, self.rule_name), "present")

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        rule = str(execution.get("result", {}).get("rule") or "")
        if rule != self.rule_name:
            raise WindowsResponseError("Refusing to remove an unknown isolation rule.")
        result = _run_ps(
            "$ErrorActionPreference='Stop';$n=$args[0];"
            "Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue|"
            "Remove-NetFirewallRule -ErrorAction Stop;'removed'", rule,
        )
        _require_success(result, "Isolation rollback failed.")
        return {"adapter": "windows_isolation", "rule": rule, "removed": True, "reversible": True}

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        rule = str(result.get("rule") or "")
        if rule != self.rule_name:
            raise WindowsResponseError("Refusing to verify an unknown isolation rule.")
        return _state(_run_ps(
            "$ErrorActionPreference='Stop';$n=$args[0];"
            "if(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue){'present'}else{'absent'}",
            rule,
        ), "absent")


def build_windows_adapters() -> dict[Action, object]:
    return {
        Action.BLOCK: WindowsFirewallBlockAdapter(),
        Action.ISOLATE: WindowsIsolationAdapter(),
        Action.TERMINATE_PROCESS: WindowsProcessTerminateAdapter(),
    }
