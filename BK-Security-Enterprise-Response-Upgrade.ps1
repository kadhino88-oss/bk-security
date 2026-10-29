$ErrorActionPreference = 'Stop'
$Root = Join-Path $env:USERPROFILE 'BK-Security'
$Target = Join-Path $Root 'bk_security\policy\windows_adapters.py'
$Core = Join-Path $Root 'bk_security\core.py'
$BackupDir = Join-Path $Root ('backup-enterprise-response-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

if (-not (Test-Path $Root)) { throw "BK-Security introuvable: $Root" }
if (-not (Test-Path $Core)) { throw "core.py introuvable: $Core" }

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
Copy-Item $Core (Join-Path $BackupDir 'core.py') -Force

$adapter = @'
from __future__ import annotations
import ipaddress, os, re, subprocess
from dataclasses import dataclass
from typing import Any
from .engine import Action

class WindowsResponseError(RuntimeError):
    pass

_PREFIX = 'BK-Security-'
_NAME_RE = re.compile(r'[^A-Za-z0-9_.:-]+')

def _safe_rule_name(target: str) -> str:
    value = _NAME_RE.sub('-', str(target).strip()).strip('-')[:100] or 'target'
    return f'{_PREFIX}{value}'

def _validate_ip(target: str) -> str:
    value = str(target).strip()
    try: ipaddress.ip_address(value)
    except ValueError as exc: raise WindowsResponseError('BLOCK target must be a valid IP address') from exc
    return value

def _validate_pid(target: str) -> int:
    try: pid = int(str(target).strip())
    except ValueError as exc: raise WindowsResponseError('TERMINATE_PROCESS target must be a PID') from exc
    if pid <= 0: raise WindowsResponseError('TERMINATE_PROCESS target PID must be positive')
    return pid

def _run_ps(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    if os.name != 'nt': raise WindowsResponseError('Windows response adapters require Windows')
    command = ['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script,'--',*[str(x) for x in args]]
    try: return subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc: raise WindowsResponseError(str(exc)) from exc

@dataclass(slots=True)
class WindowsFirewallBlockAdapter:
    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.BLOCK: raise WindowsResponseError('Firewall adapter only supports BLOCK')
        ip = _validate_ip(target); rule = _safe_rule_name(ip)
        script = ("$ErrorActionPreference='Stop';$n=$args[0];$r=$args[1];"
                  "if(-not(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)){"
                  "New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block -RemoteAddress $r -Profile Any|Out-Null};"
                  "Get-NetFirewallRule -DisplayName $n|Select-Object -First 1 -ExpandProperty DisplayName")
        result = _run_ps(script, rule, ip)
        if result.returncode != 0: raise WindowsResponseError(result.stderr.strip() or 'Firewall rule creation failed')
        return {'adapter':'windows_firewall','rule':rule,'target':ip,'reason':reason}
    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        rule = str(execution.get('result',{}).get('rule') or '')
        if not rule.startswith(_PREFIX): raise WindowsResponseError('Refusing to remove a non-BK Security rule')
        result = _run_ps("$ErrorActionPreference='Stop';Remove-NetFirewallRule -DisplayName $args[0] -ErrorAction SilentlyContinue", rule)
        if result.returncode != 0: raise WindowsResponseError(result.stderr.strip() or 'Firewall rollback failed')
        return {'adapter':'windows_firewall','rule':rule,'removed':True}

@dataclass(slots=True)
class WindowsProcessTerminateAdapter:
    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.TERMINATE_PROCESS: raise WindowsResponseError('Process adapter only supports TERMINATE_PROCESS')
        pid = _validate_pid(target)
        script = ("$ErrorActionPreference='Stop';$p=Get-Process -Id ([int]$args[0]) -ErrorAction Stop;"
                  "$n=$p.ProcessName;Stop-Process -Id $p.Id -Force -ErrorAction Stop;"
                  "[pscustomobject]@{pid=$p.Id;process=$n}|ConvertTo-Json -Compress")
        result = _run_ps(script, str(pid))
        if result.returncode != 0: raise WindowsResponseError(result.stderr.strip() or 'Process termination failed')
        return {'adapter':'windows_process','pid':pid,'reason':reason,'output':result.stdout.strip()}
    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        return {'adapter':'windows_process','reversible':False}

@dataclass(slots=True)
class WindowsIsolationAdapter:
    rule_name: str = 'BK-Security-Isolation'
    def execute(self, target: str, action: Action, reason: str) -> dict[str, Any]:
        if action is not Action.ISOLATE: raise WindowsResponseError('Isolation adapter only supports ISOLATE')
        script = ("$ErrorActionPreference='Stop';$n=$args[0];"
                  "if(-not(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)){"
                  "New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block -RemoteAddress '0.0.0.0/0','::/0' -Profile Any|Out-Null};"
                  "Get-NetFirewallRule -DisplayName $n|Select-Object -First 1 -ExpandProperty DisplayName")
        result = _run_ps(script, self.rule_name)
        if result.returncode != 0: raise WindowsResponseError(result.stderr.strip() or 'Isolation rule creation failed')
        return {'adapter':'windows_isolation','rule':self.rule_name,'target':target,'reason':reason}
    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        rule = str(execution.get('result',{}).get('rule') or self.rule_name)
        if rule != self.rule_name: raise WindowsResponseError('Refusing to remove an unknown isolation rule')
        result = _run_ps("$ErrorActionPreference='Stop';Remove-NetFirewallRule -DisplayName $args[0] -ErrorAction SilentlyContinue", rule)
        if result.returncode != 0: raise WindowsResponseError(result.stderr.strip() or 'Isolation rollback failed')
        return {'adapter':'windows_isolation','rule':rule,'removed':True}

def build_windows_adapters() -> dict[Action, object]:
    return {Action.BLOCK:WindowsFirewallBlockAdapter(),Action.ISOLATE:WindowsIsolationAdapter(),Action.TERMINATE_PROCESS:WindowsProcessTerminateAdapter()}
'@

Set-Content -Path $Target -Value $adapter -Encoding UTF8

$coreText = Get-Content $Core -Raw
if ($coreText -notmatch 'windows_adapters') {
    $coreText = $coreText.Replace('from .policy.response import ResponseEngine', "from .policy.response import ResponseEngine`r`nfrom .policy.windows_adapters import build_windows_adapters")
}
$coreText = $coreText.Replace('self.correlation = CorrelationEngine(); self.policy = ResponsePolicy(); self.response = ResponseEngine()', "self.correlation = CorrelationEngine(); self.policy = ResponsePolicy(); self.response = ResponseEngine(adapters=build_windows_adapters() if os.name == 'nt' and os.getenv('BK_SECURITY_WINDOWS_RESPONSE', '0') == '1' else {})")
Set-Content -Path $Core -Value $coreText -Encoding UTF8

python -m py_compile $Target, $Core
Write-Host "BK Security Enterprise Response foundation integree." -ForegroundColor Green
Write-Host "Backup : $BackupDir"
Write-Host "Mode production protege : BK_SECURITY_WINDOWS_RESPONSE=1"
Write-Host "Aucune action destructive n'est activee automatiquement par ce patch."
