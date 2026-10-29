$ErrorActionPreference = 'Stop'
$Root = Join-Path $env:USERPROFILE 'BK-Security'
$Core = Join-Path $Root 'bk_security\core.py'

if (-not (Test-Path $Core)) { throw "core.py introuvable: $Core" }

$BackupDir = Join-Path $Root ('backup-enterprise-decision-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
Copy-Item $Core (Join-Path $BackupDir 'core.py') -Force

$text = Get-Content $Core -Raw

# Enterprise decision imports/state.
if ($text -notmatch 'from collections import OrderedDict, defaultdict') {
    throw 'Structure core.py inattendue: imports introuvables.'
}
if ($text -notmatch 'import hashlib') {
    $text = $text -replace 'import threading', "import threading`r`nimport hashlib"
}

# Add bounded alert fingerprint state after _dns_context initialization.
$anchor = 'self._dns_context: OrderedDict[str, dict[str, tuple[str, float, str]]] = OrderedDict()'
if ($text -notmatch '_alert_fingerprints') {
    $replacement = @'
self._dns_context: OrderedDict[str, dict[str, tuple[str, float, str]]] = OrderedDict()
        # Enterprise alert deduplication is opt-in so the existing detection
        # contract and test suite remain unchanged until production policy enables it.
        self._alert_fingerprints: OrderedDict[str, float] = OrderedDict()
        self._alert_dedup_window = max(30.0, float(os.getenv("BK_SECURITY_ALERT_DEDUP_WINDOW", "300")))
'@
    $text = $text.Replace($anchor, $replacement.TrimEnd())
}

# Add helper methods before _on_event.
$marker = '    def _on_event(self, event: SecurityEvent) -> None:'
if ($text -notmatch 'def _alert_fingerprint') {
$helpers = @'
    @staticmethod
    def _alert_fingerprint(alert: SecurityAlert) -> str:
        data = getattr(alert, "data", {}) or {}
        network = getattr(alert, "network", {}) or {}
        parts = (
            str(getattr(alert, "host_id", "") or ""),
            str(getattr(alert, "title", "") or ""),
            str(getattr(alert, "severity", "") or ""),
            str(getattr(alert, "process", "") or ""),
            str(network.get("dst_ip") or data.get("dst_ip") or ""),
            str(network.get("dst_port") or data.get("dst_port") or ""),
            ",".join(sorted(getattr(alert, "mitre_techniques", []) or [])),
        )
        return hashlib.sha256("|".join(parts).encode("utf-8", "ignore")).hexdigest()

    def _dedup_alert(self, alert: SecurityAlert, now_epoch: float) -> bool:
        """Return True when an equivalent alert was already emitted recently."""
        if os.getenv("BK_SECURITY_ALERT_DEDUP", "0") != "1":
            return False
        fingerprint = self._alert_fingerprint(alert)
        previous = self._alert_fingerprints.get(fingerprint)
        self._alert_fingerprints[fingerprint] = now_epoch
        self._alert_fingerprints.move_to_end(fingerprint)
        cutoff = now_epoch - self._alert_dedup_window
        while self._alert_fingerprints:
            first_key, first_seen = next(iter(self._alert_fingerprints.items()))
            if first_seen >= cutoff:
                break
            self._alert_fingerprints.pop(first_key, None)
        return previous is not None and now_epoch - previous < self._alert_dedup_window

'@
    $text = $text.Replace($marker, $helpers + $marker)
}

# Insert opt-in suppression immediately after detector evaluation.
$old = 'for alert in self.detector.evaluate(event):'
$new = @'
for alert in self.detector.evaluate(event):
            if self._dedup_alert(alert, event_epoch):
                continue
'@
if ($text -match [regex]::Escape($old) -and $text -notmatch 'if self\._dedup_alert\(alert, event_epoch\)') {
    $text = $text.Replace($old, $new.TrimEnd())
}

Set-Content $Core $text -Encoding UTF8

python -m py_compile "$Core"
Write-Host "BK Security Enterprise decision foundation integree." -ForegroundColor Green
Write-Host "Backup : $BackupDir"
Write-Host "Deduplication Enterprise : opt-in via BK_SECURITY_ALERT_DEDUP=1"
Write-Host "Fenetre : BK_SECURITY_ALERT_DEDUP_WINDOW (default 300s)"
Write-Host "Aucune reponse destructive n'est activee par ce patch."
