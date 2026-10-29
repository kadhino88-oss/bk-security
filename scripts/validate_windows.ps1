$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host '=== BK Security Windows validation ===' -ForegroundColor Cyan

function Test-CommandExists([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Write-Host "Python: $(python --version 2>&1)"
Write-Host "Node: $(node --version 2>&1)"
$NpmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if ($NpmCommand) {
    $NpmVersion = & $NpmCommand.Source --version 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Host "npm: $NpmVersion" }
    else { Write-Warning "npm.cmd is installed but failed to run: $NpmVersion" }
} else {
    Write-Warning 'npm.cmd is unavailable; the release build invokes the checked-in Node package CLIs directly.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Administrator: $isAdmin"
if (-not $isAdmin) {
    Write-Warning 'Not elevated. Live Npcap capture cannot be validated in this session.'
}

$npcapService = Get-Service -Name npcap -ErrorAction SilentlyContinue
if ($npcapService) {
    Write-Host "Npcap service: $($npcapService.Status)"
} else {
    Write-Warning 'Npcap service was not found.'
}

Write-Host '--- Network adapters ---'
try {
    Get-NetAdapter -ErrorAction Stop | Sort-Object ifIndex | Select-Object ifIndex, Name, InterfaceDescription, Status, LinkSpeed | Format-Table -AutoSize
} catch {
    Write-Warning "PowerShell adapter details unavailable in this session: $($_.Exception.Message)"
}

Write-Host '--- Python Scapy / platform diagnostics ---'
python -c "import os,sys; print('Python executable:',sys.executable); print('Windows:',os.name); import scapy; print('Scapy:',getattr(scapy,'VERSION','unknown'))"

Write-Host '--- BK Security capture capabilities ---'
$env:PYTHONPATH = $ProjectRoot
python -c "from bk_security.capture.live import LivePacketCapture; from bk_security.platform_windows import discover_interfaces, find_npcap, is_elevated; print('Npcap detected:',find_npcap()); print('Elevated:',is_elevated()); print('Live capture available:',LivePacketCapture.available()); print('Interfaces:'); [print('  -',i.name,'|',i.status,'|',i.ipv4) for i in discover_interfaces()]"

Write-Host '--- Python tests ---'
$ValidationId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
$TestTemp = Join-Path $ProjectRoot "build\windows-validation-$ValidationId\pytest"
New-Item -ItemType Directory -Path $TestTemp -Force | Out-Null
python -m pytest -p no:cacheprovider --basetemp $TestTemp -q
if ($LASTEXITCODE -ne 0) {
    throw "Python tests failed with exit code $LASTEXITCODE. Test artifacts: $TestTemp"
}

Write-Host '=== Validation complete ===' -ForegroundColor Green
