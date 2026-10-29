$ErrorActionPreference = "Stop"

Write-Host "=== BK Security Windows Preflight ==="

$python = Get-Command python -ErrorAction SilentlyContinue
$node = Get-Command node -ErrorAction SilentlyContinue
$npm = Get-Command npm -ErrorAction SilentlyContinue

if (-not $python) { throw "Python not found." }
if (-not $node) { throw "Node.js not found." }
if (-not $npm) { throw "npm not found." }

Write-Host "Python: $(& python --version)"
Write-Host "Node:   $(& node --version)"
Write-Host "npm:    $(& npm --version)"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
Write-Host "Administrator: $isAdmin"

$npcap = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if ($npcap) {
    Write-Host "Npcap service: $($npcap.Status)"
} else {
    Write-Warning "Npcap service not found. Live capture cannot be validated yet."
}

Write-Host ""
Write-Host "Running BK Security Python preflight..."
python .\scripts\production_runtime_check.py

Write-Host ""
Write-Host "Running Python tests..."
python -m pytest -q

Write-Host ""
Write-Host "Windows preflight completed."
