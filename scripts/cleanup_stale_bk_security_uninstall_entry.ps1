[CmdletBinding()]
param(
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

$installRoot = 'C:\Program Files\BK Security'
$appExecutable = Join-Path $installRoot 'BK Security.exe'
$uninstaller = Join-Path $installRoot 'Uninstall BK Security.exe'
$manifestPath = Join-Path $installRoot 'resources\release-manifest.json'
$currentBuildId = 'v1.0.0-3a43e61a67fb1fc8'
$currentKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\d1f08d36-26f7-50ed-a276-c4fa5eff449c'
$staleKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\c5c23a17-7cae-5c52-bff6-fc3960942eef'

if (-not (Test-Path -LiteralPath $appExecutable -PathType Leaf)) {
    throw 'The expected BK Security executable is missing; no registry change was made.'
}
if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
    throw 'The expected BK Security uninstaller is missing; no registry change was made.'
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'The installed release manifest is missing; no registry change was made.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.build_id -ne $currentBuildId) {
    throw 'The installed build does not match the cleanup target; no registry change was made.'
}

if (-not (Test-Path -LiteralPath $currentKey) -or -not (Test-Path -LiteralPath $staleKey)) {
    throw 'Both the verified current and stale uninstall entries must exist; no registry change was made.'
}

$current = Get-ItemProperty -LiteralPath $currentKey
$stale = Get-ItemProperty -LiteralPath $staleKey
$expectedUninstall = '"' + $uninstaller + '" /allusers'
$expectedQuietUninstall = '"' + $uninstaller + '" /allusers /S'
$expectedIcon = $appExecutable + ',0'

foreach ($entry in @(
    [pscustomobject]@{ Name = 'current'; Properties = $current },
    [pscustomobject]@{ Name = 'stale'; Properties = $stale }
)) {
    $properties = $entry.Properties
    if ($properties.DisplayName -ne 'BK Security 1.0.0' -or
        $properties.DisplayVersion -ne '1.0.0' -or
        $properties.Publisher -ne 'BK ENTREPRISE' -or
        $properties.DisplayIcon -ne $expectedIcon -or
        $properties.UninstallString -ne $expectedUninstall -or
        $properties.QuietUninstallString -ne $expectedQuietUninstall) {
        throw ('The ' + $entry.Name + ' entry does not match the verified BK Security installation; no registry change was made.')
    }
}

if ($current.PSPath -eq $stale.PSPath) {
    throw 'The current and stale registry paths unexpectedly resolve to the same key.'
}
if (@(Get-ChildItem -LiteralPath $staleKey).Count -ne 0) {
    throw 'The stale registry key has child keys; no registry change was made.'
}

$result = [ordered]@{
    mode = if ($Apply) { 'apply' } else { 'dry-run' }
    current_build_id = $manifest.build_id
    current_uninstall_key = $currentKey
    stale_duplicate_key = $staleKey
    both_entries_target = $uninstaller
    current_estimated_size_kb = $current.EstimatedSize
    stale_estimated_size_kb = $stale.EstimatedSize
    change = if ($Apply) { 'export the stale key, then delete only that key' } else { 'no registry changes' }
}

if (-not $Apply) {
    [pscustomobject]$result | ConvertTo-Json -Depth 3
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Apply requires a 64-bit elevated PowerShell session; no registry change was made.'
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    throw 'Apply requires 64-bit PowerShell to avoid registry redirection; no registry change was made.'
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupId = [guid]::NewGuid().ToString('N')
$backupPath = Join-Path $env:TEMP ('bk-security-stale-uninstall-' + $timestamp + '-' + $backupId + '.reg')
$regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
& $regExe export 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\c5c23a17-7cae-5c52-bff6-fc3960942eef' $backupPath /y | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
    throw 'Registry backup export failed; the stale entry was not deleted.'
}

try {
    Remove-Item -LiteralPath $staleKey -Recurse -Force
} catch {
    throw ('Registry export preserved at ' + $backupPath + '. Removal failed: ' + $_.Exception.Message)
}
if (Test-Path -LiteralPath $staleKey) {
    throw ('The stale registry entry remains. Recovery export: ' + $backupPath)
}
if (-not (Test-Path -LiteralPath $currentKey)) {
    throw ('The current registry entry is unexpectedly missing. Recovery export: ' + $backupPath)
}

$result.backup = $backupPath
$result.change = 'stale duplicate removed; current entry verified'
[pscustomobject]$result | ConvertTo-Json -Depth 3
