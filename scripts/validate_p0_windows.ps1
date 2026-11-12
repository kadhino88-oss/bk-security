$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not $IsWindows) { throw 'Run this validation from Windows PowerShell 7 or newer.' }
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or newer is required.' }

foreach ($Command in @('python', 'node')) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Required command '$Command' was not found on PATH."
    }
}

$PreviousResponseSetting = $env:BK_SECURITY_WINDOWS_RESPONSE
$env:BK_SECURITY_WINDOWS_RESPONSE = '0'

function Invoke-Checked {
    param([string]$Command, [string[]]$Arguments, [string]$Label)
    Write-Host "=== $Label ===" -ForegroundColor Cyan
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE." }
}

try {
    Write-Host "Project: $ProjectRoot"
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
    Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
    Invoke-Checked 'python' @('--version') 'Python runtime'
    Invoke-Checked 'node' @('--version') 'Node runtime'

    $ValidationId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
    $TestTemp = Join-Path ([IO.Path]::GetTempPath()) "bk-security-p0-pytest-$ValidationId"
    New-Item -ItemType Directory -Path $TestTemp -Force | Out-Null

    Invoke-Checked 'python' @('-m', 'pytest', '-p', 'no:cacheprovider', '--basetemp', $TestTemp, '-q') 'Complete Python regression suite'
    Invoke-Checked 'node' @((Join-Path $ProjectRoot 'electron\test\run.js')) 'Electron lifecycle and security regression suite'

    Push-Location (Join-Path $ProjectRoot 'dashboard')
    try {
        Invoke-Checked 'node' @(
            '--test', 'src/traffic-triage.test.js', 'src/brain-visuals.test.js',
            'src/alert-sound.test.js', 'src/capture-controls.test.js',
            'src/response-activity.test.js', 'src/monthly-audit.test.js',
            'src/auth-session.test.js', 'src/admin-sessions.test.js'
        ) 'Dashboard regression suite'
    } finally { Pop-Location }

    Write-Host ''
    Write-Host 'P0 WINDOWS-HOSTED REGRESSION SUITES: PASS' -ForegroundColor Green
    Write-Host 'Windows service installation, ACL enforcement, and privileged execution remain separate acceptance checks.'
} finally {
    if ($null -ne $PreviousResponseSetting) { $env:BK_SECURITY_WINDOWS_RESPONSE = $PreviousResponseSetting }
    else { Remove-Item Env:\BK_SECURITY_WINDOWS_RESPONSE -ErrorAction SilentlyContinue }
}
