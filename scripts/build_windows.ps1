$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$BuildId = $Timestamp + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
$BuildRoot = Join-Path $ProjectRoot "build\windows-$BuildId"
$BackendDist = Join-Path $ProjectRoot "dist\backend-$BuildId"
$InstallerDist = Join-Path $ProjectRoot "dist\windows-$BuildId"
$DashboardStage = Join-Path $BuildRoot 'dashboard-static'
$DocumentationStage = Join-Path $BuildRoot 'documentation'
$LegalStage = Join-Path $BuildRoot 'legal'
$BackendBuildRoot = Join-Path $BuildRoot 'pyinstaller'
$ReleaseManifest = Join-Path $BuildRoot 'release-manifest.json'
$EnvironmentSetting = $env:BK_SECURITY_ENV
$CaptureModeSetting = $env:BK_SECURITY_CAPTURE_MODE
$CaptureInterfaceSetting = $env:BK_SECURITY_CAPTURE_INTERFACE
$env:BK_SECURITY_WINDOWS_RESPONSE = '0'
$env:BK_SECURITY_ENV = 'test'
$env:BK_SECURITY_CAPTURE_MODE = 'simulation'
$env:BK_SECURITY_CAPTURE_INTERFACE = ''
Push-Location $ProjectRoot

function Invoke-Checked {
    param([string]$Command, [string[]]$Arguments, [string]$Label)
    Write-Host "=== $Label ===" -ForegroundColor Cyan
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE." }
}

function Assert-VersionIdentity {
    $Version = (Get-Content -LiteralPath (Join-Path $ProjectRoot 'VERSION') -Raw).Trim()
    $Electron = Get-Content -LiteralPath (Join-Path $ProjectRoot 'electron\package.json') -Raw | ConvertFrom-Json -AsHashtable
    $Dashboard = Get-Content -LiteralPath (Join-Path $ProjectRoot 'dashboard\package.json') -Raw | ConvertFrom-Json -AsHashtable
    $ElectronLock = Get-Content -LiteralPath (Join-Path $ProjectRoot 'electron\package-lock.json') -Raw | ConvertFrom-Json -AsHashtable
    $DashboardLock = Get-Content -LiteralPath (Join-Path $ProjectRoot 'dashboard\package-lock.json') -Raw | ConvertFrom-Json -AsHashtable
    $ProjectMetadata = Get-Content -LiteralPath (Join-Path $ProjectRoot 'pyproject.toml') -Raw
    $PythonMatch = [regex]::Match($ProjectMetadata, '(?m)^version\s*=\s*"([^"]+)"')
    $Versions = @($Electron.version, $ElectronLock.version, $Dashboard.version, $DashboardLock.version, $PythonMatch.Groups[1].Value)
    $Mismatched = @($Versions | Where-Object { $_ -ne $Version })
    if ([string]::IsNullOrWhiteSpace($Version) -or $Mismatched.Count -gt 0) {
        throw "Release version mismatch. VERSION=$Version; package versions=$($Versions -join ', ')."
    }
    return $Version
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or newer is required for the release build.' }
    if ($env:BK_SECURITY_WINDOWS_RESPONSE -ne '0') { throw 'Windows response actions must remain disabled.' }
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python is required.' }
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js is required.' }

    $Version = Assert-VersionIdentity
    $Node = (Get-Command node).Source
    $ViteCli = Join-Path $ProjectRoot 'dashboard\node_modules\vite\bin\vite.js'
    $ElectronBuilderCli = Join-Path $ProjectRoot 'electron\node_modules\electron-builder\out\cli\cli.js'
    $ElectronRuntime = Join-Path $ProjectRoot 'electron\node_modules\electron\dist\electron.exe'
    if (-not (Test-Path -LiteralPath $ViteCli)) { throw 'Vite is missing from dashboard/node_modules. Install the locked dashboard dependencies before building.' }
    if (-not (Test-Path -LiteralPath $ElectronBuilderCli)) { throw 'electron-builder is missing from electron/node_modules. Install the locked Electron dependencies before building.' }
    if (-not (Test-Path -LiteralPath $ElectronRuntime)) {
        $ElectronInstaller = Join-Path $ProjectRoot 'electron\node_modules\electron\install.js'
        if (-not (Test-Path -LiteralPath $ElectronInstaller)) { throw 'Electron package is missing. Run npm.cmd ci in electron first.' }
        Invoke-Checked 'node' @($ElectronInstaller) 'Downloading the locked Electron 44.5.1 desktop runtime'
    }
    if (-not (Test-Path -LiteralPath $ElectronRuntime)) { throw 'The locked Electron runtime installer did not produce electron.exe.' }

    python --version
    & $Node --version
    Invoke-Checked 'python' @((Join-Path $ProjectRoot 'scripts\verify_build_environment.py')) 'Checking exact locked Python build/test dependencies'

    New-Item -ItemType Directory -Path $BuildRoot, $BackendDist, $InstallerDist, $DashboardStage, $DocumentationStage, $LegalStage, $BackendBuildRoot -Force | Out-Null
    $env:BK_SECURITY_E2E_DATA_DIR = Join-Path ([IO.Path]::GetTempPath()) "bk-security-build-$BuildId"
    $TestTemp = Join-Path ([IO.Path]::GetTempPath()) "bk-security-pytest-$BuildId"
    New-Item -ItemType Directory -Path $TestTemp -Force | Out-Null

    Push-Location (Join-Path $ProjectRoot 'dashboard')
    try {
        Invoke-Checked $Node @($ViteCli, 'build', '--outDir', $DashboardStage, '--emptyOutDir') 'Building dashboard into this release staging directory'
        $DashboardPackage = Get-Content -LiteralPath 'package.json' -Raw | ConvertFrom-Json
        $DashboardTestParts = @([string]$DashboardPackage.scripts.test -split '\s+')
        if ($DashboardTestParts.Count -lt 3 -or $DashboardTestParts[0] -ne 'node' -or $DashboardTestParts[1] -ne '--test') {
            throw 'Dashboard tests must use the direct Node test runner so the release build can execute them without the npm shim.'
        }
        $DashboardTestArguments = @('--test') + @($DashboardTestParts | Select-Object -Skip 2)
        Write-Host '=== Running dashboard unit and integration tests ===' -ForegroundColor Cyan
        $DashboardTestOutput = & $Node @DashboardTestArguments 2>&1
        $DashboardTestExitCode = $LASTEXITCODE
        $DashboardTestOutput | ForEach-Object { Write-Host $_ }
        if ($DashboardTestExitCode -ne 0) { throw "Dashboard tests failed with exit code $DashboardTestExitCode." }
        $DashboardTestMatch = [regex]::Match(($DashboardTestOutput -join "`n"), '(?m)^# pass\s+(\d+)\s*$')
        if (-not $DashboardTestMatch.Success) { throw 'Dashboard tests passed without a parseable TAP pass count.' }
        $DashboardTestsPassed = [int]$DashboardTestMatch.Groups[1].Value
    } finally { Pop-Location }

    $DashboardStatic = $DashboardStage
    $DashboardEntry = Join-Path $DashboardStage 'index.html'
    $DashboardAssets = Join-Path $DashboardStage 'assets'
    if (-not (Test-Path -LiteralPath $DashboardEntry) -or -not (Test-Path -LiteralPath $DashboardAssets)) {
        throw 'Dashboard build did not produce index.html and assets.'
    }
    $JsFiles = @(Get-ChildItem -LiteralPath $DashboardAssets -Filter '*.js' -File)
    $CssFiles = @(Get-ChildItem -LiteralPath $DashboardAssets -Filter '*.css' -File)
    if ($JsFiles.Count -lt 1 -or $CssFiles.Count -lt 1) { throw 'Dashboard build is missing JavaScript or CSS.' }
    foreach ($Relative in @(
        'docs\WINDOWS_PRODUCTION_SETUP.md',
        'docs\WINDOWS_CAPTURE_AND_WIFI_READINESS.md',
        'docs\PHASE6_CONTROLLED_RESPONSE_ACTIVATION_PROTOCOL.md',
        'docs\PHASE6_REAL_WORLD_VALIDATION.md'
    )) {
        Copy-Item -LiteralPath (Join-Path $ProjectRoot $Relative) -Destination (Join-Path $DocumentationStage (Split-Path -Leaf $Relative)) -Force
    }
    foreach ($Relative in @('NOTICE-ORIGINS.md', 'LICENSE-THIRD-PARTY-ORBIS.txt')) {
        Copy-Item -LiteralPath (Join-Path $ProjectRoot $Relative) -Destination (Join-Path $LegalStage (Split-Path -Leaf $Relative)) -Force
    }

    Invoke-Checked 'python' @('-m', 'pytest', '-p', 'no:cacheprovider', '--basetemp', $TestTemp, '-q') 'Running the complete Python test suite'
    Invoke-Checked 'node' @((Join-Path $ProjectRoot 'electron\test\run.js')) 'Running Electron lifecycle and security tests'

    $PyInstallerArgs = @(
        '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir',
        '--name', 'bk-security-backend', '--distpath', $BackendDist,
        '--workpath', (Join-Path $BackendBuildRoot 'work'),
        '--specpath', (Join-Path $BackendBuildRoot 'spec'),
        '--collect-all', 'fastapi', '--collect-all', 'uvicorn',
        '--collect-all', 'scapy', '--collect-all', 'psutil',
        '--add-data', "$DashboardStatic;dashboard/static",
        (Join-Path $ProjectRoot 'bk_security\desktop_backend.py')
    )
    Invoke-Checked 'python' $PyInstallerArgs 'Building the Windows onedir backend with PyInstaller'
    $BackendDir = Join-Path $BackendDist 'bk-security-backend'
    $BackendExecutable = Join-Path $BackendDir 'bk-security-backend.exe'
    if (-not (Test-Path -LiteralPath $BackendExecutable)) { throw "Backend executable is missing: $BackendExecutable" }

    $env:BK_SECURITY_BACKEND_DIR = $BackendDir
    $env:BK_SECURITY_DASHBOARD_DIR = $DashboardStage
    $env:BK_SECURITY_DOCUMENTATION_DIR = $DocumentationStage
    $env:BK_SECURITY_LEGAL_DIR = $LegalStage
    $env:BK_SECURITY_RELEASE_MANIFEST = $ReleaseManifest
    $env:BK_SECURITY_INSTALLER_OUTPUT = $InstallerDist
    Invoke-Checked 'python' @(
        (Join-Path $ProjectRoot 'scripts\release_manifest.py'), '--version', $Version,
        '--backend-dir', $BackendDir, '--dashboard-dir', $DashboardStage,
        '--documentation-dir', $DocumentationStage, '--legal-dir', $LegalStage,
        '--electron-dir', (Join-Path $ProjectRoot 'electron'), '--output', $ReleaseManifest
    ) 'Creating the V1 build identity and integrity inventory'

    Push-Location (Join-Path $ProjectRoot 'electron')
    try {
        $PackagerArguments = @($ElectronBuilderCli, '--config', 'electron-builder.config.js', '--win', 'nsis')
        $PackageReady = $false
        for ($PackagerAttempt = 1; $PackagerAttempt -le 2; $PackagerAttempt++) {
            Write-Host "=== Building the unsigned Windows NSIS installer (attempt $PackagerAttempt/2) ===" -ForegroundColor Cyan
            $PackagerOutput = & $Node @PackagerArguments 2>&1
            $PackagerExitCode = $LASTEXITCODE
            $PackagerOutput | ForEach-Object { Write-Host $_ }
            if ($PackagerExitCode -eq 0) {
                $PackageReady = $true
                break
            }
            if ($PackagerAttempt -eq 2) {
                throw "Electron Builder failed after two attempts with exit code $PackagerExitCode."
            }
            Write-Warning 'Electron Builder did not complete; retrying once in a fresh installer directory.'
            $InstallerDist = Join-Path $ProjectRoot "dist\windows-$BuildId-retry"
            New-Item -ItemType Directory -Path $InstallerDist -Force | Out-Null
            $env:BK_SECURITY_INSTALLER_OUTPUT = $InstallerDist
        }
        if (-not $PackageReady) { throw 'Electron Builder did not produce a Windows package.' }
    }
    finally { Pop-Location }

    $Unpacked = Join-Path $InstallerDist 'win-unpacked'
    $Resources = Join-Path $Unpacked 'resources'
    $Asar = Join-Path $Resources 'app.asar'
    $PackagedBackend = Join-Path $Resources 'backend\bk-security-backend.exe'
    $PackagedDashboard = Join-Path $Resources 'dashboard\static\index.html'
    $PackagedManifest = Join-Path $Resources 'release-manifest.json'
    $Installer = Join-Path $InstallerDist "BK Security Setup $Version.exe"
    foreach ($Required in @($Installer, $Asar, $PackagedBackend, $PackagedDashboard, $PackagedManifest)) {
        if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) { throw "Windows package output is incomplete: $Required" }
    }
    Copy-Item -LiteralPath $ReleaseManifest -Destination (Join-Path $InstallerDist 'release-manifest.json') -Force

    $Signature = Get-AuthenticodeSignature -LiteralPath $Installer
    $Manifest = Get-Content -LiteralPath $ReleaseManifest -Raw | ConvertFrom-Json
    $Metadata = [ordered]@{
        product = 'BK Security'
        version = $Version
        build_id = $Manifest.build_id
        app_id = $Manifest.app_id
        installer = [IO.Path]::GetFileName($Installer)
        installer_sha256 = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
        signature_status = $Signature.Status.ToString()
        signer_subject = if ($Signature.SignerCertificate) { $Signature.SignerCertificate.Subject } else { $null }
        dashboard_tests_passed = $DashboardTestsPassed
        capture_mode_default = 'stopped'
        windows_response_enabled = $false
        installer_install_uninstall_smoke = 'not_run; per-machine install requires an interactive administrator session'
        built_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    $Metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $InstallerDist 'build-metadata.json') -Encoding utf8

    $env:BK_SECURITY_RELEASE_OUTPUT_DIR = Join-Path $InstallerDist 'gate-state'
    Invoke-Checked 'python' @((Join-Path $ProjectRoot 'scripts\release_gate.py'), '--build-dir', $InstallerDist) 'Running the complete V1 release gate against the built Windows package'

    Write-Host ''
    Write-Host 'BK SECURITY V1 WINDOWS BUILD AND RELEASE GATE: SAFE' -ForegroundColor Green
    Write-Host "Version   : $Version"
    Write-Host "Build ID  : $($Manifest.build_id)"
    Write-Host "Installer : $Installer"
    Write-Host "SHA-256   : $($Metadata.installer_sha256)"
    Write-Host "Signature : $($Metadata.signature_status)"
    Write-Host "Gate      : $($env:BK_SECURITY_RELEASE_OUTPUT_DIR)\release-gate.json"
    Write-Host 'Windows response actions: disabled (BK_SECURITY_WINDOWS_RESPONSE=0)'
} finally {
    foreach ($Name in @('BK_SECURITY_BACKEND_DIR', 'BK_SECURITY_DASHBOARD_DIR', 'BK_SECURITY_DOCUMENTATION_DIR', 'BK_SECURITY_LEGAL_DIR', 'BK_SECURITY_RELEASE_MANIFEST', 'BK_SECURITY_INSTALLER_OUTPUT', 'BK_SECURITY_RELEASE_OUTPUT_DIR', 'BK_SECURITY_E2E_DATA_DIR')) {
        Remove-Item "Env:\$Name" -ErrorAction SilentlyContinue
    }
    $env:BK_SECURITY_WINDOWS_RESPONSE = '0'
    if ($null -ne $EnvironmentSetting) { $env:BK_SECURITY_ENV = $EnvironmentSetting }
    else { Remove-Item Env:\BK_SECURITY_ENV -ErrorAction SilentlyContinue }
    if ($null -ne $CaptureModeSetting) { $env:BK_SECURITY_CAPTURE_MODE = $CaptureModeSetting }
    else { Remove-Item Env:\BK_SECURITY_CAPTURE_MODE -ErrorAction SilentlyContinue }
    if ($null -ne $CaptureInterfaceSetting) { $env:BK_SECURITY_CAPTURE_INTERFACE = $CaptureInterfaceSetting }
    else { Remove-Item Env:\BK_SECURITY_CAPTURE_INTERFACE -ErrorAction SilentlyContinue }
    Pop-Location
}
