$ErrorActionPreference = 'Stop'

Write-Host '=== BK Security Windows production configuration ===' -ForegroundColor Cyan
Write-Host 'This configures the current Windows user environment for the packaged backend.'

function Read-SecretValue([string]$Prompt, [int]$MinimumLength = 12) {
    while ($true) {
        $secure = Read-Host $Prompt -AsSecureString
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        if ($plain.Length -ge $MinimumLength) { return $plain }
        Write-Warning "Value must contain at least $MinimumLength characters."
    }
}

$authSecret = Read-SecretValue 'BK_SECURITY_AUTH_SECRET (minimum 32 characters)' 32
$adminPassword = Read-SecretValue 'BK_SECURITY_ADMIN_PASSWORD' 12
$analystPassword = Read-SecretValue 'BK_SECURITY_ANALYST_PASSWORD' 12
$viewerPassword = Read-SecretValue 'BK_SECURITY_VIEWER_PASSWORD' 12
$approverPassword = Read-SecretValue 'BK_SECURITY_APPROVER_PASSWORD' 12
$responderPassword = Read-SecretValue 'BK_SECURITY_RESPONDER_PASSWORD' 12

if (@($adminPassword, $analystPassword, $viewerPassword, $approverPassword, $responderPassword) | Sort-Object -Unique | Measure-Object | Select-Object -ExpandProperty Count) -ne 5 {
    throw 'Production passwords must be unique.'
}

[Environment]::SetEnvironmentVariable('BK_SECURITY_ENV', 'production', 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_AUTH_SECRET', $authSecret, 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_ADMIN_PASSWORD', $adminPassword, 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_ANALYST_PASSWORD', $analystPassword, 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_VIEWER_PASSWORD', $viewerPassword, 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_APPROVER_PASSWORD', $approverPassword, 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_RESPONDER_PASSWORD', $responderPassword, 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_CORS_ORIGINS', '', 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_CAPTURE_MODE', 'stopped', 'User')
[Environment]::SetEnvironmentVariable('BK_SECURITY_WINDOWS_RESPONSE', '0', 'User')

Write-Host ''
Write-Host 'Production configuration saved for the current Windows user.' -ForegroundColor Green
Write-Host 'The production baseline leaves capture stopped until an operator selects an interface and starts live capture; Windows responses stay disabled.' -ForegroundColor Yellow
Write-Host 'Restart BK Security (or the terminal/application) so the new environment is loaded.'
