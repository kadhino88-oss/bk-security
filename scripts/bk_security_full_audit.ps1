$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " BK SECURITY - AUDIT GLOBAL" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

$fail = 0

function Test-Section {
    param([string]$Name, [scriptblock]$Action)

    Write-Host "[$Name]" -ForegroundColor Yellow
    try {
        & $Action
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            $script:fail++
            Write-Host "  FAIL" -ForegroundColor Red
        } else {
            Write-Host "  OK" -ForegroundColor Green
        }
    } catch {
        $script:fail++
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
}

Test-Section "ARBRE DU PROJET" {
    foreach ($p in @(
        ".\bk_security",
        ".\electron",
        ".\dashboard",
        ".\tests",
        ".\scripts",
        ".\dist"
    )) {
        if (Test-Path $p) {
            Write-Host "  OK  $p"
        } else {
            Write-Host "  MISSING  $p"
            $script:fail++
        }
    }
}

Test-Section "CREDENTIALS / 5 ROLES" {
    $main = Get-Content ".\electron\main.js" -Raw
    $setup = Get-Content ".\electron\setup.html" -Raw

    $required = @(
        "adminPassword",
        "analystPassword",
        "viewerPassword",
        "approverPassword",
        "responderPassword"
    )

    foreach ($r in $required) {
        if ($main -notmatch [regex]::Escape($r)) {
            throw "main.js: rôle absent: $r"
        }
        if ($setup -notmatch [regex]::Escape($r)) {
            throw "setup.html: rôle absent: $r"
        }
    }

    if ($main -notmatch "safeStorage") {
        throw "safeStorage absent de main.js"
    }

    Write-Host "  5 rôles détectés"
    Write-Host "  safeStorage détecté"
}

Test-Section "TESTS PYTHON" {
    python -m pytest -q
}

Test-Section "SYNTAXE ELECTRON" {
    node --check ".\electron\main.js"
}

Test-Section "CONFIGURATION WINDOWS" {
    python -m pytest `
        ".\tests\test_windows_production_setup.py" `
        ".\tests\test_production_configuration.py" `
        ".\tests\test_production_preflight.py" -q
}

Test-Section "ELECTRON / RUNTIME" {
    python -m pytest `
        ".\tests\test_electron_contract.py" `
        ".\tests\test_electron_packaging_contract.py" `
        ".\tests\test_runtime_lifecycle.py" `
        ".\tests\test_desktop_shutdown.py" -q
}

Test-Section "RESPONSE / SECURITY" {
    python -m pytest `
        ".\tests\test_response_engine.py" `
        ".\tests\test_response_api.py" `
        ".\tests\test_windows_response_adapters.py" `
        ".\tests\test_hardening.py" -q
}

Test-Section "THREAT / INCIDENT / AI" {
    python -m pytest `
        ".\tests\test_threat_family.py" `
        ".\tests\test_threat_intel_ai.py" `
        ".\tests\test_ai_soc_contracts.py" `
        ".\tests\test_incident_lifecycle.py" -q
}

Test-Section "RELEASE FILES" {
    foreach ($f in @(
        ".\VERSION",
        ".\pyproject.toml",
        ".\electron\electron-builder.config.js",
        ".\NOTICE-ORIGINS.md",
        ".\LICENSE-THIRD-PARTY-ORBIS.txt"
    )) {
        if (-not (Test-Path $f)) {
            throw "Fichier manquant: $f"
        }
    }
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan

if ($fail -eq 0) {
    Write-Host " AUDIT GLOBAL : PASS" -ForegroundColor Green
    Write-Host " Aucune anomalie bloquante detectee." -ForegroundColor Green
    exit 0
} else {
    Write-Host " AUDIT GLOBAL : $fail PROBLEME(S)" -ForegroundColor Red
    Write-Host " Le projet n'est PAS pret pour une nouvelle release." -ForegroundColor Red
    exit 1
}
