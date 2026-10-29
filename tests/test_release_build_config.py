from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]

def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def test_frontend_and_electron_dependencies_are_supported_and_pinned():
    package = _read_json(ROOT / "electron" / "package.json")

    dependencies = package.get("dependencies") or {}
    dev_dependencies = package.get("devDependencies") or {}

    assert "electron" not in dependencies
    assert dev_dependencies.get("electron") == "44.5.1"
    assert dev_dependencies.get("electron-builder") == "26.17.0"
    assert package.get("author") == "BK ENTREPRISE"


def test_dashboard_build_uses_unique_release_static_assets_for_backend_and_electron():
    build_script = ROOT / "scripts" / "build_windows.ps1"
    text = build_script.read_text(encoding="utf-8-sig")

    normalized = text.replace("/", "\\").lower()

    # Le script doit bien déclencher une construction du dashboard.
    assert (
        re.search(r"npm\s+.*run\s+build", text, re.IGNORECASE)
        or "@('run', 'build')" in text
        or "npm run build" in text.lower()
        or "run-dashboard-build" in normalized
        or "dashboard build" in normalized
        or "dashboard_build" in normalized
    ), (
        "Windows build script must contain a dashboard build step."
    )

    # Le résultat attendu doit être le dossier static du dashboard.
    assert (
        "dashboard\\static" in normalized
        or "dashboard/static" in normalized
        or "dashboardentry" in normalized
        or "static_index" in normalized
    ), (
        "Windows build script must reference the Vite dashboard static output."
    )
    assert "--outdir" in text.lower()
    assert "$dashboardstage" in normalized
    assert '"$dashboardstatic;dashboard\\static"' in normalized

    static_index = ROOT / "dashboard" / "static" / "index.html"

    if static_index.exists():
        html = static_index.read_text(encoding="utf-8-sig")
        assert '<div id="root"></div>' in html


def test_windows_release_runs_the_dashboard_node_test_script():
    build_script = ROOT / "scripts" / "build_windows.ps1"
    script = build_script.read_text(encoding="utf-8-sig")
    package = _read_json(ROOT / "dashboard" / "package.json")
    test_parts = package["scripts"]["test"].split()

    assert test_parts[:2] == ["node", "--test"]
    assert len(test_parts) > 2
    assert "$DashboardPackage.scripts.test" in script
    assert "$DashboardTestArguments" in script
    assert "$DashboardTestsPassed = [int]$DashboardTestMatch.Groups[1].Value" in script
    assert "dashboard_tests_passed = $DashboardTestsPassed" in script
    release_gate = (ROOT / "scripts" / "release_gate.py").read_text(encoding="utf-8")
    assert "MINIMUM_DASHBOARD_TESTS = 25" in release_gate
    assert 'metadata.get("dashboard_tests_passed")' in release_gate
    assert '"dashboard_tests_passed": package["build_metadata"]["dashboard_tests_passed"]' in release_gate
    for test_file in test_parts[2:]:
        assert (ROOT / "dashboard" / test_file).is_file()


def test_windows_build_has_backend_packaging_contract():
    build_script = ROOT / "scripts" / "build_windows.ps1"
    text = build_script.read_text(encoding="utf-8-sig")

    assert "PyInstaller" in text
    assert "BK_SECURITY_BACKEND_DIR" in text
    assert "BK_SECURITY_INSTALLER_OUTPUT" in text

    # Le script doit contenir l'étape de packaging Electron,
    # directement ou via une fonction/helper.
    normalized = text.lower()

    assert (
        "dist:win" in normalized
        or "electron-builder" in normalized
        or "run-electron" in normalized
        or "electron packaging" in normalized
    ), (
        "Windows build script must contain the Electron packaging step."
    )


def test_electron_package_uses_nsis():
    config = ROOT / "electron" / "electron-builder.config.js"

    assert config.exists()

    text = config.read_text(encoding="utf-8-sig")

    assert "nsis" in text
    assert "requestedExecutionLevel" in text
    assert "requireAdministrator" in text


def test_release_version_is_coherent_across_python_dashboard_electron_and_locks():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    project_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    python_version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', project_text).group(1)
    electron = _read_json(ROOT / "electron" / "package.json")
    electron_lock = _read_json(ROOT / "electron" / "package-lock.json")
    dashboard = _read_json(ROOT / "dashboard" / "package.json")
    dashboard_lock = _read_json(ROOT / "dashboard" / "package-lock.json")
    assert {version, python_version, electron["version"], electron_lock["version"], dashboard["version"], dashboard_lock["version"]} == {"1.0.0"}


def test_packaged_runtime_defaults_to_stopped_and_never_enables_responses():
    backend_command = (ROOT / "electron" / "backend-command.js").read_text(encoding="utf-8")
    assert "stopped" in backend_command
    assert "BK_SECURITY_WINDOWS_RESPONSE: '0'" in backend_command
    assert "explicitly selected BK_SECURITY_CAPTURE_INTERFACE" in backend_command
    assert "BK_SECURITY_RELEASE_MANIFEST" in (ROOT / "electron" / "electron-builder.config.js").read_text(encoding="utf-8")


def test_initial_setup_collects_all_five_unique_production_roles():
    setup = (ROOT / "electron" / "setup.html").read_text(encoding="utf-8")
    main = (ROOT / "electron" / "main.js").read_text(encoding="utf-8")
    for role in ("admin", "analyst", "viewer", "approver", "responder"):
        assert f'id="{role}"' in setup
        assert f"{role}Password" in main


def test_windows_production_configuration_covers_all_five_roles_and_keeps_safe_defaults():
    script = (ROOT / "scripts" / "configure_windows_production.ps1").read_text(encoding="utf-8-sig")
    for role in ("ADMIN", "ANALYST", "VIEWER", "APPROVER", "RESPONDER"):
        assert f"BK_SECURITY_{role}_PASSWORD" in script
    assert "BK_SECURITY_WINDOWS_RESPONSE', '0'" in script
    assert "BK_SECURITY_CAPTURE_MODE', 'stopped'" in script


def test_windows_validation_uses_isolated_pytest_temp_and_propagates_failures():
    script = (ROOT / "scripts" / "validate_windows.ps1").read_text(encoding="utf-8-sig")
    assert "windows-validation-$ValidationId" in script
    assert "--basetemp $TestTemp" in script
    assert "$LASTEXITCODE -ne 0" in script


def test_windows_build_uses_installed_node_clis_without_global_npm():
    script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8-sig").lower()
    assert "dashboard\\node_modules\\vite\\bin\\vite.js" in script
    assert "electron\\node_modules\\electron-builder\\out\\cli\\cli.js" in script
    assert "get-command npm.cmd" not in script
    assert "$npm =" not in script
    assert "$packagerattempt -le 2" in script
    assert '"dist\\windows-$buildid-retry"' in script


def test_windows_validation_treats_optional_diagnostics_as_warnings():
    script = (ROOT / "scripts" / "validate_windows.ps1").read_text(encoding="utf-8-sig")
    assert "Write-Warning \"PowerShell adapter details unavailable" in script
    assert "npm.cmd is installed but failed to run" in script
