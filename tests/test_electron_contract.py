from pathlib import Path
import json
import re


ROOT = Path(__file__).resolve().parents[1]


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_electron_navigation_and_packaged_backend_contracts():
    electron_dir = ROOT / "electron"

    main = electron_dir / "main.js"
    backend_command = electron_dir / "backend-command.js"
    preload = electron_dir / "preload.js"
    config = electron_dir / "config.json"

    assert main.exists(), "electron/main.js is missing."
    assert backend_command.exists(), "electron/backend-command.js is missing."
    assert preload.exists(), "electron/preload.js is missing."
    assert config.exists(), "electron/config.json is missing."

    main_text = main.read_text(encoding="utf-8-sig")
    backend_text = backend_command.read_text(encoding="utf-8-sig")
    preload_text = preload.read_text(encoding="utf-8-sig")
    cfg = _read_json(config)

    assert "backend" in cfg
    assert "dashboard" in cfg

    # Backend empaqueté
    assert (
        "resourcesPath" in backend_text
        or "resourcesPath" in main_text
    ), "Packaged backend does not reference Electron resourcesPath."

    assert (
        "bk-security-backend.exe" in backend_text
        or "bk-security-backend" in backend_text
    ), "Packaged backend executable is not referenced."

    # Dashboard Vite
    static_dir = ROOT / "dashboard" / "static"
    index = static_dir / "index.html"

    assert index.exists(), "dashboard/static/index.html is missing."

    html = index.read_text(encoding="utf-8-sig")

    assert '<div id="root"></div>' in html, (
        "Vite React root is missing from dashboard/static/index.html."
    )

    script_matches = re.findall(
        r'<script[^>]+src=["\']([^"\']+\.js)["\']',
        html,
        flags=re.IGNORECASE,
    )

    assert script_matches, (
        "No JavaScript asset is referenced by dashboard/static/index.html."
    )

    for src in script_matches:
        # Vite produit normalement /assets/xxx.js.
        # On retire proprement le slash initial.
        relative_src = src.lstrip("/\\")

        asset = (static_dir / relative_src).resolve()

        assert asset.exists(), (
            f"Vite dashboard asset referenced by index.html is missing: {src}"
        )

    # Preload
    assert "getStatus" in preload_text
    assert "restartBackend" in preload_text
    assert "getCredentialStatus" in preload_text

def test_credentials_store_recovery_is_non_destructive():
    main = (ROOT / "electron" / "main.js").read_text(encoding="utf-8-sig")
    assert "function inspectCredentialStore()" in main
    assert "status: 'unavailable'" in main
    assert "status: 'invalid'" in main
    assert "No credential data was changed." in main
    assert "Aucune donnée n’a été écrasée." in main
    assert "credential_store_backed_up_for_repair" in main


def test_five_role_credentials_are_consistent():
    main = (ROOT / "electron" / "main.js").read_text(encoding="utf-8-sig")
    setup = (ROOT / "electron" / "setup.html").read_text(encoding="utf-8-sig")
    backend = (ROOT / "bk_security" / "api" / "app.py").read_text(encoding="utf-8-sig")
    for role in ("admin", "analyst", "viewer", "approver", "responder"):
        assert f"{role}Password" in main
        assert f"id=\"{role}\"" in setup
        assert f"BK_SECURITY_{role.upper()}_PASSWORD" in main
        assert f"BK_SECURITY_{role.upper()}_PASSWORD" in backend
