import json

from scripts.release_manifest import ELECTRON_FILES, create_manifest


def test_release_manifest_hashes_dashboard_backend_and_electron_identity(tmp_path):
    package_inputs = tmp_path / "build" / "dist"
    backend = package_inputs / "backend"
    dashboard = package_inputs / "dashboard"
    documentation = package_inputs / "documentation"
    legal = package_inputs / "legal"
    electron = tmp_path / "electron"
    backend.mkdir(parents=True)
    dashboard.mkdir()
    documentation.mkdir()
    legal.mkdir()
    electron.mkdir()
    (backend / "bk-security-backend.exe").write_bytes(b"backend-binary")
    (dashboard / "index.html").write_text("<div id=\"root\"></div>", encoding="utf-8")
    (documentation / "WINDOWS_PRODUCTION_SETUP.md").write_text("setup", encoding="utf-8")
    (legal / "NOTICE-ORIGINS.md").write_text("notice", encoding="utf-8")
    for relative in ELECTRON_FILES:
        (electron / relative).write_text(relative, encoding="utf-8")
    manifest_path = tmp_path / "release-manifest.json"

    manifest = create_manifest(
        version="1.0.0",
        build_id="v1.0.0-test",
        backend_dir=backend,
        dashboard_dir=dashboard,
        documentation_dir=documentation,
        legal_dir=legal,
        electron_dir=electron,
        output=manifest_path,
        root=tmp_path,
    )

    assert manifest["windows_response_enabled"] is False
    assert manifest["capture_mode_default"] == "stopped"
    assert manifest["version"] == "1.0.0"
    assert "backend/bk-security-backend.exe" in manifest["resource_files"]
    assert "dashboard/static/index.html" in manifest["resource_files"]
    assert "docs/WINDOWS_PRODUCTION_SETUP.md" in manifest["resource_files"]
    assert "legal/NOTICE-ORIGINS.md" in manifest["resource_files"]
    assert set(manifest["electron_files"]) == set(ELECTRON_FILES)
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest
