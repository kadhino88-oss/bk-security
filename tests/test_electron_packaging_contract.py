import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def test_electron_package_declares_nsis_windows_target():
    package = json.loads((ROOT / "electron" / "package.json").read_text(encoding="utf-8"))
    build = package.get("build", {})
    win = build.get("win", {})
    nsis = build.get("nsis", {})
    targets = win.get("target", [])
    assert any((t == "nsis") or (isinstance(t, dict) and t.get("target") == "nsis") for t in targets)
    assert nsis.get("oneClick") is False
    assert nsis.get("perMachine") is True
