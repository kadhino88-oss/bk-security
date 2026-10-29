from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scripts" / "production_runtime_check.py"

def test_production_preflight_script_exists():
    assert TARGET.exists()

def test_required_runtime_artifacts_exist():
    required = [
        ROOT / "bk_security",
        ROOT / "bk_security" / "api" / "app.py",
        ROOT / "bk_security" / "core.py",
        ROOT / "electron",
        ROOT / "dashboard",
    ]
    assert all(p.exists() for p in required)
