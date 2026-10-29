"""Preflight installed artifacts and fail closed on incomplete production config."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bk_security.configuration import production_configuration_errors

REQUIRED = (
    ROOT / "bk_security" / "api" / "app.py",
    ROOT / "bk_security" / "configuration.py",
    ROOT / "bk_security" / "core.py",
    ROOT / "dashboard" / "static" / "index.html",
    ROOT / "electron" / "main.js",
    ROOT / "pyproject.toml",
)


def main() -> int:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED if not path.is_file()]
    if missing:
        print("BK Security production preflight: FAILED")
        for item in missing:
            print(f"  MISSING: {item}")
        return 2

    environment = os.getenv("BK_SECURITY_ENV", "development").lower()
    errors = production_configuration_errors(os.environ)
    if errors:
        print("BK Security production preflight: FAILED")
        for item in errors:
            print(f"  INVALID: {item}")
        return 3

    print("BK Security production preflight: PASS")
    print(f"  environment={environment}")
    print("  required runtime artifacts present")
    if environment == "production":
        print("  production configuration valid; response flag is disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
