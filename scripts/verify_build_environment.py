from __future__ import annotations

import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if sys.version_info < (3, 11):
        print("Build environment check failed: Python 3.11 or newer is required.")
        return 2
    lock = ROOT / "requirements-build.lock"
    if not lock.is_file():
        print("Build environment check failed: requirements-build.lock is missing.")
        return 2
    failures = []
    for line in lock.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        name, separator, expected = item.partition("==")
        if not separator or not name or not expected:
            failures.append("requirements-build.lock contains a non-exact dependency entry.")
            continue
        try:
            actual = metadata.version(name)
        except metadata.PackageNotFoundError:
            failures.append(f"{name} is missing.")
            continue
        if actual != expected:
            failures.append(f"{name} version mismatch (expected {expected}).")
    if failures:
        print("Build environment check failed:")
        for failure in failures:
            print(f"  {failure}")
        return 3
    print("Build environment check passed: exact Python lock versions are installed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
