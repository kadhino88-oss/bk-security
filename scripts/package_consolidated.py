from __future__ import annotations

import hashlib
import zipfile
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT.parent / "releases"
PREFIX = "bk-security-v1"
EXCLUDED_DIRS = {
    ".git", ".venv", ".pytest_cache", ".npm-cache", "node_modules",
    "__pycache__", "test-data", "dist", "build", "outputs",
    "bk_security_core.egg-info",
    "releases",
}
EXCLUDED_SUFFIXES = {
    ".db", ".sqlite", ".sqlite3", ".log", ".pyc", ".pyd", ".dll",
    ".exe", ".msi", ".zip", ".whl", ".tmp",
}
EXCLUDED_NAMES = {".env", "Thumbs.db", ".DS_Store", "BUNDLE-MANIFEST.sha256"}


def source_files() -> list[Path]:
    included = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if path.name in EXCLUDED_NAMES or path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        if path.name.startswith(".env.") and path.name != ".env.example":
            continue
        included.append(path)
    return sorted(included, key=lambda item: item.relative_to(ROOT).as_posix().casefold())


def create_bundle() -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    date_tag = date.today().strftime("%Y%m%d")
    existing = []
    for candidate in OUTPUT_DIR.glob(f"BK-Security-V1-Consolidated-{date_tag}-r*.zip"):
        try:
            existing.append(int(candidate.stem.rsplit("-r", 1)[1]))
        except (IndexError, ValueError):
            pass
    revision = max(existing, default=0) + 1
    while True:
        target = OUTPUT_DIR / f"BK-Security-V1-Consolidated-{date_tag}-r{revision}.zip"
        if not target.exists():
            break
        revision += 1

    files = source_files()
    manifest_lines = []
    payloads: list[tuple[str, bytes]] = []
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        archive_name = f"{PREFIX}/{relative}"
        content = path.read_bytes()
        payloads.append((archive_name, content))
        manifest_lines.append(f"{hashlib.sha256(content).hexdigest()}  {archive_name}\n")
    manifest_name = f"{PREFIX}/BUNDLE-MANIFEST.sha256"
    manifest = "".join(manifest_lines).encode("utf-8")
    payloads.append((manifest_name, manifest))

    with target.open("xb") as output:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for archive_name, content in payloads:
                bundle.writestr(archive_name, content)

    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    checksum = target.with_suffix(target.suffix + ".sha256")
    with checksum.open("x", encoding="ascii", newline="\n") as output:
        output.write(f"{digest}  {target.name}\n")
    print(f"Bundle: {target}")
    print(f"Files: {len(payloads)} (including manifest)")
    print(f"Bytes: {target.stat().st_size}")
    print(f"SHA-256: {digest}")
    return target


if __name__ == "__main__":
    create_bundle()
