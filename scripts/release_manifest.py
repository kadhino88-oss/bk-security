from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_ID = "com.bkentreprise.bksecurity"
ELECTRON_FILES = (
    "main.js",
    "preload.js",
    "security-policy.js",
    "dashboard-url.js",
    "backend-command.js",
    "backend-supervisor.js",
    "runtime-log.js",
    "integrity-manifest.js",
    "config.json",
    "setup.html",
)
SOURCE_ROOTS = ("bk_security", "electron", "dashboard/src", "scripts", "tests")
SOURCE_FILES = (
    "VERSION", "pyproject.toml", "requirements-build.lock", "dashboard/package.json", "dashboard/package-lock.json",
    "electron/package.json", "electron/package-lock.json",
)
EXCLUDED_PARTS = {"node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".git"}
EXCLUDED_BACKUP_MARKERS = (".bak", ".backup-")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_map(root: Path) -> dict[str, str]:
    if not root.is_dir():
        raise FileNotFoundError(f"Release input directory is missing: {root}")
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"Release input contains a symbolic link: {path}")
        if path.is_file():
            result[relative.as_posix()] = sha256(path)
    if not result:
        raise ValueError(f"Release input directory is empty: {root}")
    return result


def source_sha256(root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    candidates: set[Path] = set()
    for relative in SOURCE_FILES:
        path = root / relative
        if path.is_file():
            candidates.add(path)
    for relative in SOURCE_ROOTS:
        directory = root / relative
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if (
                path.is_file()
                and not path.is_symlink()
                and not any(part in EXCLUDED_PARTS for part in path.relative_to(root).parts)
                and not any(marker in path.name.lower() for marker in EXCLUDED_BACKUP_MARKERS)
            ):
                candidates.add(path)
    for path in sorted(candidates, key=lambda item: item.relative_to(root).as_posix()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def create_manifest(
    *,
    version: str,
    build_id: str | None,
    backend_dir: Path,
    dashboard_dir: Path,
    documentation_dir: Path,
    legal_dir: Path,
    electron_dir: Path,
    output: Path,
    root: Path = ROOT,
) -> dict:
    source_digest = source_sha256(root)
    if not build_id:
        build_id = f"v{version}-{source_digest[:16]}"
    electron_files = {}
    for relative in ELECTRON_FILES:
        path = electron_dir / relative
        if not path.is_file():
            raise FileNotFoundError(f"Required Electron package input is missing: {relative}")
        electron_files[relative] = sha256(path)
    manifest = {
        "schema_version": 1,
        "product": "BK Security",
        "app_id": APP_ID,
        "version": version,
        "build_id": build_id,
        "source_sha256": source_digest,
        "capture_mode_default": "stopped",
        "windows_response_enabled": False,
        "resource_files": {
            **{f"backend/{name}": value for name, value in _file_map(backend_dir).items()},
            **{f"dashboard/static/{name}": value for name, value in _file_map(dashboard_dir).items()},
            **{f"docs/{name}": value for name, value in _file_map(documentation_dir).items()},
            **{f"legal/{name}": value for name, value in _file_map(legal_dir).items()},
        },
        "electron_files": electron_files,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Create the BK Security V1 integrity manifest.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-id")
    parser.add_argument("--backend-dir", type=Path, required=True)
    parser.add_argument("--dashboard-dir", type=Path, required=True)
    parser.add_argument("--documentation-dir", type=Path, required=True)
    parser.add_argument("--legal-dir", type=Path, required=True)
    parser.add_argument("--electron-dir", type=Path, default=ROOT / "electron")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = create_manifest(
        version=args.version,
        build_id=args.build_id,
        backend_dir=args.backend_dir,
        dashboard_dir=args.dashboard_dir,
        documentation_dir=args.documentation_dir,
        legal_dir=args.legal_dir,
        electron_dir=args.electron_dir,
        output=args.output,
    )
    print(f"Release manifest: {args.output}")
    print(f"Version: {manifest['version']} | build: {manifest['build_id']}")
    print(f"Hashed files: {len(manifest['resource_files']) + len(manifest['electron_files'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
