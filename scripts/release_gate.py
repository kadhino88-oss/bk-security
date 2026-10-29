from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_manifest import APP_ID, sha256, source_sha256

CRITICAL_TESTS = (
    "tests/test_security_reliability.py",
    "tests/test_security_golden_scenarios.py",
    "tests/test_ai_soc_contracts.py",
    "tests/test_threat_family.py",
    "tests/test_brain_mode_contract.py",
    "tests/test_incident_lifecycle.py",
    "tests/test_response_engine.py",
    "tests/test_response_api.py",
    "tests/test_windows_response_adapters.py",
    "tests/test_production_configuration.py",
    "tests/test_desktop_shutdown.py",
    "tests/test_release_manifest.py",
)
MINIMUM_PYTHON_TESTS = 145
MINIMUM_DASHBOARD_TESTS = 25
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    re.compile(rb"\bsk-(?:live|proj)-[A-Za-z0-9_-]{20,}\b"),
)
TEXT_SUFFIXES = {".html", ".js", ".css", ".json", ".toml", ".yaml", ".yml", ".txt", ".md", ".jsonl"}


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _record_blocked_candidate(out_dir: Path, version: str, stage: str, reason: str) -> None:
    lkg_path = out_dir / "last-known-good.json"
    lkg = json.loads(lkg_path.read_text(encoding="utf-8")) if lkg_path.exists() else None
    prior_status_path = out_dir / "candidate-status.json"
    prior_status = json.loads(prior_status_path.read_text(encoding="utf-8")) if prior_status_path.exists() else {}
    _atomic_json(out_dir / "candidate-status.json", {
        "candidate_version": version,
        "status": "BLOCKED",
        "failed_stage": stage,
        "reason": reason,
        "active_version": prior_status.get("active_version"),
        "last_known_good": lkg,
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "automatic_rollback": "candidate was blocked before activation; active release is unchanged" if lkg else "candidate blocked; no Last Known Good is recorded",
    })


def _record_passed_candidate(out_dir: Path, manifest: dict) -> None:
    prior_status_path = out_dir / "candidate-status.json"
    prior_status = json.loads(prior_status_path.read_text(encoding="utf-8")) if prior_status_path.exists() else {}
    release = {**manifest, "status": "SAFE"}
    _atomic_json(out_dir / "release-gate.json", release)
    _atomic_json(out_dir / "last-known-good.json", {
        "version": manifest["version"],
        "artifact_sha256": manifest["artifact_sha256"],
        "config_fingerprint": manifest["config_fingerprint"],
        "configuration": manifest["validated_configuration"],
        "validated_at": manifest["validated_at"],
    })
    _atomic_json(out_dir / "candidate-status.json", {
        "candidate_version": manifest["version"],
        "active_version": prior_status.get("active_version"),
        "status": "SAFE",
        "release_eligible": True,
        "activated": False,
        "validated_at": manifest["validated_at"],
        "failed_stage": None,
    })


def _run(stage: str, command: list[str], out_dir: Path, version: str, env: dict[str, str]) -> tuple[bool, str]:
    print(f"=== {stage} ===", flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, check=False, capture_output=True, text=True, errors="replace")
    output = (result.stdout or "") + (result.stderr or "")
    if output:
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if result.returncode:
        _record_blocked_candidate(out_dir, version, stage, f"command exited with status {result.returncode}")
        print("Candidate blocked; the Last Known Good manifest was preserved.", flush=True)
        return False, output
    return True, output


def _compile_sources() -> int:
    count = 0
    for directory in (ROOT / "bk_security", ROOT / "scripts", ROOT / "tests"):
        for path in sorted(directory.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            compile(path.read_bytes(), str(path), "exec")
            count += 1
    return count


def _dashboard_files(static: Path) -> tuple[str, str]:
    index = static / "index.html"
    assets = static / "assets"
    if not index.is_file() or not assets.is_dir():
        raise ValueError("dashboard/static must contain index.html and an assets directory.")
    html = index.read_text(encoding="utf-8")
    if '<div id="root"></div>' not in html:
        raise ValueError("Dashboard React root is missing.")
    js_refs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html, re.IGNORECASE)
    css_refs = re.findall(r'<link[^>]+href=["\']([^"\']+\.css)["\']', html, re.IGNORECASE)
    if not js_refs or not css_refs:
        raise ValueError("Dashboard index must reference at least one JavaScript and CSS asset.")
    for reference in [*js_refs, *css_refs]:
        relative = reference.lstrip("/\\").replace("/", os.sep).replace("\\", os.sep)
        target = (static / relative).resolve()
        if not target.is_relative_to(static.resolve()) or not target.is_file():
            raise ValueError(f"Dashboard asset reference is missing or outside static root: {reference}")
    return html, str(len(set(js_refs)) + len(set(css_refs)))


def _dashboard_test_count(metadata: dict) -> int:
    count = metadata.get("dashboard_tests_passed")
    if isinstance(count, bool) or not isinstance(count, int) or count < MINIMUM_DASHBOARD_TESTS:
        raise ValueError(
            f"Dashboard Node test results are missing or below the minimum {MINIMUM_DASHBOARD_TESTS}."
        )
    return count


def _scan_text_files(root: Path) -> list[str]:
    findings = []
    if not root.exists():
        return findings
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(root).as_posix()
        if path.name.lower() == ".env" or (path.name.lower().startswith(".env.") and path.name != ".env.example"):
            findings.append(f"environment file included: {relative}")
            continue
        content = path.read_bytes()
        if any(pattern.search(content) for pattern in SECRET_PATTERNS):
            findings.append(f"known secret pattern: {relative}")
    return findings


def _verify_package(build_dir: Path, env: dict[str, str], version: str, out_dir: Path) -> dict | None:
    metadata_path = build_dir / "build-metadata.json"
    manifest_path = build_dir / "release-manifest.json"
    unpacked = build_dir / "win-unpacked"
    resources = unpacked / "resources"
    manifest_in_resources = resources / "release-manifest.json"
    asar = resources / "app.asar"
    backend = resources / "backend" / "bk-security-backend.exe"
    dashboard = resources / "dashboard" / "static"
    installers = sorted(path for path in build_dir.glob("BK Security Setup *.exe") if path.is_file())
    required = (metadata_path, manifest_path, manifest_in_resources, asar, backend, dashboard / "index.html")
    missing = [str(path.relative_to(build_dir)) for path in required if not path.is_file()]
    if missing:
        raise ValueError("Windows package is incomplete: " + ", ".join(missing))
    if len(installers) != 1:
        raise ValueError(f"Expected exactly one versioned NSIS installer, found {len(installers)}.")

    metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest_in_resources.read_bytes() != manifest_path.read_bytes():
        raise ValueError("Packaged release manifest differs from its sidecar.")
    if (
        manifest.get("version") != version
        or manifest.get("app_id") != APP_ID
        or manifest.get("windows_response_enabled") is not False
        or manifest.get("capture_mode_default") != "stopped"
    ):
        raise ValueError("Version, app identity, capture policy or response flag is inconsistent.")
    if manifest.get("source_sha256") != source_sha256(ROOT):
        raise ValueError("Package source fingerprint differs from the current validated source tree.")
    installer_hash = sha256(installers[0])
    if (
        metadata.get("version") != version
        or metadata.get("build_id") != manifest.get("build_id")
        or metadata.get("app_id") != APP_ID
        or metadata.get("installer_sha256") != installer_hash
        or metadata.get("capture_mode_default") != "stopped"
        or metadata.get("windows_response_enabled") is not False
    ):
        raise ValueError("Installer build metadata does not match the built artifact.")
    _dashboard_test_count(metadata)
    if metadata.get("signature_status") not in {"Valid", "NotSigned"}:
        raise ValueError(f"Unexpected Authenticode status: {metadata.get('signature_status')}.")

    verifier = ROOT / "scripts" / "verify_packaged_release.js"
    node = os.getenv("BK_SECURITY_NODE", "node")
    ok, _ = _run(
        "packaged Electron/resources manifest and secret scan",
        [node, str(verifier), str(asar), str(manifest_in_resources), str(resources)],
        out_dir, version, env,
    )
    if not ok:
        return None
    findings = _scan_text_files(build_dir)
    if findings:
        raise ValueError("Release secret/config scan failed: " + "; ".join(findings))

    smoke = ROOT / "scripts" / "validate_packaged_backend.py"
    ok, _ = _run(
        "packaged backend production/API/dashboard/graceful-restart/SQLite smoke",
        [sys.executable, str(smoke), str(backend), str(manifest_in_resources)],
        out_dir, version, env,
    )
    if not ok:
        return None
    return {
        "installer": str(installers[0].relative_to(build_dir)),
        "installer_sha256": installer_hash,
        "signature_status": metadata["signature_status"],
        "signer_subject": metadata.get("signer_subject"),
        "manifest": manifest,
        "build_metadata": metadata,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the BK Security V1 release gate against a built Windows package.")
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    version_path = ROOT / "VERSION"
    version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else "unknown"
    out_dir = Path(os.getenv("BK_SECURITY_RELEASE_OUTPUT_DIR", str(build_dir / "gate-state"))).resolve()
    print("=== BK Security V1 release gate ===")
    print(f"Platform: {platform.platform()}")
    print(f"Python: {sys.version.split()[0]}")
    if os.name != "nt":
        _record_blocked_candidate(out_dir, version, "Windows package runtime", "V1 package gate requires a Windows host.")
        return 2

    try:
        package = _verify_package(build_dir, {
            **os.environ,
            "BK_SECURITY_WINDOWS_RESPONSE": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }, version, out_dir)
        if package is None:
            return 1
        _dashboard_files(build_dir / "win-unpacked" / "resources" / "dashboard" / "static")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        _record_blocked_candidate(out_dir, version, "package integrity/configuration", f"{type(exc).__name__}: {exc}")
        print(f"Release gate blocked: {type(exc).__name__}: {exc}")
        return 1

    with tempfile.TemporaryDirectory(prefix="bk-security-v1-release-gate-") as temporary:
        temp_root = Path(temporary)
        env = os.environ.copy()
        env["BK_SECURITY_WINDOWS_RESPONSE"] = "0"
        env["BK_SECURITY_ENV"] = "test"
        env["BK_SECURITY_CAPTURE_MODE"] = "simulation"
        env["BK_SECURITY_CAPTURE_INTERFACE"] = ""
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["BK_SECURITY_E2E_DATA_DIR"] = str(temp_root / "e2e-data")
        env["BK_SECURITY_NODE"] = os.getenv("BK_SECURITY_NODE", "node")

        critical_command = [
            sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q",
            "--basetemp", str(temp_root / "pytest-critical"), *CRITICAL_TESTS,
        ]
        ok, _ = _run("critical security and production regression suite", critical_command, out_dir, version, env)
        if not ok:
            return 1
        full_command = [
            sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q",
            "--basetemp", str(temp_root / "pytest-full"),
        ]
        ok, test_output = _run("full Python regression suite", full_command, out_dir, version, env)
        if not ok:
            return 1
        test_match = re.search(r"(\d+) passed", test_output)
        test_count = int(test_match.group(1)) if test_match else 0
        if test_count < MINIMUM_PYTHON_TESTS:
            _record_blocked_candidate(out_dir, version, "full regression suite", f"Only {test_count} passing Python tests were reported; minimum is {MINIMUM_PYTHON_TESTS}.")
            return 1

        electron_test = ROOT / "electron" / "test" / "run.js"
        ok, node_output = _run("Electron lifecycle/security/integrity/log tests", [env["BK_SECURITY_NODE"], str(electron_test)], out_dir, version, env)
        if not ok:
            return 1
        node_match = re.search(r"# tests\s+(\d+)", node_output)
        node_test_count = int(node_match.group(1)) if node_match else 0

        print("=== Python source syntax compilation ===")
        try:
            compiled_count = _compile_sources()
        except (OSError, SyntaxError, UnicodeError) as exc:
            _record_blocked_candidate(out_dir, version, "Python source syntax compilation", f"{type(exc).__name__}: {exc}")
            return 1
        print(f"Compiled {compiled_count} Python files without writing bytecode.")

        ok, _ = _run(
            "production runtime artifact preflight",
            [sys.executable, "scripts/production_runtime_check.py"], out_dir, version, env,
        )
        if not ok:
            return 1
        ok, _ = _run("API lifecycle/restart persistence canary", [sys.executable, "scripts/validate_restart_e2e.py"], out_dir, version, env)
        if not ok:
            return 1
        ok, performance_output = _run(
            "bounded synthetic ingest/SQLite performance probe",
            [sys.executable, "scripts/benchmark_ingest.py", "--events", "2000"],
            out_dir, version, env,
        )
        if not ok:
            return 1
        try:
            json_start = performance_output.find("{")
            json_end = performance_output.rfind("}")
            if json_start < 0 or json_end < json_start:
                raise json.JSONDecodeError("benchmark JSON was not found", performance_output, 0)
            performance = json.loads(performance_output[json_start:json_end + 1])
        except json.JSONDecodeError as exc:
            _record_blocked_candidate(out_dir, version, "synthetic performance probe", f"invalid benchmark output: {exc}")
            return 1
        if not performance.get("writer_healthy") or performance.get("events") != 2000:
            _record_blocked_candidate(out_dir, version, "synthetic performance probe", "bounded ingest writer health did not pass")
            return 1

    safe_configuration = {
        "BK_SECURITY_ENV": "production",
        "BK_SECURITY_CAPTURE_MODE": "stopped",
        "BK_SECURITY_CAPTURE_INTERFACE": "not configured",
        "BK_SECURITY_CORS_ORIGINS": "same-origin only",
        "BK_SECURITY_WINDOWS_RESPONSE": "0",
    }
    configuration_fingerprint = hashlib.sha256(json.dumps(safe_configuration, sort_keys=True).encode("utf-8")).hexdigest()
    manifest = {
        "version": version,
        "app_id": APP_ID,
        "build_id": package["manifest"]["build_id"],
        "source_sha256": source_sha256(ROOT),
        "artifact_sha256": package["installer_sha256"],
        "installer": package["installer"],
        "signature_status": package["signature_status"],
        "signer_subject": package["signer_subject"],
        "config_fingerprint": configuration_fingerprint,
        "validated_configuration": safe_configuration,
        "python_tests_passed": test_count,
        "dashboard_tests_passed": package["build_metadata"]["dashboard_tests_passed"],
        "electron_tests_passed": node_test_count,
        "python_files_compiled": compiled_count,
        "packaged_backend_api_dashboard_smoke": "passed",
        "synthetic_performance": performance,
        "installer_install_uninstall_smoke": package["build_metadata"]["installer_install_uninstall_smoke"],
        "windows_response_enabled": False,
        "capture_mode_default": "stopped",
        "critical_tests": "passed",
        "full_tests": "passed",
        "python_compileall": "passed",
        "api_restart_canary": "passed",
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.system(),
    }
    _record_passed_candidate(out_dir, manifest)
    print(f"Release gate SAFE. Python tests={test_count}, Dashboard tests={package['build_metadata']['dashboard_tests_passed']}, Electron tests={node_test_count}, compiled Python files={compiled_count}.")
    print(f"Installer SHA-256: {package['installer_sha256']}")
    print(f"Authenticode: {package['signature_status']}")
    print(f"Manifest: {out_dir / 'release-gate.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
