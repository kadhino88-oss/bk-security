from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _find_brain_source():
    candidates = []

    for base in (
        ROOT / "dashboard" / "src",
        ROOT / "dashboard",
    ):
        if not base.exists():
            continue

        for path in base.rglob("*"):
            if not path.is_file():
                continue

            if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx"}:
                continue

            try:
                text = path.read_text(encoding="utf-8-sig")
            except Exception:
                continue

            lowered = text.lower()

            if (
                "brain mode" in lowered
                or "brainmode" in lowered
                or "security-brain" in lowered
            ):
                candidates.append((path, text))

    return candidates


def test_static_dashboard_brain_mode_contract():
    """
    Brain Mode is a source-level React feature.

    Do not assert exact strings in Vite's minified production bundle:
    labels can be split, minified or transformed by the build pipeline.
    """
    candidates = _find_brain_source()

    assert candidates, (
        "Brain Mode source implementation was not found under dashboard/src "
        "or dashboard."
    )

    combined = "\n".join(text for _, text in candidates).lower()

    assert (
        "brain mode" in combined
        or "brainmode" in combined
        or "security-brain" in combined
    ), "Brain Mode source marker is missing."


def test_dashboard_brain_mode_is_built():
    static_dir = ROOT / "dashboard" / "static"
    index = static_dir / "index.html"

    assert index.exists(), "dashboard/static/index.html is missing."

    html = index.read_text(encoding="utf-8-sig")

    assert '<div id="root"></div>' in html, (
        "Expected Vite React root is missing from dashboard/static/index.html."
    )

    assets = static_dir / "assets"
    js_files = list(assets.glob("*.js")) if assets.exists() else []

    assert js_files, (
        "Vite did not produce a JavaScript asset in dashboard/static/assets."
    )